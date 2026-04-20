"""
IDS-ML API v3.0 — FastAPI hardened con auth + integridad de modelo.
Arquitectura v2 (sin Wazuh, con API key + rate limit).
"""
import hashlib
import json
import logging
import math
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from mitre_mapping import get_mitre_info, get_all_mappings

# ── Config ────────────────────────────────────────────────────
MODEL_DIR = Path(os.environ.get("MODEL_DIR", "/app/models"))
API_KEY = os.environ.get("IDS_API_KEY")
RATE_LIMIT = os.environ.get("IDS_RATE_LIMIT", "120/minute")
MAX_BATCH_SIZE = 500
LOG_DIR = Path(os.environ.get("LOG_DIR", "/app/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ml_api")

# ── Verificación de integridad (P0.2) ─────────────────────────
def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_load(path: Path, expected_hash: str):
    actual = sha256_of(path)
    if actual != expected_hash:
        raise RuntimeError(
            f"Hash mismatch: {path.name} esperado={expected_hash[:16]}... actual={actual[:16]}...")
    return joblib.load(path)

manifest_path = MODEL_DIR / "manifest.json"
if manifest_path.exists():
    manifest = json.loads(manifest_path.read_text())
    logger.info(f"Manifest encontrado: {len(manifest)} artefactos")
else:
    manifest = {}
    logger.warning("Sin manifest.json — carga sin verificación de integridad")

def load_artifact(name: str):
    p = MODEL_DIR / name
    if name in manifest:
        logger.info(f"  safe_load {name} (hash verificado)")
        return safe_load(p, manifest[name])
    logger.warning(f"  carga sin hash: {name}")
    return joblib.load(p)

# ── Carga de artefactos ──────────────────────────────────────
logger.info("Cargando artefactos v3...")
rf_binary = load_artifact("rf_binary_v3.joblib")
rf_multi = load_artifact("rf_multiclass_v3.joblib")
scaler = load_artifact("scaler_v3.joblib")
label_encoder = load_artifact("label_encoder_v3.joblib")
feature_names = load_artifact("feature_names_v3.joblib")

metrics_path = MODEL_DIR / "metrics_v3.json"
model_metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else {}

logger.info(f"  OK. Features: {len(feature_names)}, categorías: {list(label_encoder.classes_)}")

# ── Auth ──────────────────────────────────────────────────────
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def require_api_key(key: str | None = Security(api_key_header)) -> str:
    if not API_KEY:
        return "no-auth"  # Si no se configuró API_KEY, sin auth (dev mode)
    if not key or key != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or missing X-API-Key")
    return key

# ── Rate limiter ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])

# ── App ──────────────────────────────────────────────────────
app = FastAPI(title="IDS-ML API", version="3.0.0",
              description="Detección de intrusiones con RF v3 — Arquitectura v2 UDLA")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    rid = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response

# ── Validación ───────────────────────────────────────────────
def _validate(features: list[float], idx: int | None = None):
    prefix = f"Flow {idx}: " if idx is not None else ""
    if len(features) != len(feature_names):
        raise HTTPException(400, f"{prefix}Expected {len(feature_names)} features, got {len(features)}")
    for i, v in enumerate(features):
        if math.isnan(v) or math.isinf(v):
            raise HTTPException(400, f"{prefix}Feature {i} ('{feature_names[i]}') is NaN/Inf")

# ── Schemas ──────────────────────────────────────────────────
class FlowInput(BaseModel):
    features: list[float]

class BatchInput(BaseModel):
    flows: list[list[float]]

# ── Endpoints ────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "version": "3.0.0", "model": "v3",
            "n_features": len(feature_names),
            "categories": list(label_encoder.classes_),
            "integrity": "verified" if manifest else "unverified"}

@app.post("/predict", dependencies=[Depends(require_api_key)])
@limiter.limit(RATE_LIMIT)
def predict(request: Request, flow: FlowInput):
    t0 = time.perf_counter()
    _validate(flow.features)
    X = np.array(flow.features).reshape(1, -1)
    X_s = scaler.transform(X)
    bin_pred = int(rf_binary.predict(X_s)[0])
    bin_proba = rf_binary.predict_proba(X_s)[0]
    mc_pred = rf_multi.predict(X_s)[0]
    mc_proba = rf_multi.predict_proba(X_s)[0]
    category = label_encoder.inverse_transform([mc_pred])[0]
    mitre = get_mitre_info(category)
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        "is_attack": bool(bin_pred),
        "attack_confidence": round(float(bin_proba[1]), 4),
        "category": category,
        "category_confidence": round(float(mc_proba[mc_pred]), 4),
        "mitre": mitre,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "processing_time_ms": round(elapsed, 2),
    }

@app.post("/predict/batch", dependencies=[Depends(require_api_key)])
@limiter.limit(RATE_LIMIT)
def predict_batch(request: Request, batch: BatchInput):
    t0 = time.perf_counter()
    if not batch.flows:
        raise HTTPException(400, "Empty batch")
    if len(batch.flows) > MAX_BATCH_SIZE:
        raise HTTPException(400, f"Max batch size is {MAX_BATCH_SIZE}")
    for i, f in enumerate(batch.flows):
        _validate(f, i)
    X = np.array(batch.flows)
    X_s = scaler.transform(X)
    bin_preds = rf_binary.predict(X_s)
    bin_probas = rf_binary.predict_proba(X_s)
    mc_preds = rf_multi.predict(X_s)
    mc_probas = rf_multi.predict_proba(X_s)
    categories = label_encoder.inverse_transform(mc_preds)
    results = []
    for i in range(len(batch.flows)):
        cat = categories[i]
        results.append({
            "is_attack": bool(bin_preds[i]),
            "attack_confidence": round(float(bin_probas[i][1]), 4),
            "category": cat,
            "category_confidence": round(float(mc_probas[i][mc_preds[i]]), 4),
            "mitre": get_mitre_info(cat),
        })
    attack_count = sum(1 for r in results if r["is_attack"])
    cat_dist = {}
    for r in results:
        cat_dist[r["category"]] = cat_dist.get(r["category"], 0) + 1
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        "total": len(results), "attacks": attack_count, "benign": len(results) - attack_count,
        "categories": cat_dist, "timestamp": datetime.now(timezone.utc).isoformat(),
        "processing_time_ms": round(elapsed, 2), "predictions": results,
    }

@app.get("/metrics", dependencies=[Depends(require_api_key)])
def get_metrics():
    return model_metrics

@app.get("/features", dependencies=[Depends(require_api_key)])
def get_features():
    return {"n_features": len(feature_names), "feature_names": list(feature_names)}

@app.get("/mitre")
def get_mitre():
    return get_all_mappings()

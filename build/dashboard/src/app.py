"""Dashboard IDS-ML v2 — IA aplicada a Ciberseguridad (lab educativo).

Stakeholders: estudiantes de ciberseguridad aprendiendo ML.

Tabs (orden pedagogico):
  1. Intro          — contexto del lab, arquitectura, glosario
  2. Dataset        — explorar CICIDS2017 (entrenamiento)
  3. Metricas       — rendimiento del modelo + matriz de confusion + feature importance
  4. Prediccion     — clasificar flujos con presets + sliders + explicacion
  5. Ataques        — lanzar ataques simulados contra DVWA
  6. Suricata vs ML — complementariedad rule-based vs ML
"""
import os
import json
import time
import collections
from datetime import datetime, timezone
import requests
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

# ═══════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════
API_URL = os.environ.get("ML_API_URL", "http://ml_api:8000")
API_KEY = os.environ.get("IDS_API_KEY", "")
LOGS_DIR = os.environ.get("LOGS_DIR", "/app/logs")
DATASETS_DIR = os.environ.get("DATASETS_DIR", "/app/datasets")
SENSOR_URL = os.environ.get("SENSOR_URL", "http://sensor:9999")
DVWA_URL = os.environ.get("DVWA_URL", "http://dvwa")
HOST_IP = os.environ.get("HOST_IP", "localhost")

SENSOR_PREDICTIONS_PATH = os.path.join(LOGS_DIR, "sensor_predictions.jsonl")
LAB_HISTORY_PATH = os.path.join(LOGS_DIR, "lab_history.jsonl")
EVE_JSON_PATH = os.path.join(LOGS_DIR, "eve.json")
DATASET_PATH = os.path.join(DATASETS_DIR, "cicids_test.parquet")
HISTORY_MAX_ENTRIES = 500

CATEGORY_COLORS = {
    "Benign": "#10b981",
    "DoS": "#f59e0b",
    "DDoS": "#ef4444",
    "Brute Force": "#8b5cf6",
    "Reconnaissance": "#3b82f6",
    "Web Attack": "#ec4899",
}
CATEGORY_ORDER = ["Benign", "DoS", "DDoS", "Brute Force", "Reconnaissance", "Web Attack"]

headers = {"X-API-Key": API_KEY} if API_KEY else {}


# ═══════════════════════════════════════════════════════════════
# Helpers — normalizacion y logs
# ═══════════════════════════════════════════════════════════════
_PROTO_INT_TO_NAME = {6: 'TCP', 17: 'UDP', 1: 'ICMP', 2: 'IGMP'}


def _norm_proto(v):
    try:
        return _PROTO_INT_TO_NAME.get(int(v), str(v))
    except (ValueError, TypeError):
        return str(v).upper().strip()


def _norm_port(v):
    try:
        return int(v)
    except (ValueError, TypeError):
        return 0


def load_sensor_predictions(limit=2000):
    if not os.path.exists(SENSOR_PREDICTIONS_PATH):
        return []
    preds = []
    try:
        with open(SENSOR_PREDICTIONS_PATH) as f:
            for line in f:
                try:
                    preds.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return preds[-limit:]


def correlate_5tuple(ml_preds, suri_alerts):
    """Join ML↔Suricata por 5-tupla (src/dst/port/proto)."""
    alert_idx = {}
    for a in suri_alerts:
        key = (a.get('src_ip', ''), a.get('dest_ip', ''),
               _norm_port(a.get('src_port', 0)),
               _norm_port(a.get('dest_port', 0)),
               _norm_proto(a.get('proto', '')))
        alert_idx.setdefault(key, []).append(a)

    rows = []
    matched_keys = set()
    for p in ml_preds:
        src = p.get('src_ip', '')
        dst = p.get('dst_ip', '')
        sp = _norm_port(p.get('src_port', 0))
        dp = _norm_port(p.get('dst_port', 0))
        pr = _norm_proto(p.get('protocol', 0))
        k_fwd = (src, dst, sp, dp, pr)
        k_rev = (dst, src, dp, sp, pr)
        matches = alert_idx.get(k_fwd, []) + alert_idx.get(k_rev, [])
        if matches:
            matched_keys.add(k_fwd)
            matched_keys.add(k_rev)
        ml_attack = bool(p.get('is_attack', False))
        if matches:
            verdict = 'both_detected' if ml_attack else 'suricata_only'
            top = matches[0]
            rows.append({
                '5-tupla': f"{src}:{sp} → {dst}:{dp} ({pr})",
                'ML categoría': p.get('category', 'Benign'),
                'ML conf.': f"{float(p.get('confidence', 0)):.0%}",
                'Suricata signature': top.get('alert', {}).get('signature', '')[:55],
                'Alertas': len(matches),
                'Veredicto': verdict,
                'request_id': p.get('request_id', ''),
            })
        else:
            verdict = 'ml_only' if ml_attack else 'both_clean'
            rows.append({
                '5-tupla': f"{src}:{sp} → {dst}:{dp} ({pr})",
                'ML categoría': p.get('category', 'Benign'),
                'ML conf.': f"{float(p.get('confidence', 0)):.0%}",
                'Suricata signature': '—',
                'Alertas': 0,
                'Veredicto': verdict,
                'request_id': p.get('request_id', ''),
            })
    for key, alerts in alert_idx.items():
        if key in matched_keys:
            continue
        top = alerts[0]
        rows.append({
            '5-tupla': f"{key[0]}:{key[2]} → {key[1]}:{key[3]} ({key[4]})",
            'ML categoría': '—',
            'ML conf.': '—',
            'Suricata signature': top.get('alert', {}).get('signature', '')[:55],
            'Alertas': len(alerts),
            'Veredicto': 'suricata_only',
            'request_id': '',
        })
    return rows


def save_history_entry(entry):
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        existing = []
        if os.path.exists(LAB_HISTORY_PATH):
            with open(LAB_HISTORY_PATH) as f:
                for line in f:
                    try:
                        existing.append(json.loads(line))
                    except Exception:
                        pass
        existing.append(entry)
        if len(existing) > HISTORY_MAX_ENTRIES:
            existing = existing[-HISTORY_MAX_ENTRIES:]
        with open(LAB_HISTORY_PATH, 'w') as f:
            for e in existing:
                f.write(json.dumps(e, ensure_ascii=False) + '\n')
        return True
    except Exception:
        return False


def load_history():
    if not os.path.exists(LAB_HISTORY_PATH):
        return []
    entries = []
    try:
        with open(LAB_HISTORY_PATH) as f:
            for line in f:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return entries


# ═══════════════════════════════════════════════════════════════
# Helpers — dataset (CICIDS2017 parquet) + confusion matrix
# ═══════════════════════════════════════════════════════════════
@st.cache_data(ttl=600, show_spinner="Cargando dataset CICIDS2017...")
def load_dataset():
    if not os.path.exists(DATASET_PATH):
        return None
    try:
        return pd.read_parquet(DATASET_PATH)
    except Exception:
        return None


@st.cache_data(ttl=300, show_spinner=False)
def fetch_metrics():
    try:
        r = requests.get(f"{API_URL}/metrics", headers=headers, timeout=5)
        return r.json()
    except Exception:
        return {}


@st.cache_data(ttl=600, show_spinner="Calculando matriz de confusión (prediciendo batch vía API)...")
def compute_confusion_matrix(n_per_class=50):
    df = load_dataset()
    if df is None:
        return None
    feat_cols = [c for c in df.columns if c != 'Label_6']
    parts = []
    for cat in df['Label_6'].unique():
        grp = df[df['Label_6'] == cat]
        parts.append(grp.sample(n=min(n_per_class, len(grp)), random_state=42))
    sample = pd.concat(parts, ignore_index=True)
    flows = sample[feat_cols].values.tolist()
    try:
        resp = requests.post(
            f"{API_URL}/predict/batch",
            json={"flows": flows}, headers=headers, timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        preds = [p.get("category", "?") for p in data.get("predictions", [])]
        if len(preds) != len(sample):
            return None
        return pd.DataFrame({"y_true": sample['Label_6'].tolist(), "y_pred": preds})
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# Helpers — ataques simulados
# ═══════════════════════════════════════════════════════════════
def count_alerts_now():
    if not os.path.exists(EVE_JSON_PATH):
        return 0
    try:
        with open(EVE_JSON_PATH) as f:
            return sum(1 for l in f if '"event_type":"alert"' in l)
    except Exception:
        return 0


def count_predictions_now():
    if not os.path.exists(SENSOR_PREDICTIONS_PATH):
        return 0
    try:
        with open(SENSOR_PREDICTIONS_PATH) as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def latest_alert_signatures(n=10):
    if not os.path.exists(EVE_JSON_PATH):
        return []
    sigs = []
    try:
        with open(EVE_JSON_PATH) as f:
            for line in f:
                if '"event_type":"alert"' in line:
                    try:
                        d = json.loads(line)
                        sigs.append({
                            'ts': d.get('timestamp', '')[11:19],
                            'sig': d.get('alert', {}).get('signature', '')[:70],
                            'sev': d.get('alert', {}).get('severity', '?'),
                            'src': d.get('src_ip', ''),
                            'dst': d.get('dest_ip', ''),
                        })
                    except Exception:
                        pass
    except Exception:
        pass
    return sigs[-n:][::-1]


def launch_sensor_capture(attack_type, duration=15, intensity=30, inject_dataset=True):
    try:
        r = requests.post(
            f"{SENSOR_URL}/capture/start",
            json={"duration": duration, "attack_type": attack_type,
                  "intensity": intensity, "inject_dataset": inject_dataset},
            timeout=5,
        )
        r.raise_for_status()
        req_id = r.json().get("request_id", "?")
    except Exception as e:
        return {"error": f"No se pudo invocar sensor: {e}"}

    progress = st.progress(0.0, text=f"Sensor ejecutando '{attack_type}'...")
    start_time = time.time()
    deadline = start_time + duration + 120
    last_status = "?"
    pkts = flows = 0
    while time.time() < deadline:
        try:
            s = requests.get(f"{SENSOR_URL}/capture/status", timeout=3).json()
            last_status = s.get("status", "?")
            pkts = s.get("packets_captured", 0)
            flows = s.get("flows_extracted", 0)
            elapsed = time.time() - start_time
            pct = min(0.99, elapsed / (duration + 30))
            progress.progress(pct, text=f"{last_status} · pkts={pkts} flows={flows}")
            if last_status == "done":
                break
        except Exception:
            pass
        time.sleep(2)
    progress.progress(1.0, text=f"{last_status} · pkts={pkts} flows={flows}")
    return {"request_id": req_id, "status": last_status,
            "packets_captured": pkts, "flows_extracted": flows}


def run_http_attacks(categories):
    """Payloads HTTP crudos contra DVWA para disparar firmas Suricata."""
    target = DVWA_URL
    results = []

    def safe_req(method, url, **kw):
        kw.setdefault("timeout", 4)
        try:
            r = requests.request(method, url, **kw)
            return r.status_code
        except Exception as e:
            return f"err:{type(e).__name__}"

    if "sqli" in categories:
        for p in [
            "/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit",
            "/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users--",
            "/vulnerabilities/sqli/?id=1; DROP TABLE users--",
            "/?id=1' AND SLEEP(5)--",
        ]:
            results.append({"cat": "SQLi", "url": p[:60],
                            "code": str(safe_req("GET", f"{target}{p}"))})
    if "xss" in categories:
        for p in [
            "/vulnerabilities/xss_r/?name=<script>alert(1)</script>",
            "/vulnerabilities/xss_r/?name=<img src=x onerror=alert(1)>",
            "/vulnerabilities/xss_r/?name=<svg onload=alert(1)>",
            "/vulnerabilities/xss_s/?txtName=<iframe src=javascript:alert(1)>",
        ]:
            results.append({"cat": "XSS", "url": p[:60],
                            "code": str(safe_req("GET", f"{target}{p}"))})
    if "traversal" in categories:
        for p in [
            "/../../../etc/passwd",
            "/?page=../../../../etc/shadow",
            "/cgi-bin/test.cgi?arg=%00",
            "/?file=....//....//etc/passwd",
        ]:
            results.append({"cat": "LFI/Traversal", "url": p[:60],
                            "code": str(safe_req("GET", f"{target}{p}"))})
    if "shellshock" in categories:
        for url, hdr in [
            ("/cgi-bin/test", {"User-Agent": "() { :;}; /bin/ls"}),
            ("/cgi-bin/status", {"User-Agent": "() { :;}; /bin/cat /etc/passwd"}),
            ("/cgi-bin/", {"Cookie": "() { :;}; echo vulnerable"}),
        ]:
            results.append({"cat": "Shellshock", "url": url,
                            "code": str(safe_req("GET", f"{target}{url}", headers=hdr))})
    if "badagent" in categories:
        for ua, desc in [
            ("Mozilla/5.00 (Nikto/2.1.6)", "ET SCAN Nikto"),
            ("sqlmap/1.5.12#stable", "ET WEB Sqlmap"),
            ("Mozilla/5.0 zgrab/0.x", "ET SCAN zgrab"),
            ("Mozilla/5.0 (compatible; Nmap NSE)", "ET SCAN Nmap"),
            ("masscan/1.3", "ET SCAN masscan"),
        ]:
            results.append({"cat": f"UA ({desc})", "url": "/",
                            "code": str(safe_req("GET", f"{target}/", headers={"User-Agent": ua}))})
    if "recon" in categories:
        for p in ["/wp-admin/", "/phpmyadmin/", "/.env", "/.git/config",
                  "/admin.php", "/console", "/server-status", "/robots.txt",
                  "/api/v1/users", "/actuator/health", "/config.php.bak"]:
            results.append({"cat": "Recon paths", "url": p,
                            "code": str(safe_req("GET", f"{target}{p}"))})
    if "bruteforce" in categories:
        for u in ["admin", "root", "administrator"]:
            for pw in ["admin", "password", "123456", "letmein",
                       "qwerty", "toor", "root", "dvwa", "welcome"]:
                results.append({"cat": "Bruteforce", "url": f"login {u}:{pw}",
                                "code": str(safe_req(
                                    "POST", f"{target}/login.php",
                                    data={"username": u, "password": pw, "Login": "Login"}))})
    return results


# ═══════════════════════════════════════════════════════════════
# Page setup + Health
# ═══════════════════════════════════════════════════════════════
st.set_page_config(page_title="IDS-ML Lab UDLA", layout="wide", page_icon="")
st.title("IDS-ML Educational Lab")
st.caption("IA aplicada a Ciberseguridad · Random Forest v2 + Suricata ET-Open · UDLA Capstone 2026")

col1, col2, col3 = st.columns(3)
try:
    health = requests.get(f"{API_URL}/health", timeout=5).json()
    col1.metric("ML API", health["status"], f"modelo {health.get('model','?')}")
    col2.metric("Features", health["n_features"])
    col3.metric("Integridad modelo", health.get("integrity", "?"))
except Exception as e:
    st.error(f"ML API no accesible: {e}")
    st.stop()


# ═══════════════════════════════════════════════════════════════
# Tabs
# ═══════════════════════════════════════════════════════════════
tab_intro, tab_dataset, tab_metrics, tab_pred, tab_attack, tab_compare = st.tabs([
    "Intro",
    "Dataset",
    "Métricas",
    "Predicción",
    "Ataques",
    "Suricata vs ML",
])

# ═══════════════════════════════════════════════════════════════
# TAB 1: Intro / Lab Guide
# ═══════════════════════════════════════════════════════════════
with tab_intro:
    st.header("Bienvenido al Lab IDS + ML")
    st.markdown("""
Este laboratorio combina **Machine Learning** y **detección por firmas** para construir
un **IDS híbrido**. Objetivos pedagógicos:

1. Entender cómo se entrena un modelo de ML con tráfico real (CICIDS2017).
2. Ver las limitaciones de los IDS tradicionales basados en reglas.
3. Experimentar lanzando ataques y observar la detección en vivo.
4. Razonar sobre **complementariedad**: ¿qué aporta cada enfoque y dónde falla?
""")
    st.divider()

    st.subheader("Arquitectura del lab")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**Captura / detección**")
        st.markdown("""
- **Suricata 7.0.15** — IDS open-source
- 49.8k reglas **ET Open** (Emerging Threats)
- **CICFlowMeter** — 47 features por flujo TCP/UDP
- **Sensor FastAPI** — orquesta capturas + inyección
""")
    with c2:
        st.markdown("**Análisis / ML**")
        st.markdown("""
- **ML API** — FastAPI + Random Forest
- Dos modelos: **binario** (ataque/no) + **multiclase** (6 categorías)
- Entrenado en **CICIDS2017** (2.5M flujos reales)
- Mapping automático a **MITRE ATT&CK**
""")
    with c3:
        st.markdown("**Observabilidad**")
        st.markdown("""
- **Grafana 10.2** — dashboards en vivo
- **Loki** — agregador de logs
- **Promtail** — shipper
- **DVWA** — host vulnerable objetivo
""")

    st.divider()
    st.subheader("Recorrido recomendado")
    st.markdown("""
| Paso | Tab | Qué aprendes |
|---|---|---|
| 1 | Dataset | Con qué datos se entrenó el modelo; distribución y correlaciones |
| 2 | Métricas | Qué tan bueno es el modelo; confusion matrix y feature importance |
| 3 | Predicción | Clasificar flujos interactivamente; ver cómo cambian las decisiones |
| 4 | Ataques | Lanzar ataques reales contra el host vulnerable (DVWA) |
| 5 | Suricata vs ML | Comparar los dos enfoques: dónde coinciden, dónde discrepan |
""")

    st.divider()
    st.subheader("Servicios activos del lab")
    c1, c2, c3, c4 = st.columns(4)
    c1.link_button("Grafana", f"http://{HOST_IP}:3000", use_container_width=True)
    c2.link_button("Jupyter", f"http://{HOST_IP}:8888", use_container_width=True)
    c3.link_button("DVWA (target)", f"http://{HOST_IP}:8080", use_container_width=True)
    c4.link_button("Sensor API docs", f"http://{HOST_IP}:9999/docs", use_container_width=True)

    st.divider()
    with st.expander("Glosario rápido"):
        st.markdown("""
- **IDS (Intrusion Detection System)**: sistema que detecta intentos de ataque en una red.
- **Suricata**: IDS open-source multithread, base del lab. Usa reglas tipo `alert tcp any -> $HOME_NET 80 (content:"UNION SELECT"; sid:XXX;)`.
- **ET Open (Emerging Threats)**: set gratuito de ~50k reglas Suricata mantenido por la comunidad.
- **Random Forest**: ensemble de cientos de árboles de decisión. Cada árbol vota y se toma la mayoría.
- **CICIDS2017**: dataset benchmark del Canadian Institute for Cybersecurity con 14+ tipos de ataque.
- **Flow (flujo)**: secuencia bidireccional de paquetes entre dos endpoints (mismo src/dst/puertos/proto).
- **CICFlowMeter**: extractor de 80+ estadísticas por flujo (duración, bytes, IAT, flags TCP, etc.).
- **MITRE ATT&CK**: framework que clasifica técnicas de ataque observadas en el mundo real (T1046, T1110, ...).
- **Zero-day**: ataque sin firma conocida — ML puede ser más efectivo aquí que Suricata.
- **False Positive (FP)** / **False Negative (FN)**: tráfico benigno marcado como ataque / ataque no detectado.
""")

# ═══════════════════════════════════════════════════════════════
# TAB 2: Dataset Explorer
# ═══════════════════════════════════════════════════════════════
with tab_dataset:
    st.header("Dataset CICIDS2017 — los datos del entrenamiento")
    df = load_dataset()
    if df is None:
        st.error(f"Dataset no encontrado en `{DATASET_PATH}`. "
                 "Asegúrate de que el volumen `./datasets` esté montado.")
        st.stop()

    st.caption(
        "Fuente: **ericanacletoribeiro/cicids2017-cleaned-and-preprocessed** (Kaggle). "
        "Subset balanceado (2000 muestras por clase) → se usó para entrenar y evaluar el modelo. "
        "Aquí ves exactamente los datos con los que el RF aprendió a distinguir ataques."
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Filas totales", f"{len(df):,}")
    c2.metric("Features por flujo", len(df.columns) - 1)
    c3.metric("Clases", df['Label_6'].nunique())
    c4.metric("% ataques", f"{(df['Label_6'] != 'Benign').mean():.0%}")

    st.divider()
    st.subheader("Distribución de clases")
    cat_counts = df['Label_6'].value_counts().reindex(CATEGORY_ORDER).dropna()
    fig = px.pie(
        values=cat_counts.values, names=cat_counts.index,
        color=cat_counts.index, color_discrete_map=CATEGORY_COLORS, hole=0.4,
    )
    fig.update_traces(textinfo='label+percent+value')
    st.plotly_chart(fig, use_container_width=True)

    st.info(
        "**Observación clave**: el dataset está **balanceado** (~2000/clase). "
        "En datos reales el tráfico benigno domina ~99%. Si no balanceas, un modelo "
        "perezoso que diga **'Benign' siempre** parece tener 99% de accuracy. "
        "Por eso usamos F1 (no accuracy) y balanceamos al entrenar."
    )

    st.divider()
    st.subheader("Distribución de una feature por clase")
    feat_cols = [c for c in df.columns if c != 'Label_6']
    c1, c2 = st.columns([3, 1])
    with c1:
        default_feat = "Flow_Duration" if "Flow_Duration" in feat_cols else feat_cols[0]
        feature_choice = st.selectbox(
            "Feature", options=feat_cols, index=feat_cols.index(default_feat),
        )
    with c2:
        st.write("")
        use_log = st.checkbox("Escala log", value=True,
                              help="Las features de CICIDS tienen mucha asimetría; log ayuda a ver distribuciones.")
    fig = px.histogram(
        df, x=feature_choice, color='Label_6',
        color_discrete_map=CATEGORY_COLORS,
        marginal="box", nbins=40, log_y=use_log,
        category_orders={'Label_6': CATEGORY_ORDER},
    )
    fig.update_layout(height=450)
    st.plotly_chart(fig, use_container_width=True)

    st.caption(
        "Si las barras de distintos colores **no se solapan**, esa feature es muy útil "
        "para distinguir esa clase. Si se solapan mucho, no ayuda."
    )

    st.divider()
    st.subheader("Correlación entre features más importantes")
    st.caption(
        "Pares con correlación cerca de ±1 son **redundantes** (el modelo podría ignorar una). "
        "Valores cerca de 0 significan features independientes."
    )
    m = fetch_metrics()
    top10 = [x["feature"] for x in m.get("feature_importance_gini_top20", [])[:10]]
    top10 = [f for f in top10 if f in df.columns]
    if len(top10) >= 3:
        corr = df[top10].corr()
        fig = px.imshow(
            corr, color_continuous_scale='RdBu_r',
            zmin=-1, zmax=1, text_auto='.2f', aspect='auto',
        )
        fig.update_layout(height=450)
        st.plotly_chart(fig, use_container_width=True)

    with st.expander("Ver muestra aleatoria de filas"):
        n = st.slider("N filas", 10, 200, 50, 10)
        st.dataframe(df.sample(n, random_state=42).reset_index(drop=True),
                     use_container_width=True)


# ═══════════════════════════════════════════════════════════════
# TAB 3: Métricas del modelo
# ═══════════════════════════════════════════════════════════════
with tab_metrics:
    st.header("Rendimiento del modelo v2")

    m = fetch_metrics()
    if not m:
        st.error("No se pudieron obtener métricas del ML API.")
        st.stop()

    bin_t = m.get("binary", {}).get("test", {})
    mc_t = m.get("multiclass", {}).get("test", {})

    st.caption(
        f"Pipeline: `{m.get('pipeline','?')}` · "
        f"Features: {m.get('n_features','?')} · "
        f"Train: {m.get('n_train', 0):,} · "
        f"Val: {m.get('n_val', 0):,} · "
        f"Test: {m.get('n_test', 0):,}"
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("F1-weighted binario", f"{bin_t.get('f1_weighted', 0):.4f}",
              help="F1 ponderado por tamaño de clase (binario ataque/no). 1.0 = perfecto. Robusto a desbalance.")
    c2.metric("F1-macro binario", f"{bin_t.get('f1_macro', 0):.4f}",
              help="Promedio simple del F1 de las 2 clases (binario). Más estricto si una clase falla.")
    c3.metric("F1-weighted multiclase", f"{mc_t.get('f1_weighted', 0):.4f}",
              help="F1 ponderado sobre las 6 categorías de ataque.")
    c4.metric("F1-macro multiclase", f"{mc_t.get('f1_macro', 0):.4f}",
              help="F1 macro sobre las 6 categorías — penaliza fuerte si falla una clase rara.")

    st.divider()

    # ──── Matriz de confusión ────
    st.subheader("Matriz de confusión — predicciones en vivo")
    st.markdown(
        "La matriz muestra dónde el modelo **se equivoca entre categorías**. "
        "Filas = clase real del dataset, columnas = predicción del modelo. "
        "**Diagonal = aciertos**; fuera de diagonal = confusiones entre clases."
    )
    st.caption(
        "Cálculo en vivo: muestreamos 50 flujos por clase del parquet, los enviamos "
        "a `/predict/batch` del ML API, y comparamos predicciones vs labels reales. "
        "Cached 10 min."
    )
    if st.button("Recalcular matriz de confusión"):
        st.cache_data.clear()
        st.rerun()

    cm_df = compute_confusion_matrix(n_per_class=50)
    if cm_df is None or cm_df.empty:
        st.warning("No se pudo calcular (dataset o API no disponible).")
    else:
        cats = CATEGORY_ORDER
        cm = pd.crosstab(
            cm_df['y_true'], cm_df['y_pred'],
            rownames=['Real'], colnames=['Predicho'],
        )
        # asegurar todas las clases
        for c in cats:
            if c not in cm.columns:
                cm[c] = 0
            if c not in cm.index:
                cm.loc[c] = 0
        cm = cm.loc[cats, cats]
        cm_norm = cm.div(cm.sum(axis=1), axis=0).fillna(0)

        c1, c2 = st.columns(2)
        with c1:
            fig = px.imshow(
                cm, text_auto=True, color_continuous_scale='Blues',
                aspect='auto', labels=dict(x="Predicho", y="Real", color="Conteo"),
            )
            fig.update_layout(height=450, title="Conteos absolutos")
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            fig = px.imshow(
                cm_norm, text_auto='.0%', color_continuous_scale='Blues',
                aspect='auto', zmin=0, zmax=1,
                labels=dict(x="Predicho", y="Real", color="Recall"),
            )
            fig.update_layout(height=450,
                              title="Normalizado por clase real (recall por clase)")
            st.plotly_chart(fig, use_container_width=True)

        accuracy = (cm_df['y_true'] == cm_df['y_pred']).mean()
        correct = int((cm_df['y_true'] == cm_df['y_pred']).sum())
        st.success(
            f"**Accuracy en este sample**: {accuracy:.1%} "
            f"({correct} de {len(cm_df)} predicciones correctas)"
        )

        # diagnóstico automático
        worst_class = cm_norm.loc[cats, cats].apply(
            lambda row: row[row.name] if row.name in row.index else 0, axis=1
        ).idxmin()
        worst_recall = cm_norm.loc[worst_class, worst_class] if worst_class in cm_norm.columns else 0
        if worst_recall < 0.8:
            confused_with = cm_norm.loc[worst_class].drop(worst_class).idxmax() if len(cm_norm.columns) > 1 else "?"
            st.warning(
                f"**Clase más débil**: `{worst_class}` con recall {worst_recall:.0%}. "
                f"Se confunde principalmente con `{confused_with}`. "
                f"(El parquet bundleado tiene cobertura 47/47 de las features del modelo.)"
            )

    st.divider()

    # ──── Classification report ────
    st.subheader("Reporte por clase (multiclase, test del entrenamiento)")
    cr = m.get("multiclass", {}).get("classification_report", {})
    rows = []
    for cls, stats in cr.items():
        if isinstance(stats, dict) and "f1-score" in stats:
            rows.append({
                "Clase": cls,
                "Precision": round(stats.get("precision", 0), 3),
                "Recall": round(stats.get("recall", 0), 3),
                "F1": round(stats.get("f1-score", 0), 3),
                "Support": int(stats.get("support", 0)),
            })
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        st.caption(
            "**Precision** = de todo lo que predije como X, cuánto era X realmente (bajo ⇒ falsos positivos). "
            "**Recall** = de todo lo que era X realmente, cuánto detecté (bajo ⇒ falsos negativos)."
        )

    st.divider()

    # ──── Baselines ────
    st.subheader("Comparativa con modelos baseline")
    bl = m.get("baselines_on_v1_split", {})
    if bl:
        b_df = pd.DataFrame([
            {"Modelo": "Dummy (clase mayoritaria)",
             "F1-w": round(bl.get("dummy_majority_f1_weighted", 0), 4),
             "Descripción": "Siempre predice 'Benign'. Techo inferior trivial."},
            {"Modelo": f"Stump (1 split en '{bl.get('stump_feature','?')}')",
             "F1-w": round(bl.get("stump_depth1_f1_weighted", 0), 4),
             "Descripción": "Árbol de 1 nivel — la mínima señal extraíble."},
            {"Modelo": "Árbol depth=3",
             "F1-w": round(bl.get("tree_depth3_f1_weighted", 0), 4),
             "Descripción": "Árbol pequeño; referencia interpretable."},
            {"Modelo": "RF v2 (200 árboles, tuned)",
             "F1-w": round(bin_t.get("f1_weighted", 0), 4),
             "Descripción": "Modelo de producción del lab."},
        ])
        st.dataframe(b_df, hide_index=True, use_container_width=True)
        st.caption(
            "El salto entre **Stump** y **RF** mide cuánta señal **no-lineal** hay "
            "en los datos. Si el stump ya es 0.90, tu problema es fácil; si el stump "
            "es 0.60 y RF llega a 0.99, hay mucha interacción entre features."
        )

    st.divider()

    # ──── Feature importance ────
    st.subheader("Feature importance (Gini)")
    fi = m.get("feature_importance_gini_top20", [])
    if fi:
        fi_df = pd.DataFrame(fi[:15])
        fig = px.bar(
            fi_df, x="importance", y="feature", orientation="h",
            color="importance", color_continuous_scale="Viridis",
        )
        fig.update_layout(yaxis={'categoryorder': 'total ascending'}, height=500)
        st.plotly_chart(fig, use_container_width=True)
        st.caption(
            "Las top features son las que más contribuyen a **reducir la impureza Gini** "
            "del ensemble. Son los 'tornillos' del modelo — cambiarlas mueve la predicción. "
            "No confundir con **importancia causal** (Gini mide uso, no causalidad)."
        )


# ═══════════════════════════════════════════════════════════════
# TAB 4: Predicción interactiva
# ═══════════════════════════════════════════════════════════════
with tab_pred:
    st.header("Clasificación interactiva de flujos")
    st.markdown(
        "Carga un **ejemplo real del dataset** con un click, modifica las features "
        "más influyentes con sliders, y observa cómo el modelo cambia su predicción."
    )

    df = load_dataset()
    if df is None:
        st.error("Dataset no disponible; los presets requieren el parquet.")
        st.stop()

    feat_cols = [c for c in df.columns if c != 'Label_6']
    m = fetch_metrics()
    top_features = [x["feature"] for x in m.get("feature_importance_gini_top20", [])[:6]
                    if x["feature"] in feat_cols]
    if not top_features:
        top_features = feat_cols[:6]

    # Session state
    if 'preset_features' not in st.session_state:
        benign_pool = df[df['Label_6'] == 'Benign']
        if len(benign_pool) > 0:
            st.session_state.preset_features = benign_pool.sample(1, random_state=42).iloc[0][feat_cols].tolist()
            st.session_state.preset_label = "Benign"
        else:
            st.session_state.preset_features = [0.0] * len(feat_cols)
            st.session_state.preset_label = "?"

    st.subheader("Paso 1 — Carga un preset del dataset")
    cols = st.columns(6)
    for i, cat in enumerate(CATEGORY_ORDER):
        if cols[i].button(cat, use_container_width=True, key=f"preset_btn_{cat}"):
            pool = df[df['Label_6'] == cat]
            if len(pool) > 0:
                sample = pool.sample(1).iloc[0]
                st.session_state.preset_features = sample[feat_cols].tolist()
                st.session_state.preset_label = cat
                # Limpiar sliders anteriores
                for f in top_features:
                    st.session_state.pop(f"slider_{f}", None)
                st.rerun()

    st.caption(f"Preset actual: **{st.session_state.preset_label}** (muestra aleatoria del dataset).")

    st.subheader("Paso 2 — Ajusta features clave (opcional)")
    st.caption(
        f"Las **{len(top_features)} features más importantes** del modelo. "
        f"El resto de las {len(feat_cols) - len(top_features)} quedan en el valor del preset."
    )

    features = list(st.session_state.preset_features)
    slider_cols = st.columns(2)
    for i, fname in enumerate(top_features):
        feat_idx = feat_cols.index(fname)
        col_min = float(df[fname].min())
        col_max = float(df[fname].max())
        if col_min == col_max:
            col_max = col_min + 1.0
        current = float(features[feat_idx])
        current = max(col_min, min(col_max, current))
        new_val = slider_cols[i % 2].slider(
            fname,
            min_value=col_min, max_value=col_max, value=current,
            key=f"slider_{fname}",
            help=f"Rango en dataset: [{col_min:.2f}, {col_max:.2f}]",
        )
        features[feat_idx] = new_val

    st.subheader("Paso 3 — Clasificar")
    if st.button("Clasificar con el modelo v2", type="primary", use_container_width=True):
        try:
            resp = requests.post(
                f"{API_URL}/predict",
                json={"features": features},
                headers=headers, timeout=10,
            ).json()

            is_attack = resp.get("is_attack", False)
            category = resp.get("category", "?")
            cat_conf = float(resp.get("category_confidence", 0))
            atk_conf = float(resp.get("attack_confidence", 0))

            if is_attack:
                st.error(
                    f"**ATAQUE detectado** — categoría: **{category}** "
                    f"(confianza categoría: {cat_conf:.1%}, prob. ataque: {atk_conf:.1%})"
                )
            else:
                st.success(
                    f"**Tráfico BENIGNO** (prob. ataque: {atk_conf:.1%}, "
                    f"categoría más probable: {category} @ {cat_conf:.1%})"
                )

            # Comparación con label real
            if st.session_state.preset_label != "?":
                if category == st.session_state.preset_label:
                    st.info(
                        f"**Coincide con el label real del preset** "
                        f"({st.session_state.preset_label}). El modelo acertó."
                    )
                else:
                    st.warning(
                        f"El preset tenía label **{st.session_state.preset_label}** "
                        f"pero el modelo predijo **{category}**. "
                        f"Probablemente modificaste features al punto de confundirlo "
                        f"— muy útil para entender los límites del modelo."
                    )

            # MITRE ATT&CK como badges
            mitre = resp.get("mitre", {})
            tactics = mitre.get("tactics", [])
            techniques = mitre.get("techniques", [])
            if tactics or techniques:
                st.markdown("### MITRE ATT&CK Mapping")
                cols_m = st.columns(2)
                with cols_m[0]:
                    st.markdown("**Tácticas**")
                    if tactics:
                        for t in tactics:
                            st.markdown(f"- **`{t.get('id','?')}`** — {t.get('name','?')}")
                    else:
                        st.caption("—")
                with cols_m[1]:
                    st.markdown("**Técnicas**")
                    if techniques:
                        for t in techniques:
                            st.markdown(f"- **`{t.get('id','?')}`** — {t.get('name','?')}")
                    else:
                        st.caption("—")

            # Explicación heurística
            st.markdown("### Explicación heurística")
            st.caption(
                "Aproximación **educativa** de qué features pesaron. "
                "Score = `|valor normalizado| × importancia_Gini`. "
                "Para explicaciones formales se usa SHAP (no implementado en este lab)."
            )
            if m.get("feature_importance_gini_top20"):
                rows = []
                for item in m["feature_importance_gini_top20"][:10]:
                    fname = item["feature"]
                    if fname in feat_cols:
                        fidx = feat_cols.index(fname)
                        val = features[fidx]
                        imp = item["importance"]
                        col_max = float(df[fname].max()) or 1.0
                        norm_val = abs(val) / col_max if col_max else 0
                        rows.append({
                            "Feature": fname,
                            "Valor actual": round(val, 3),
                            "Importancia Gini": round(imp, 4),
                            "Score heurístico": round(imp * norm_val, 4),
                        })
                rows.sort(key=lambda r: r["Score heurístico"], reverse=True)
                expl_df = pd.DataFrame(rows)
                fig = px.bar(
                    expl_df.head(10),
                    x="Score heurístico", y="Feature",
                    orientation="h", color="Score heurístico",
                    color_continuous_scale="Oranges",
                )
                fig.update_layout(yaxis={'categoryorder': 'total ascending'}, height=350)
                st.plotly_chart(fig, use_container_width=True)
                st.dataframe(expl_df, hide_index=True, use_container_width=True)

            with st.expander("Respuesta completa del ML API (JSON)"):
                st.json(resp)
        except Exception as e:
            st.error(f"Error al clasificar: {e}")


# ═══════════════════════════════════════════════════════════════
# TAB 5: Ataques simulados
# ═══════════════════════════════════════════════════════════════
with tab_attack:
    st.header("Ataques simulados contra DVWA (172.25.0.50)")
    st.warning(
        "**Uso exclusivamente educativo.** Todos los ataques se ejecutan "
        "dentro de la red docker aislada `laboratorio-mlcyber_ids_network`. "
        "NO uses estos payloads contra sistemas que no controles."
    )

    base_alerts = count_alerts_now()
    base_preds = count_predictions_now()
    st.markdown(
        f"**Baseline actual** — Alertas Suricata: `{base_alerts}` · "
        f"Predicciones ML: `{base_preds}` · Target: `{DVWA_URL}`"
    )
    st.divider()

    # ── Sección A ──
    st.markdown("### A. Ataques vía Sensor ML")
    st.caption(
        "POST a `/capture/start` del sensor. El sensor genera tráfico con scapy, "
        "captura, extrae 47 features con CICFlowMeter, inyecta flujos reales del "
        "CICIDS2017 y clasifica con el modelo v2. Escribe en "
        "`sensor_predictions.jsonl` (visible en Grafana)."
    )

    cA1, cA2 = st.columns(2)
    duration = cA1.slider("Duración (s)", 5, 60, 15, 5, key="atk_duration")
    intensity = cA2.slider("Intensidad (pkts/s)", 5, 100, 30, 5, key="atk_intensity")
    inject = st.checkbox(
        "Inyectar flujos CICIDS2017 (recomendado para disparar categorías de ataque)",
        value=True, key="atk_inject",
    )

    bA1, bA2, bA3, bA4, bA5 = st.columns(5)
    attack_to_run = None
    if bA1.button("Flood (DoS)", use_container_width=True):
        attack_to_run = "flood"
    if bA2.button("Scan (Recon)", use_container_width=True):
        attack_to_run = "scan"
    if bA3.button("Bruteforce", use_container_width=True):
        attack_to_run = "bruteforce"
    if bA4.button("Mixed", type="primary", use_container_width=True):
        attack_to_run = "mixed"
    if bA5.button("Normal (baseline)", use_container_width=True):
        attack_to_run = "normal"

    if attack_to_run:
        with st.status(f"Ejecutando ataque '{attack_to_run}' vía sensor...",
                       expanded=True) as status:
            result = launch_sensor_capture(
                attack_to_run, duration=duration,
                intensity=intensity, inject_dataset=inject,
            )
            if "error" in result:
                status.update(label=f"{result['error']}", state="error")
                st.error(result["error"])
            else:
                time.sleep(1)
                new_alerts = count_alerts_now() - base_alerts
                new_preds = count_predictions_now() - base_preds
                status.update(
                    label=f"'{attack_to_run}' → +{new_alerts} alertas · "
                          f"+{new_preds} predicciones",
                    state="complete", expanded=False,
                )

                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Paquetes capturados", result.get("packets_captured", 0))
                c2.metric("Flujos extraídos", result.get("flows_extracted", 0))
                c3.metric("Alertas Suricata (Δ)", new_alerts)
                c4.metric("Predicciones ML (Δ)", new_preds)

                if new_preds > 0:
                    preds = load_sensor_predictions(limit=new_preds + 10)
                    my_preds = [p for p in preds
                                if p.get("request_id") == result.get("request_id")]
                    if my_preds:
                        cat_counts = collections.Counter(p.get("category", "?") for p in my_preds)
                        atk_counts = collections.Counter(str(p.get("is_attack", False)) for p in my_preds)
                        st.markdown("**Distribución de predicciones de este ataque:**")
                        c1, c2 = st.columns(2)
                        c1.dataframe(
                            pd.DataFrame(cat_counts.most_common(),
                                         columns=["Categoría ML", "Conteo"]),
                            hide_index=True, use_container_width=True,
                        )
                        c2.dataframe(
                            pd.DataFrame([{"is_attack": k, "Conteo": v}
                                          for k, v in atk_counts.items()]),
                            hide_index=True, use_container_width=True,
                        )

    st.divider()

    # ── Sección B ──
    st.markdown("### B. Ataques HTTP directos contra DVWA")
    st.caption(
        "Payloads HTTP crudos que viajan por el bridge docker y disparan "
        "**firmas Suricata ET Open** (SQLi, XSS, Shellshock, User-Agents de "
        "herramientas ofensivas). No pasan por el sensor → **no generan "
        "predicciones ML**, solo alertas Suricata."
    )

    cats_enabled = st.multiselect(
        "Categorías de payload",
        options=["sqli", "xss", "traversal", "shellshock", "badagent", "recon", "bruteforce"],
        default=["sqli", "xss", "badagent", "recon"],
        format_func=lambda x: {
            "sqli": "SQL Injection",
            "xss": "XSS (Reflected + Stored)",
            "traversal": "Directory Traversal / LFI",
            "shellshock": "Shellshock (CVE-2014-6271)",
            "badagent": "User-Agents maliciosos (Nikto, sqlmap, zgrab...)",
            "recon": "Recon paths (wp-admin, .env, .git, phpmyadmin...)",
            "bruteforce": "Bruteforce login (27 intentos)",
        }.get(x, x),
        key="atk_cats",
    )

    if st.button("Disparar payloads HTTP", type="primary", use_container_width=True):
        if not cats_enabled:
            st.warning("Selecciona al menos una categoría.")
        else:
            with st.status("Enviando payloads contra DVWA...", expanded=True) as status:
                t0 = time.time()
                http_results = run_http_attacks(cats_enabled)
                elapsed = time.time() - t0
                time.sleep(2)
                new_alerts = count_alerts_now() - base_alerts
                status.update(
                    label=f"{len(http_results)} requests en {elapsed:.1f}s · "
                          f"+{new_alerts} alertas",
                    state="complete", expanded=False,
                )

            c1, c2, c3 = st.columns(3)
            c1.metric("Requests enviados", len(http_results))
            c2.metric("Categorías", len(cats_enabled))
            c3.metric("Alertas Suricata nuevas", new_alerts,
                      delta=new_alerts if new_alerts > 0 else None)

            st.markdown("**Detalle de requests:**")
            st.dataframe(pd.DataFrame(http_results), hide_index=True,
                         use_container_width=True, height=250)

            recent = latest_alert_signatures(n=15)
            if recent:
                st.markdown("**Últimas 15 alertas Suricata:**")
                st.dataframe(pd.DataFrame(recent), hide_index=True,
                             use_container_width=True, height=300)

    st.divider()

    # ── Sección C ──
    st.markdown("### C. Combo end-to-end")
    st.caption(
        "Ejecuta la batería completa: 1) `mixed` con inyección CICIDS2017 "
        "(→ ML detecta ataques), 2) payloads HTTP de todas las categorías "
        "(→ Suricata dispara firmas). Demostración completa del pipeline."
    )

    if st.button("Lanzar combo completo", use_container_width=True):
        with st.status("Combo en ejecución (~30-45 s)...", expanded=True) as status:
            st.write("Paso 1/2: Sensor 'mixed' 15s @ 30 pkts/s + inject CICIDS...")
            r1 = launch_sensor_capture("mixed", duration=15, intensity=30, inject_dataset=True)
            if "error" in r1:
                status.update(label=f"Sensor falló: {r1['error']}", state="error")
            else:
                st.write(f"  → pkts={r1.get('packets_captured', 0)} flows={r1.get('flows_extracted', 0)}")

            st.write("Paso 2/2: Payloads HTTP de todas las categorías...")
            all_cats = ["sqli", "xss", "traversal", "shellshock",
                        "badagent", "recon", "bruteforce"]
            http_r = run_http_attacks(all_cats)
            st.write(f"  → {len(http_r)} requests enviados")

            time.sleep(3)
            final_alerts = count_alerts_now() - base_alerts
            final_preds = count_predictions_now() - base_preds
            status.update(
                label=f"Combo listo · +{final_alerts} alertas Suricata · "
                      f"+{final_preds} predicciones ML",
                state="complete", expanded=False,
            )

        c1, c2 = st.columns(2)
        c1.metric("Alertas Suricata (Δ)", final_alerts)
        c2.metric("Predicciones ML (Δ)", final_preds)
        st.info(
            f"**Siguiente paso**: abre [Grafana](http://{HOST_IP}:3000) → "
            "**IDS-ML Overview v2** con time range `Last 15 minutes`. "
            "Deberías ver picos en ambos paneles (Suricata y ML)."
        )


# ═══════════════════════════════════════════════════════════════
# TAB 6: Suricata vs ML
# ═══════════════════════════════════════════════════════════════
with tab_compare:
    st.header("Suricata (firmas) vs ML (aprendizaje)")
    st.markdown("""
Las dos formas dominantes de detección de intrusiones tienen **errores diferentes**:

| Enfoque | Fortalezas | Debilidades |
|---|---|---|
| **Suricata** (firmas ET Open ~50k) | Ataques **conocidos**, firma-por-firma muy preciso, bajo FP si la firma está bien escrita | No ve **zero-days**; se evade cambiando el pattern exacto; mantenimiento humano de reglas |
| **ML** (Random Forest sobre CICIDS2017) | Aprende patrones **generales** (comportamiento), detecta variantes y anomalías | Falsos positivos en tráfico legítimo inusual; se evade con perturbaciones adversariales; caja negra relativa |

Un SOC moderno los combina para cubrir los **blind spots** de cada uno.
""")

    with st.expander("¿Qué significan los veredictos de correlación?", expanded=False):
        st.markdown("""
Cuando cruzamos predicciones ML ↔ alertas Suricata por **5-tupla** (src_ip, dst_ip, src_port, dst_port, proto):

- **`both_detected`** — Ambos marcaron ataque. **Alta confianza** de ataque real.
- **`ml_only`** — Solo el ML lo marcó. Candidato a **zero-day** o variante nueva sin firma. Investigar: ¿falso positivo del ML o ataque desconocido?
- **`suricata_only`** — Solo Suricata disparó. Puede ser **falso negativo del ML** (no aprendió esa variante) o **falso positivo de la firma**.
- **`both_clean`** — Ambos dicen "benigno". Probablemente tráfico legítimo.

En el lab aún hay asimetría: Suricata escucha el bridge docker y ve **todos los ataques HTTP**; el ML solo ve lo que procesa el sensor (capturas puntuales + flujos inyectados). Por eso `suricata_only` es común.
""")

    eve_path = EVE_JSON_PATH
    if not os.path.exists(eve_path):
        st.info(f"`eve.json` no encontrado en {LOGS_DIR}.")
    else:
        try:
            lines = open(eve_path).readlines()
            alerts = [json.loads(l) for l in lines if '"event_type":"alert"' in l]
            flows = [json.loads(l) for l in lines if '"event_type":"flow"' in l]

            c1, c2, c3 = st.columns(3)
            c1.metric("Alertas Suricata", f"{len(alerts):,}")
            c2.metric("Flows observados (Suricata)", f"{len(flows):,}")
            c3.metric("Eventos eve.json totales", f"{len(lines):,}")

            if alerts:
                sigs = collections.Counter(a.get("alert", {}).get("signature", "?") for a in alerts)
                sig_df = pd.DataFrame(sigs.most_common(15), columns=["Firma", "Conteo"])
                fig = px.bar(sig_df, x="Conteo", y="Firma", orientation="h",
                             color="Conteo", color_continuous_scale="Reds",
                             title="Top 15 firmas Suricata disparadas")
                fig.update_layout(height=500, yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig, use_container_width=True)

                sev_counts = collections.Counter(
                    a.get("alert", {}).get("severity", 0) for a in alerts)
                sev_df = pd.DataFrame(
                    [{"Severidad": k, "Conteo": v} for k, v in sorted(sev_counts.items())])
                c1, c2 = st.columns(2)
                c1.subheader("Severidad (1=high, 3=low)")
                c1.dataframe(sev_df, use_container_width=True, hide_index=True)

                c2.subheader("Últimas 20 alertas")
                last = []
                for a in alerts[-20:]:
                    last.append({
                        "ts": a.get("timestamp", "")[:19],
                        "sig": a.get("alert", {}).get("signature", "")[:60],
                        "sev": a.get("alert", {}).get("severity", ""),
                        "src": f"{a.get('src_ip', '')}:{a.get('src_port', '')}",
                        "dst": f"{a.get('dest_ip', '')}:{a.get('dest_port', '')}",
                    })
                c2.dataframe(pd.DataFrame(last), use_container_width=True,
                             hide_index=True, height=400)

                st.subheader("Correlación ML↔Suricata por flujo (5-tupla)")
                ml_preds = load_sensor_predictions(limit=2000)
                if not ml_preds:
                    st.info(
                        "Sin predicciones ML aún. Ve al tab **Ataques** y lanza "
                        "un ataque vía sensor para poblar `sensor_predictions.jsonl`."
                    )
                else:
                    corr = correlate_5tuple(ml_preds, alerts)
                    vc = collections.Counter(r['Veredicto'] for r in corr)
                    total = len(corr)
                    agree = ((vc.get('both_detected', 0) + vc.get('both_clean', 0))
                             / total if total else 0)
                    k1, k2, k3, k4, k5 = st.columns(5)
                    k1.metric("Flujos correlacionados", total)
                    k2.metric("Ambos detectaron", vc.get('both_detected', 0))
                    k3.metric("Solo ML", vc.get('ml_only', 0))
                    k4.metric("Solo Suricata", vc.get('suricata_only', 0))
                    k5.metric("Acuerdo", f"{agree:.0%}")

                    # Matriz 2x2 visual
                    matrix_data = pd.DataFrame(
                        [[vc.get('both_detected', 0), vc.get('ml_only', 0)],
                         [vc.get('suricata_only', 0), vc.get('both_clean', 0)]],
                        index=["Suricata: Alerta", "Suricata: Sin alerta"],
                        columns=["ML: Ataque", "ML: Benigno"],
                    )
                    fig = px.imshow(
                        matrix_data, text_auto=True, color_continuous_scale='Blues',
                        aspect='auto',
                        title="Matriz de acuerdo Suricata ↔ ML",
                        labels=dict(x="", y="", color="Flujos"),
                    )
                    fig.update_layout(height=380)
                    st.plotly_chart(fig, use_container_width=True)

                    verdict_badge = {
                        'both_detected': 'Ambos detectaron',
                        'ml_only': 'Solo ML (zero-day?)',
                        'suricata_only': 'Solo Suricata',
                        'both_clean': 'Ambos limpio',
                    }
                    df_corr = pd.DataFrame([
                        {**r, 'Veredicto': verdict_badge.get(r['Veredicto'], r['Veredicto'])}
                        for r in corr[:200]
                    ])
                    st.dataframe(df_corr, use_container_width=True,
                                 hide_index=True, height=320)

                    discrepancias = [r for r in corr
                                     if r['Veredicto'] in ('ml_only', 'suricata_only')]
                    if discrepancias:
                        with st.expander(
                                f"Discrepancias ML ↔ Suricata ({len(discrepancias)})",
                                expanded=False):
                            st.caption(
                                "Flujos donde un sistema alerta y el otro no. "
                                "Son los casos más interesantes pedagógicamente — "
                                "candidatos a evasión adversarial o firmas faltantes."
                            )
                            st.dataframe(pd.DataFrame(discrepancias[:50]),
                                         use_container_width=True, hide_index=True)

                    now_iso = datetime.now(timezone.utc).isoformat()
                    save_history_entry({
                        'timestamp': now_iso,
                        'n_ml_flows': len(ml_preds),
                        'n_suricata_alerts': len(alerts),
                        'verdicts': dict(vc),
                        'agreement_rate': round(agree, 4),
                    })
            else:
                st.info(
                    "Aún no hay alertas Suricata. Ve al tab **Ataques** y "
                    "lanza payloads HTTP para generar alertas."
                )
        except Exception as e:
            st.warning(f"Error leyendo eve.json: {e}")

    # Historial
    history = load_history()
    if history:
        st.divider()
        st.subheader("Historial de snapshots de correlación")
        df_hist = pd.DataFrame([
            {
                'Hora': h.get('timestamp', '')[:19].replace('T', ' '),
                'ML flows': h.get('n_ml_flows', 0),
                'Suricata alerts': h.get('n_suricata_alerts', 0),
                'Ambos': h.get('verdicts', {}).get('both_detected', 0),
                'Solo ML': h.get('verdicts', {}).get('ml_only', 0),
                'Solo Suri': h.get('verdicts', {}).get('suricata_only', 0),
                'Acuerdo': f"{h.get('agreement_rate', 0):.0%}",
            } for h in reversed(history[-30:])
        ])
        st.dataframe(df_hist, use_container_width=True, hide_index=True, height=250)
        try:
            with open(LAB_HISTORY_PATH, 'rb') as fh:
                st.download_button(
                    "Descargar histórico (JSONL)", data=fh.read(),
                    file_name='lab_history.jsonl', mime='application/x-ndjson',
                )
        except Exception:
            pass
        st.caption(f"Rotación automática a {HISTORY_MAX_ENTRIES} entradas.")


# ═══════════════════════════════════════════════════════════════
# Footer
# ═══════════════════════════════════════════════════════════════
st.markdown("---")
st.caption(
    "Maestría en IA Aplicada · UDLA 2026 · "
    f"Dashboard v2 · [Grafana](http://{HOST_IP}:3000) · "
    f"[Jupyter](http://{HOST_IP}:8888) · "
    f"[DVWA](http://{HOST_IP}:8080)"
)

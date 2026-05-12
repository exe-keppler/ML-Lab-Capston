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


def _append_interactive_prediction(model: str, resp: dict, preset_label):
    """Persiste una predicción del tab Predicción al mismo JSONL que escribe
    el sensor. De ahí Promtail → Loki → Grafana, así las predicciones
    interactivas aparecen en los dashboards SOC RF/XGBoost junto con las
    del sensor.

    Marcamos con source='dashboard' y src_ip='interactive' para que un
    analista pueda filtrar este origen sintético si quiere ver sólo
    tráfico real capturado."""
    import uuid
    entry = {
        "request_id": f"dash-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "interactive",
        "dst_ip": "interactive",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "interactive",
        "category": str(resp.get("category", "?")),
        "confidence": float(resp.get("category_confidence", 0)),
        "is_attack": bool(resp.get("is_attack", False)),
        "n_packets": 1,
        "model": model,
        "source": "dashboard",
        "preset_label": preset_label or "?",
    }
    try:
        with open(SENSOR_PREDICTIONS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        # Best-effort: no romper la UI si el log no se puede escribir.
        pass


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
def compute_confusion_matrix(n_per_class=50, model="rf"):
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
            f"{API_URL}/predict/batch?model={model}",
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


# Firmas de Suricata que son del decoder/parser (warnings, no ataques reales).
# Sin filtrar dominaban el top firmas y tapaban las firmas ET Open de verdad.
SURICATA_NOISE_PREFIXES = (
    "SURICATA HTTP ",
    "SURICATA Applayer ",
    "SURICATA STREAM ",
    "SURICATA TLS ",
    "SURICATA SMTP ",
    "SURICATA TCPv4 ",
    "SURICATA IPv4 ",
    "SURICATA UDP ",
    "SURICATA ICMPv4 ",
    "SURICATA Stream ",
)
SURICATA_NOISE_CATEGORIES = {
    "Generic Protocol Command Decode",
    "Application Layer Protocol Detection",
}


def is_real_alert(alert):
    """True si la alerta es una firma de ataque real (no warning del decoder)."""
    a = alert.get("alert", {}) if isinstance(alert, dict) else {}
    sig = a.get("signature", "")
    cat = a.get("category", "")
    if cat in SURICATA_NOISE_CATEGORIES:
        return False
    if any(sig.startswith(p) for p in SURICATA_NOISE_PREFIXES):
        return False
    return True


@st.cache_data(ttl=30, show_spinner=False)
def load_eve_recent(max_bytes=5_000_000):
    """Tail de eve.json: lee solo los últimos ~max_bytes en lugar de
    cargar el archivo completo (que crece a 100+ MB en sesiones largas).
    Cache 30 s para no relanzar el parse en cada render.
    Devuelve (alerts, flows, n_lines_recientes, total_size_bytes)."""
    if not os.path.exists(EVE_JSON_PATH):
        return [], [], 0, 0
    try:
        size = os.path.getsize(EVE_JSON_PATH)
        with open(EVE_JSON_PATH, 'rb') as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()  # descartar primera línea (probable truncamiento)
            raw = f.read().decode('utf-8', 'replace').splitlines()
        alerts, flows = [], []
        for ln in raw:
            if '"event_type":"alert"' in ln:
                try: alerts.append(json.loads(ln))
                except Exception: pass
            elif '"event_type":"flow"' in ln:
                try: flows.append(json.loads(ln))
                except Exception: pass
        return alerts, flows, len(raw), size
    except Exception:
        return [], [], 0, 0


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
    st.header("¿Cómo funciona el laboratorio?")
    st.markdown(
        "Este lab implementa un **IDS híbrido**: el tráfico pasa por **2 detectores en paralelo** "
        "(un IDS por firmas y un modelo de ML), los resultados se persisten, se centralizan en Loki, "
        "y se visualizan en Grafana. Abajo está el pipeline completo paso por paso."
    )

    st.divider()

    # ──── El pipeline (diagrama Graphviz) ────
    st.subheader("El pipeline (de paquete a dashboard)")
    dot = """
digraph pipeline {
    rankdir=LR;
    bgcolor=transparent;
    nodesep=0.4;
    ranksep=0.5;
    node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=11, margin=0.15];
    edge [fontname="Helvetica", fontsize=9, color="#94a3b8"];

    trafico  [label="Tráfico\\n(bridge docker\\no NIC física)", fillcolor="#f1f5f9"];

    sensor   [label="1. Sensor\\n(scapy + FastAPI)\\ncaptura paquetes", fillcolor="#dbeafe"];
    suricata [label="1. Suricata\\n(AF_PACKET)\\nIDS por firmas", fillcolor="#dbeafe"];

    cicflow  [label="2. CICFlowMeter\\n47 features por flujo\\n(duración, IAT, flags...)", fillcolor="#fef3c7"];

    mlapi    [label="3. ML API\\nRF + XGBoost\\nbinary + multiclase + SHAP", fillcolor="#dcfce7"];
    rules    [label="3. ET Open\\n~50k reglas\\n(SQLi, XSS, Recon, ...)", fillcolor="#dcfce7"];

    jsonl    [label="4. sensor_predictions\\n.jsonl", fillcolor="#f3e8ff"];
    eve      [label="4. eve.json\\n(alerts + flows)", fillcolor="#f3e8ff"];

    promtail [label="Promtail\\n(tail logs)", fillcolor="#fee2e2"];
    loki     [label="Loki\\n(log store)", fillcolor="#fee2e2"];
    grafana  [label="5. Grafana\\ndashboards SOC\\n(RF, XGB, Suricata, correlación)", fillcolor="#fce7f3"];

    trafico -> sensor;
    trafico -> suricata;

    sensor   -> cicflow -> mlapi -> jsonl;
    suricata -> rules   -> eve;

    jsonl -> promtail;
    eve   -> promtail;
    promtail -> loki -> grafana;
}
"""
    st.graphviz_chart(dot, use_container_width=True)
    st.caption(
        "🔵 captura · 🟡 extracción · 🟢 análisis · 🟣 persistencia · 🔴 transporte · 🌸 visualización"
    )

    st.divider()

    # ──── Cada paso explicado ────
    st.subheader("Cada paso del pipeline")
    st.markdown(
        "El mismo tráfico se analiza por **2 caminos en paralelo** (ML y reglas), "
        "y los resultados convergen en Grafana para correlacionar."
    )

    p1, p2 = st.columns(2)
    with p1:
        st.markdown("##### 🤖 Camino ML (aprendizaje)")
        st.markdown("""
1. **Sensor** (FastAPI + scapy) — sniffea el bridge docker / NIC del host.
2. **CICFlowMeter** — agrupa paquetes en flujos bidireccionales y calcula **47 features estadísticas** por flujo (Flow_Duration, IAT, flags TCP, packet length stats, etc.).
3. **ML API** — los flujos pasan por 2 modelos:
   - **Binary**: ¿es ataque o no?
   - **Multiclase**: ¿qué tipo de ataque? (DDoS, DoS, BF, Recon, Web Attack, Benign)
   - **SHAP** explica cuáles features pesaron más en la decisión.
4. **JSONL** — cada predicción se appendea a `sensor_predictions.jsonl`.
""")
    with p2:
        st.markdown("##### 📜 Camino reglas (firmas)")
        st.markdown("""
1. **Suricata 7.0.15** — escucha la misma interfaz que el sensor, vía AF_PACKET.
2. (No hay paso de feature engineering: las reglas comparan **bytes crudos** del paquete o flags del protocolo.)
3. **ET Open** — ~50k reglas mantenidas por Emerging Threats:
   ```
   alert tcp any -> $HOME_NET 80 (content:"UNION SELECT"; sid:XXX;)
   ```
4. **eve.json** — cada match genera un evento `alert`. También loggea `flow`, `http`, `dns`, etc.
""")

    st.markdown("---")
    st.markdown(
        "##### 🎯 Convergencia: **Promtail → Loki → Grafana**\n\n"
        "Ambos JSONLs los tail-ea **Promtail**, los empuja a **Loki** (log store) con labels "
        "(`model=rf|xgb`, `is_attack=true|false`, `category=...`), y **Grafana** los consulta "
        "en vivo. Los 5 dashboards SOC del lab cruzan ML vs Suricata por **5-tupla** "
        "(src_ip, dst_ip, src_port, dst_port, proto) para encontrar **discrepancias** "
        "(zero-days candidatos o falsos positivos)."
    )

    st.divider()

    # ──── Acceso a servicios ────
    st.subheader("Servicios accesibles desde tu browser")
    s1, s2, s3, s4 = st.columns(4)
    s1.link_button("📊 Grafana", f"http://{HOST_IP}:3000", use_container_width=True)
    s2.link_button("🔬 JupyterLab", f"http://{HOST_IP}:8888", use_container_width=True)
    s3.link_button("🎯 DVWA (target)", f"http://{HOST_IP}:8080", use_container_width=True)
    s4.link_button("⚙️ Sensor API docs", f"http://{HOST_IP}:9999/docs", use_container_width=True)
    st.caption(
        f"Todos sobre `{HOST_IP}`. El dashboard que estás viendo va por nginx en el puerto 80 con BasicAuth."
    )

    st.divider()

    # ──── Recorrido recomendado ────
    st.subheader("Recorrido recomendado de las tabs")
    st.markdown("""
| # | Tab | Qué aprendés | Conecta con el pipeline |
|---|---|---|---|
| 1 | **Dataset** | Con qué datos entrenó el modelo, distribución por clase | Insumo del **paso 3 (ML API)** |
| 2 | **Métricas** | Qué tan bueno es el modelo, dónde se equivoca | Calidad del **paso 3** |
| 3 | **Predicción** | Clasificar flujos manualmente + SHAP | Camino corto: **paso 3** directo (sin 1 y 2) |
| 4 | **Ataques** | Lanzar ataques reales contra DVWA | Genera entrada para **pasos 1–4** |
| 5 | **Suricata vs ML** | Comparar los 2 caminos del pipeline | Lectura del **paso 5 (Grafana)** |
""")

    st.divider()
    with st.expander("📖 Glosario rápido"):
        st.markdown("""
- **IDS (Intrusion Detection System)**: sistema que detecta intentos de ataque en una red.
- **Suricata**: IDS open-source multithread, base del lab. Reglas tipo `alert tcp any -> $HOME_NET 80 (content:"UNION SELECT"; sid:XXX;)`.
- **ET Open (Emerging Threats)**: set gratuito de ~50k reglas Suricata mantenido por la comunidad.
- **Random Forest**: ensemble de cientos de árboles de decisión. Cada árbol vota y se toma la mayoría.
- **XGBoost**: gradient boosting de árboles. Cada árbol corrige los errores del anterior.
- **CICIDS2017**: dataset benchmark del Canadian Institute for Cybersecurity con 14+ tipos de ataque.
- **Flow (flujo)**: secuencia bidireccional de paquetes entre dos endpoints (mismo src/dst/puertos/proto).
- **CICFlowMeter**: extractor de 80+ estadísticas por flujo (duración, bytes, IAT, flags TCP, etc.). El modelo v2 usa 47 auditadas.
- **5-tupla**: (src_ip, dst_ip, src_port, dst_port, protocolo) — clave para identificar un flujo.
- **MITRE ATT&CK**: framework que clasifica técnicas de ataque observadas en el mundo real (T1046, T1110, ...).
- **SHAP**: método de explicabilidad que muestra cuánto contribuyó cada feature a una predicción específica.
- **Zero-day**: ataque sin firma conocida — ML puede ser más efectivo aquí que Suricata.
- **False Positive (FP)** / **False Negative (FN)**: tráfico benigno marcado como ataque / ataque no detectado.
""")

# ═══════════════════════════════════════════════════════════════
# TAB 2: Dataset Explorer
# ═══════════════════════════════════════════════════════════════
with tab_dataset:
    st.header("¿Con qué datos se entrenó el modelo?")

    df = load_dataset()
    if df is None:
        st.error(f"Dataset no encontrado en `{DATASET_PATH}`. "
                 "Asegúrate de que el volumen `./datasets` esté montado.")
        st.stop()

    st.markdown(
        "**CICIDS2017** es uno de los datasets más usados para entrenar IDS por ML. "
        "Lo armó el Canadian Institute for Cybersecurity capturando **5 días de tráfico real** "
        "en una red controlada, ejecutando ataques a propósito en horarios programados. "
        "El subset que ves abajo es **balanceado** (mismo número de muestras por clase) — "
        "no es el ratio que verías en producción, pero es necesario para que el modelo "
        "aprenda a reconocer todas las categorías por igual."
    )

    feat_cols = [c for c in df.columns if c != 'Label_6']
    per_class = int(df['Label_6'].value_counts().min())

    # ──── 4 headlines ────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric(
        "Flujos",
        f"{len(df):,}",
        help="Cada fila del dataset es un flujo de red (secuencia de paquetes entre 2 endpoints).",
    )
    c2.metric(
        "Features por flujo",
        len(feat_cols),
        help="Estadísticas calculadas por CICFlowMeter sobre cada flujo: duración, "
             "tamaño promedio de paquete, flags TCP, IAT, etc.",
    )
    c3.metric(
        "Clases",
        df['Label_6'].nunique(),
        help="Benign + 5 familias de ataque (DoS, DDoS, Brute Force, Reconnaissance, Web Attack).",
    )
    c4.metric(
        "Balance",
        f"{per_class:,} / clase",
        help="Mismo número de muestras por clase para que el modelo no se vuelva 'perezoso' "
             "prediciendo siempre la clase mayoritaria. En tráfico real, benigno sería ~99%.",
    )

    st.divider()

    # ──── ¿Cómo se distribuyen? ────
    st.subheader("¿Cómo se distribuyen las clases?")
    cat_counts = df['Label_6'].value_counts().reindex(CATEGORY_ORDER).fillna(0)
    bar_df = pd.DataFrame({'Clase': cat_counts.index, 'Muestras': cat_counts.values.astype(int)})
    fig = px.bar(
        bar_df, x='Muestras', y='Clase', orientation='h',
        color='Clase', color_discrete_map=CATEGORY_COLORS,
        text='Muestras',
    )
    fig.update_traces(textposition='outside')
    fig.update_layout(height=320, showlegend=False, yaxis={'categoryorder': 'array',
                                                            'categoryarray': CATEGORY_ORDER[::-1]})
    st.plotly_chart(fig, use_container_width=True)
    st.info(
        f"📌 Las 6 clases tienen **{per_class:,} muestras cada una** — perfectamente balanceadas. "
        "Esto es **intencional**: si entrenás con la distribución real (~99% benigno), el modelo "
        "aprende a decir 'Benign' a todo y parece tener 99% de accuracy sin haber detectado ningún ataque. "
        "Por eso balanceamos al entrenar y **medimos con F1-macro** (no accuracy)."
    )

    st.divider()

    # ──── ¿Qué features separan mejor las clases? ────
    st.subheader("¿Qué features separan mejor las clases?")
    st.markdown(
        "Elegí una feature y mirá cómo distribuye sus valores cada clase. "
        "Si los rangos de distintos colores **NO se solapan**, esa feature por sí sola "
        "ya distingue ataques. Si se solapan mucho, el modelo necesita combinarla con otras."
    )

    c1, c2 = st.columns([3, 1])
    with c1:
        default_feat = "Flow_Duration" if "Flow_Duration" in feat_cols else feat_cols[0]
        feature_choice = st.selectbox(
            "Feature",
            options=feat_cols,
            index=feat_cols.index(default_feat),
            key="ds_feature_choice",
            help="Tip: empezá por `Flow_Duration`, `Total_Fwd_Packets`, `Flow_Bytes_per_s`.",
        )
    with c2:
        viz_type = st.radio(
            "Vista",
            options=["Box plot", "Histograma"],
            horizontal=True,
            key="ds_viz_type",
            help="Box plot: más fácil de comparar entre clases. Histograma: forma de la distribución.",
        )

    if viz_type == "Box plot":
        fig = px.box(
            df, x='Label_6', y=feature_choice,
            color='Label_6', color_discrete_map=CATEGORY_COLORS,
            category_orders={'Label_6': CATEGORY_ORDER},
            points=False, log_y=True,
        )
        fig.update_layout(height=420, showlegend=False,
                          xaxis_title="", yaxis_title=feature_choice + "  (log)")
    else:
        fig = px.histogram(
            df, x=feature_choice, color='Label_6',
            color_discrete_map=CATEGORY_COLORS,
            marginal="box", nbins=40, log_y=True,
            category_orders={'Label_6': CATEGORY_ORDER},
        )
        fig.update_layout(height=450)
    st.plotly_chart(fig, use_container_width=True)

    # Diagnóstico automático: qué clase se distingue más para esta feature
    try:
        # Comparar las medianas: la clase con mediana MÁS lejos de las demás
        # es la "más distinguible" por esta feature sola.
        med = df.groupby('Label_6')[feature_choice].median()
        # Excluir clases que no estén en CATEGORY_ORDER (defensive)
        med = med.reindex([c for c in CATEGORY_ORDER if c in med.index]).dropna()
        if len(med) >= 2:
            distances = pd.Series({
                c: abs(med[c] - med.drop(c).median()) for c in med.index
            })
            most_distinct = distances.idxmax()
            ref_others = float(med.drop(most_distinct).median())
            md_val = float(med[most_distinct])
            if ref_others != 0 and md_val != 0:
                ratio = md_val / ref_others if abs(md_val) > abs(ref_others) else ref_others / md_val
                ratio_txt = f"{abs(ratio):.1f}×"
            else:
                ratio_txt = "muy distinto"
            st.info(
                f"📌 Para **`{feature_choice}`**, la clase que más se distingue es "
                f"**{most_distinct}** — su mediana ({md_val:,.2f}) es **{ratio_txt}** "
                f"la de las demás ({ref_others:,.2f}). El modelo va a usar mucho esta feature "
                f"cuando vea tráfico {most_distinct}."
            )
    except Exception:
        pass

    st.divider()

    # ──── Expander: detalle avanzado ────
    with st.expander("📊 Detalle avanzado (muestra cruda, correlaciones, calidad, descarga)"):
        # — Random sample —
        st.markdown("### Ver filas crudas del dataset")
        n = st.slider("Cuántas filas mostrar", 10, 200, 30, 10, key="ds_sample_n")
        st.dataframe(df.sample(n, random_state=42).reset_index(drop=True),
                     use_container_width=True, height=300)
        st.caption(
            "Las features están **escaladas con StandardScaler** (media 0, std 1) — por eso "
            "ves valores negativos. El modelo entrena sobre estos valores, no los crudos."
        )

        # — Correlation matrix —
        st.markdown("### Correlación entre las top features del modelo")
        st.caption(
            "Dos features muy correlacionadas (cerca de **+1** o **-1**) son **redundantes**: "
            "el modelo podría usar una sola sin perder info. Cerca de **0** son independientes."
        )
        m_metrics = fetch_metrics()
        top10 = [x["feature"] for x in m_metrics.get("feature_importance_gini_top20", [])[:10]]
        top10 = [f for f in top10 if f in df.columns]
        if len(top10) >= 3:
            corr = df[top10].corr()
            fig = px.imshow(
                corr, color_continuous_scale='RdBu_r',
                zmin=-1, zmax=1, text_auto='.2f', aspect='auto',
            )
            fig.update_layout(height=450)
            st.plotly_chart(fig, use_container_width=True)
            # Identificar el par más correlacionado (informativo)
            try:
                corr_abs = corr.abs()
                np.fill_diagonal(corr_abs.values, 0)
                max_pair_idx = corr_abs.stack().idxmax()
                max_pair_val = corr.loc[max_pair_idx[0], max_pair_idx[1]]
                if abs(max_pair_val) > 0.9:
                    st.warning(
                        f"⚠️ Las features **{max_pair_idx[0]}** y **{max_pair_idx[1]}** "
                        f"están correlacionadas a **{max_pair_val:+.2f}** — son casi la misma "
                        "información. Auditoría VIF las habría dropeado; en este modelo "
                        "ambas sobrevivieron al filtro."
                    )
            except Exception:
                pass

        # — Calidad —
        st.markdown("### Calidad de los datos")
        n_nulls = int(df.isna().sum().sum())
        n_inf = int(np.isinf(df.select_dtypes(include='number')).sum().sum())
        constant_cols = [c for c in df.columns if c != 'Label_6' and df[c].nunique() <= 1]
        qc1, qc2, qc3 = st.columns(3)
        qc1.metric("Valores nulos (NaN)", f"{n_nulls:,}")
        qc2.metric("Valores infinitos", f"{n_inf:,}")
        qc3.metric("Cols constantes", len(constant_cols))
        if constant_cols:
            st.caption(f"Constantes: {', '.join(constant_cols)}")
        else:
            st.caption(
                "Sin nulos, sin infinitos, sin constantes — el dataset ya pasó el preprocessing "
                "del notebook 02. Lo que ves es exactamente lo que entró al modelo."
            )

        # — Download —
        st.markdown("### Descargar")
        try:
            with open(DATASET_PATH, 'rb') as fh:
                st.download_button(
                    "Descargar dataset (parquet, ~1.3 MB)",
                    data=fh.read(),
                    file_name='cicids_test.parquet',
                    mime='application/octet-stream',
                )
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# TAB 3: Métricas del modelo
# ═══════════════════════════════════════════════════════════════
with tab_metrics:
    st.header("¿Qué tan bueno es el modelo?")

    m = fetch_metrics()
    if not m:
        st.error("No se pudieron obtener métricas del ML API.")
        st.stop()

    # ──── Selector de modelo ÚNICO para todo el tab ────
    # Maneja headline metrics + matriz de confusión. Por defecto: RF.
    try:
        avail = requests.get(f"{API_URL}/health", timeout=3).json().get("available_models", ["rf"])
    except Exception:
        avail = ["rf"]
    metric_model = st.radio(
        "Modelo a evaluar",
        options=avail,
        format_func=lambda mm: {"rf": "Random Forest v2", "xgb": "XGBoost v2"}.get(mm, mm),
        horizontal=True,
        key="metrics_model_view",
    )
    # API key del modelo seleccionado: 'rf' → m['rf'], 'xgb' → m['xgboost']
    _mk = "xgboost" if metric_model == "xgb" else "rf"
    sel = m.get(_mk, {})
    sel_mc = sel.get("multiclass", {})
    sel_bin = sel.get("binary", {})

    # ──── 3 números headline (del modelo elegido) ────
    c1, c2, c3 = st.columns(3)
    c1.metric(
        "Accuracy (categoría)",
        f"{sel_mc.get('accuracy', 0):.1%}",
        help="De cada 100 flujos del test set, cuántos clasificó en la categoría correcta "
             "(entre Benign / DDoS / DoS / Brute Force / Reconnaissance / Web Attack).",
    )
    c2.metric(
        "F1-macro (categoría)",
        f"{sel_mc.get('F1_macro', 0):.3f}",
        help="Promedio del F1 por clase, sin ponderar por tamaño. Es la métrica que importa "
             "cuando las clases están desbalanceadas: si una clase rara va mal, F1-macro baja "
             "mucho aunque la accuracy siga alta.",
    )
    c3.metric(
        "F1 binario (¿es ataque?)",
        f"{sel_bin.get('F1_weighted', 0):.3f}",
        help="Independientemente de la categoría: ¿el modelo distingue ataque vs benigno? "
             "Casi siempre el binario es más fácil que el multiclase.",
    )

    st.caption(
        f"Evaluado sobre **{m.get('n_test', 0):,}** flujos del test set "
        f"(nunca vistos en entrenamiento) usando **{m.get('n_features','?')}** features "
        f"auditadas. Pipeline: **{m.get('pipeline','?')}**."
    )

    st.divider()

    # ──── ¿Dónde se equivoca? — Matriz de confusión (UNA, normalizada) ────
    st.subheader("¿Dónde se equivoca?")
    st.markdown(
        "Cada fila es una clase real, cada columna lo que el modelo predijo. "
        "La **diagonal son aciertos**; fuera de la diagonal, confusiones. "
        f"(modelo: **{ {'rf':'Random Forest v2','xgb':'XGBoost v2'}.get(metric_model, metric_model) }**)"
    )

    if st.button("Recalcular con nueva muestra"):
        st.cache_data.clear()
        st.rerun()

    # Usa el mismo metric_model — la matriz y los headlines siempre van sincronizados.
    cm_df = compute_confusion_matrix(n_per_class=50, model=metric_model)
    if cm_df is None or cm_df.empty:
        st.warning("No se pudo calcular (dataset o API no disponible).")
    else:
        cats = CATEGORY_ORDER
        cm = pd.crosstab(cm_df['y_true'], cm_df['y_pred'],
                         rownames=['Real'], colnames=['Predicho'])
        for c in cats:
            if c not in cm.columns: cm[c] = 0
            if c not in cm.index: cm.loc[c] = 0
        cm = cm.loc[cats, cats]
        cm_norm = cm.div(cm.sum(axis=1), axis=0).fillna(0)

        fig = px.imshow(
            cm_norm, text_auto='.0%', color_continuous_scale='Blues',
            aspect='auto', zmin=0, zmax=1,
            labels=dict(x="Predicho", y="Real", color="% acierto"),
        )
        fig.update_layout(height=420)
        st.plotly_chart(fig, use_container_width=True)

        accuracy = (cm_df['y_true'] == cm_df['y_pred']).mean()
        correct = int((cm_df['y_true'] == cm_df['y_pred']).sum())
        st.success(
            f"En este sample: **{accuracy:.0%}** acierto "
            f"({correct}/{len(cm_df)} predicciones correctas)."
        )

        # Diagnóstico automático
        diag = cm_norm.apply(
            lambda row: row[row.name] if row.name in row.index else 0, axis=1
        )
        worst_class = diag.idxmin()
        worst_recall = float(diag.loc[worst_class])
        if worst_recall < 1.0 and len(cm_norm.columns) > 1:
            confused_with = cm_norm.loc[worst_class].drop(worst_class).idxmax()
            st.info(
                f"📌 La clase más débil es **{worst_class}** (recall {worst_recall:.0%}). "
                f"Cuando se equivoca, suele confundirla con **{confused_with}**."
            )

    st.divider()

    # ──── ¿En qué se basa? — Feature importance (top 10) ────
    st.subheader("¿En qué se basa el modelo?")
    fi = m.get("feature_importance_gini_top20", [])
    if fi:
        fi_df = pd.DataFrame(fi[:10])
        fig = px.bar(
            fi_df, x="importance", y="feature", orientation="h",
            color="importance", color_continuous_scale="Viridis",
        )
        fig.update_layout(yaxis={'categoryorder': 'total ascending'}, height=380,
                          xaxis_title="Importancia relativa", yaxis_title="")
        st.plotly_chart(fig, use_container_width=True)
        st.caption(
            f"Las 10 features que más usa el modelo (de las {m.get('n_features', 47)} disponibles). "
            "Medido por Gini: cuánto reduce la impureza cada vez que el modelo parte por esa feature. "
            "Esto es **uso**, no necesariamente **causalidad**."
        )

    st.divider()

    # ──── Detalle avanzado (oculto por default) ────
    with st.expander("📊 Métricas avanzadas (per-clase, RF vs XGB, baselines, hyperparams, conteos absolutos)"):
        # — Per clase —
        st.markdown("### Reporte por clase (multiclase, test)")
        cr = m.get("multiclass", {}).get("classification_report", {})
        rows = []
        for cls, stats in cr.items():
            if isinstance(stats, dict) and "f1-score" in stats:
                rows.append({
                    "Clase": cls,
                    "Precision": round(stats.get("precision", 0), 3),
                    "Recall":    round(stats.get("recall", 0), 3),
                    "F1":        round(stats.get("f1-score", 0), 3),
                    "Support":   int(stats.get("support", 0)),
                })
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
            st.caption(
                "**Precision** = de todo lo que predije como X, cuánto era X (bajo ⇒ falsos positivos). "
                "**Recall** = de todo lo que era X, cuánto detecté (bajo ⇒ falsos negativos)."
            )

        # — RF vs XGB —
        rf_metrics = m.get("rf", {})
        xgb_metrics = m.get("xgboost", {})
        if rf_metrics and xgb_metrics:
            st.markdown("### RF v2 vs XGBoost v2 (ambos tuneados)")
            comp_rows = []
            if rf_metrics.get("binary") and xgb_metrics.get("binary"):
                rfb = rf_metrics["binary"].get("F1_macro", 0)
                xgbb = xgb_metrics["binary"].get("F1_macro", 0)
                comp_rows.append({"Métrica": "Binary F1-macro",
                                  "RF": f"{rfb:.4f}", "XGBoost": f"{xgbb:.4f}",
                                  "Δ (RF-XGB)": f"{rfb-xgbb:+.4f}",
                                  "Mejor": "RF" if rfb > xgbb else ("XGB" if xgbb > rfb else "=")})
            if rf_metrics.get("multiclass") and xgb_metrics.get("multiclass"):
                rfm = rf_metrics["multiclass"].get("F1_macro", 0)
                xgbm = xgb_metrics["multiclass"].get("F1_macro", 0)
                comp_rows.append({"Métrica": "Multi F1-macro",
                                  "RF": f"{rfm:.4f}", "XGBoost": f"{xgbm:.4f}",
                                  "Δ (RF-XGB)": f"{rfm-xgbm:+.4f}",
                                  "Mejor": "RF" if rfm > xgbm else ("XGB" if xgbm > rfm else "=")})
                rfa = rf_metrics["multiclass"].get("accuracy", 0)
                xgba = xgb_metrics["multiclass"].get("accuracy", 0)
                comp_rows.append({"Métrica": "Multi accuracy",
                                  "RF": f"{rfa:.4f}", "XGBoost": f"{xgba:.4f}",
                                  "Δ (RF-XGB)": f"{rfa-xgba:+.4f}",
                                  "Mejor": "RF" if rfa > xgba else ("XGB" if xgba > rfa else "=")})
            if comp_rows:
                st.dataframe(pd.DataFrame(comp_rows), hide_index=True, use_container_width=True)
                st.caption(
                    "Gap típico ~0.02 en F1-macro. RF gana en este dataset porque "
                    "`class_weight=balanced_subsample` mejora recall en clases raras."
                )

        # — Baselines —
        bl = m.get("baselines_on_v1_split", {})
        if bl:
            st.markdown("### Comparativa con baselines")
            b_df = pd.DataFrame([
                {"Modelo": "Dummy (clase mayoritaria)",
                 "F1-w": round(bl.get("dummy_majority_f1_weighted", 0), 4),
                 "Descripción": "Siempre predice 'Benign'. Techo inferior."},
                {"Modelo": f"Stump (1 split en '{bl.get('stump_feature','?')}')",
                 "F1-w": round(bl.get("stump_depth1_f1_weighted", 0), 4),
                 "Descripción": "Árbol de 1 nivel — mínima señal extraíble."},
                {"Modelo": "Árbol depth=3",
                 "F1-w": round(bl.get("tree_depth3_f1_weighted", 0), 4),
                 "Descripción": "Árbol pequeño; referencia interpretable."},
                {"Modelo": "RF v2 (200 árboles, tuned)",
                 "F1-w": round(m.get("binary", {}).get("test", {}).get("f1_weighted", 0), 4),
                 "Descripción": "Modelo de producción del lab."},
            ])
            st.dataframe(b_df, hide_index=True, use_container_width=True)
            st.caption(
                "El salto entre **Stump** y **RF** mide cuánta señal no-lineal "
                "hay en los datos."
            )

        # — Hyperparams —
        if rf_metrics and xgb_metrics:
            st.markdown("### Hyperparámetros tuneados")
            cc1, cc2 = st.columns(2)
            cc1.markdown("**RF v2**")
            cc1.json(rf_metrics.get("best_params", {}))
            cc2.markdown("**XGBoost v2**")
            cc2.json(xgb_metrics.get("best_params", {}))

        # — Split detail —
        st.markdown("### Detalle del split")
        st.caption(
            f"Train: **{m.get('n_train', 0):,}** · Val: **{m.get('n_val', 0):,}** · "
            f"Test: **{m.get('n_test', 0):,}**. El train es subsample balanceado "
            "(~10k×6 clases) del split estratificado original (1.4M flujos). Val/test "
            "quedan con distribución real (no balanceada) para evaluación honesta."
        )

        # — Conteos absolutos de la matriz —
        if cm_df is not None and not cm_df.empty:
            st.markdown("### Matriz de confusión — conteos absolutos")
            fig = px.imshow(
                cm, text_auto=True, color_continuous_scale='Blues',
                aspect='auto', labels=dict(x="Predicho", y="Real", color="Conteo"),
            )
            fig.update_layout(height=420)
            st.plotly_chart(fig, use_container_width=True)
            st.caption("Misma matriz que arriba pero con números crudos en vez de porcentajes.")


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
    # Top features según el modelo seleccionado por el usuario (default RF).
    # Las del RF están en feature_importance_gini_top20; las de XGB las inyecta
    # el ml_api al startup en xgb_feature_importance_gini_top20.
    _model_pre = st.session_state.get("predict_model_choice", "rf")
    _imp_key = "xgb_feature_importance_gini_top20" if _model_pre == "xgb" else "feature_importance_gini_top20"
    _imp_list = m.get(_imp_key) or m.get("feature_importance_gini_top20", [])
    top_features = [x["feature"] for x in _imp_list[:6] if x["feature"] in feat_cols]
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
                # Resetear sliders al valor del nuevo preset. Streamlit
                # NO resetea widgets ya renderizados al sólo popear la key
                # (conserva el estado interno); hay que asignar el valor
                # nuevo explícitamente en session_state antes del rerun.
                for f in top_features:
                    col_min = float(df[f].min())
                    col_max = float(df[f].max())
                    if col_min == col_max:
                        col_max = col_min + 1.0
                    step = (col_max - col_min) / 1000.0
                    val = max(col_min, min(col_max, float(sample[f])))
                    # Cuantizar al mismo step que usará el slider para
                    # evitar el warning de Streamlit "values in conflict".
                    val = round((val - col_min) / step) * step + col_min
                    st.session_state[f"slider_{f}"] = max(col_min, min(col_max, val))
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
        # Step explícito (0.1% del rango). Sin él, Streamlit infiere step=1.0
        # y warnea cuando el value del preset no se alinea con esos steps.
        step = (col_max - col_min) / 1000.0
        current = float(features[feat_idx])
        current = max(col_min, min(col_max, current))
        # Cuantizar current al step más cercano (evita el warning de Streamlit).
        current = round((current - col_min) / step) * step + col_min
        current = max(col_min, min(col_max, current))
        new_val = slider_cols[i % 2].slider(
            fname,
            min_value=col_min, max_value=col_max, value=current,
            step=step,
            key=f"slider_{fname}",
            help=f"Rango en dataset: [{col_min:.2f}, {col_max:.2f}]",
        )
        features[feat_idx] = new_val

    st.subheader("Paso 3 — Clasificar")
    # Selector de modelo (RF default, XGBoost si está disponible)
    health_info = {}
    try:
        health_info = requests.get(f"{API_URL}/health", timeout=3).json()
    except Exception:
        pass
    available = health_info.get("available_models", ["rf"])
    model_choice = st.radio(
        "Modelo",
        options=available,
        format_func=lambda m: {"rf": "Random Forest v2 (tuned)", "xgb": "XGBoost v2 (tuned)"}.get(m, m),
        horizontal=True,
        key="predict_model_choice",
    )

    if st.button(f"Clasificar con el modelo v2 ({model_choice.upper()})", type="primary", use_container_width=True):
        try:
            resp = requests.post(
                f"{API_URL}/predict?model={model_choice}",
                json={"features": features},
                headers=headers, timeout=10,
            ).json()

            # Persistir al mismo JSONL del sensor para que Grafana también
            # cuente las predicciones interactivas en los dashboards SOC.
            _append_interactive_prediction(
                model_choice, resp, st.session_state.get("preset_label")
            )

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

            # Explicación SHAP — qué features contribuyeron más a ESTA decisión
            top_contribs = resp.get("top_contributions", [])
            st.markdown("### ¿Por qué predijo esa categoría? (SHAP)")
            st.caption(
                "Los valores **SHAP** muestran cuánto contribuyó cada feature al score "
                f"de la clase predicha (`{category}`) **respecto al baseline**. "
                "Positivo (rojo) = empuja la predicción hacia esta clase; "
                "negativo (azul) = empuja hacia otra clase. La magnitud absoluta indica fuerza."
            )
            if top_contribs:
                shap_df = pd.DataFrame(top_contribs)
                shap_df["abs_shap"] = shap_df["shap"].abs()
                shap_df["direction"] = shap_df["shap"].apply(
                    lambda v: "↑ a favor de " + category if v > 0 else "↓ en contra"
                )
                # Orden: el más fuerte arriba
                shap_df = shap_df.sort_values("abs_shap", ascending=True)
                fig = px.bar(
                    shap_df,
                    x="shap", y="feature",
                    orientation="h",
                    color="shap",
                    color_continuous_scale=[(0, "blue"), (0.5, "lightgray"), (1, "red")],
                    color_continuous_midpoint=0,
                    hover_data=["value", "direction"],
                )
                fig.update_layout(yaxis={'categoryorder': 'total ascending'},
                                  height=350,
                                  xaxis_title="Contribución SHAP",
                                  yaxis_title="")
                st.plotly_chart(fig, use_container_width=True)
                # Tabla detallada
                display_df = shap_df[["feature", "value", "shap", "direction"]].sort_values(
                    "shap", key=abs, ascending=False
                ).rename(columns={"feature": "Feature",
                                   "value": "Valor (escalado)",
                                   "shap": "SHAP",
                                   "direction": "Efecto"})
                display_df["SHAP"] = display_df["SHAP"].round(4)
                display_df["Valor (escalado)"] = display_df["Valor (escalado)"].round(4)
                st.dataframe(display_df, hide_index=True, use_container_width=True)
            else:
                st.info(
                    "El API no devolvió contribuciones SHAP. "
                    "Verificá que `SHAP_ENABLED=1` en el container ml_api."
                )

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
    # Mostrar la URL que el usuario PUEDE abrir en su browser (HOST_IP:8080),
    # no el hostname interno docker `http://dvwa` que no resuelve fuera del network.
    target_display = f"http://{HOST_IP}:8080" if HOST_IP and HOST_IP != "localhost" else f"{DVWA_URL} (interno docker)"
    st.markdown(
        f"**Baseline actual** — Alertas Suricata: `{base_alerts}` · "
        f"Predicciones ML: `{base_preds}` · Target: [{target_display}]({target_display})"
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
            # Tail con cache (30 s). Antes leía el archivo completo cada
            # render — con eve.json de 100+ MB esto colgaba el tab.
            alerts_all, flows, n_recent_lines, eve_size = load_eve_recent()
            alerts = [a for a in alerts_all if is_real_alert(a)]
            n_noise = len(alerts_all) - len(alerts)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Alertas reales", f"{len(alerts):,}",
                      help=f"Excluye {n_noise:,} eventos del decoder (parser warnings) que NO son ataques.")
            c2.metric("Decoder noise", f"{n_noise:,}",
                      help="Warnings tipo 'SURICATA HTTP unable to match...' — útiles para troubleshoot, no para SOC.")
            c3.metric("Flows (Suricata)", f"{len(flows):,}")
            c4.metric("eve.json size", f"{eve_size/1024/1024:.1f} MB",
                      help=f"Tail leído: ~5 MB recientes ({n_recent_lines:,} líneas).")

            if alerts:
                sigs = collections.Counter(a.get("alert", {}).get("signature", "?") for a in alerts)
                sig_df = pd.DataFrame(sigs.most_common(15), columns=["Firma", "Conteo"])
                fig = px.bar(sig_df, x="Conteo", y="Firma", orientation="h",
                             color="Conteo", color_continuous_scale="Reds",
                             title="Top 15 firmas Suricata (filtrado: solo firmas ET Open reales)")
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
                ml_preds_all = load_sensor_predictions(limit=2000)
                # Excluir predicciones interactivas del tab Predicción
                # (source='dashboard', src_ip='interactive'); nunca pueden
                # matchear contra alertas Suricata reales y inflaban `ml_only`.
                ml_preds = [p for p in ml_preds_all if p.get("source") != "dashboard"]
                n_dashboard_excluded = len(ml_preds_all) - len(ml_preds)
                if n_dashboard_excluded > 0:
                    st.caption(
                        f"ℹ️ Excluyendo {n_dashboard_excluded} predicciones interactivas "
                        "del tab Predicción (`source=dashboard`) — su 5-tupla es sintética "
                        "y no puede emparejarse con tráfico real."
                    )
                if not ml_preds:
                    st.info(
                        "Sin predicciones ML del sensor aún. Ve al tab **Ataques** y "
                        "lanza un ataque vía sensor para poblar `sensor_predictions.jsonl`."
                    )
                else:
                    corr = correlate_5tuple(ml_preds, alerts)
                    vc = collections.Counter(r['Veredicto'] for r in corr)

                    # Separar las filas "originadas desde ML" de las
                    # "Suricata solo sin ML matching" (que `correlate_5tuple`
                    # apendiza al final con ML categoría = '—').
                    rows_from_ml = [r for r in corr if r.get('ML categoría') != '—']
                    rows_suri_unmatched = [r for r in corr if r.get('ML categoría') == '—']
                    n_ml = len(rows_from_ml)
                    n_suri_only_extra = len(rows_suri_unmatched)
                    ml_agree = sum(1 for r in rows_from_ml
                                   if r['Veredicto'] in ('both_detected', 'both_clean'))
                    agree = (ml_agree / n_ml) if n_ml else 0

                    k1, k2, k3, k4, k5 = st.columns(5)
                    k1.metric("Flujos ML analizados", n_ml,
                              help="Predicciones del sensor en el JSONL, sin contar las interactivas del dashboard.")
                    k2.metric("Ambos detectaron", vc.get('both_detected', 0))
                    k3.metric("Solo ML (zero-day?)", vc.get('ml_only', 0))
                    k4.metric("Alertas Suricata sin flow ML", n_suri_only_extra,
                              help="Suricata alertó pero el sensor ML no procesó ese flow (típico: HTTP attacks sin captura sensor).")
                    k5.metric("Acuerdo (sobre ML)", f"{agree:.0%}",
                              help="(both_detected + both_clean) / flujos ML analizados.")

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
                        'n_ml_flows': n_ml,
                        'n_suricata_alerts': len(alerts),
                        'verdicts': dict(vc),
                        'agreement_rate': round(agree, 4),
                    })
            else:
                st.info(
                    "Aún no hay alertas Suricata reales (solo decoder noise filtrado). "
                    "Ve al tab **Ataques** y lanza payloads HTTP para generar alertas."
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

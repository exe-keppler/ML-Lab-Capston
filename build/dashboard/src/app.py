"""Dashboard IDS-ML v2 — Suricata + ML con comparador y ART."""
import os
import json
import time
import collections
from datetime import datetime, timezone
import requests
import streamlit as st
import pandas as pd
import plotly.express as px

API_URL = os.environ.get("ML_API_URL", "http://ml_api:8000")
API_KEY = os.environ.get("IDS_API_KEY", "")
LOGS_DIR = os.environ.get("LOGS_DIR", "/app/logs")
SENSOR_PREDICTIONS_PATH = os.path.join(LOGS_DIR, "sensor_predictions.jsonl")
LAB_HISTORY_PATH = os.path.join(LOGS_DIR, "lab_history.jsonl")
EVE_JSON_PATH = os.path.join(LOGS_DIR, "eve.json")
HISTORY_MAX_ENTRIES = 500

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
    """Lee las últimas N predicciones del sensor (JSONL)."""
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
    """Join bidireccional ML↔Suricata por 5-tupla (src/dst/port/proto)."""
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
                'Suricata signature': top.get('alert', {}).get('signature', top.get('signature', ''))[:55],
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
    # Alertas Suricata sin match (flujos que el sensor no vio)
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

st.set_page_config(page_title="IDS-ML Lab UDLA", layout="wide")
st.title("IDS-ML Educational Lab — Dashboard v2")
st.caption("Arquitectura v2: Random Forest v3 + Suricata ET-Open + ART adversarial | UDLA Capstone 2026")

headers = {"X-API-Key": API_KEY} if API_KEY else {}

# ── Health ────────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)
try:
    health = requests.get(f"{API_URL}/health", timeout=5).json()
    col1.metric("ML API", health["status"], f"modelo {health.get('model','?')}")
    col2.metric("Features", health["n_features"])
    col3.metric("Integridad", health.get("integrity", "?"))
except Exception as e:
    st.error(f"ML API no accesible: {e}")
    st.stop()

# ── Tabs ──────────────────────────────────────────────────────
tab_pred, tab_comp, tab_adv, tab_metrics = st.tabs(
    ["🔮 Predicción", "⚖️ Suricata vs ML", "🎯 Adversarial (ART)", "📊 Métricas"])

# ═══════════════════════════════════════════════════════════════
# TAB 1: Predicción individual
# ═══════════════════════════════════════════════════════════════
with tab_pred:
    st.subheader("Predicción individual")
    n_feat = health["n_features"]
    features_input = st.text_area(
        f"Features ({n_feat} valores separados por coma)",
        value=",".join(["0.0"] * n_feat), height=100)
    if st.button("Clasificar"):
        try:
            feats = [float(x.strip()) for x in features_input.split(",")]
            resp = requests.post(f"{API_URL}/predict",
                                 json={"features": feats},
                                 headers=headers, timeout=10).json()
            if resp.get("is_attack"):
                st.error(f"⚠️ ATAQUE detectado: **{resp['category']}** "
                         f"(confianza: {resp['category_confidence']:.2%})")
            else:
                st.success(f"✅ Tráfico **benigno** "
                           f"(prob ataque: {resp['attack_confidence']:.2%})")
            c1, c2 = st.columns(2)
            c1.json(resp.get("mitre", {}))
            c2.json({k: v for k, v in resp.items() if k != "mitre"})
        except Exception as e:
            st.error(str(e))

# ═══════════════════════════════════════════════════════════════
# TAB 2: Suricata vs ML (core del valor pedagógico v2)
# ═══════════════════════════════════════════════════════════════
with tab_comp:
    st.subheader("Comparativa Rule-based (Suricata ET-Open) vs ML (RF v3)")
    st.markdown("""
Esta vista muestra la **complementariedad** entre detección por firmas y ML:

- **Suricata** detecta ataques conocidos por patrones específicos (ET-Open ~50k reglas).
- **ML** detecta comportamientos anómalos aprendidos del dataset CICIDS2017.

Cada enfoque tiene **falsos positivos** y **falsos negativos** distintos; un SOC moderno los combina.
""")

    eve_path = os.path.join(LOGS_DIR, "eve.json")
    if os.path.exists(eve_path):
        try:
            lines = open(eve_path).readlines()
            alerts = [json.loads(l) for l in lines if '"event_type":"alert"' in l]
            flows = [json.loads(l) for l in lines if '"event_type":"flow"' in l]

            c1, c2, c3 = st.columns(3)
            c1.metric("Alertas Suricata", f"{len(alerts):,}")
            c2.metric("Flows observados", f"{len(flows):,}")
            c3.metric("Eventos totales", f"{len(lines):,}")

            if alerts:
                # Distribución de firmas
                sigs = collections.Counter(
                    a.get("alert", {}).get("signature", "?") for a in alerts)
                sig_df = pd.DataFrame(
                    sigs.most_common(15), columns=["Firma", "Conteo"])
                fig = px.bar(sig_df, x="Conteo", y="Firma", orientation="h",
                             title="Top 15 firmas Suricata disparadas",
                             color="Conteo", color_continuous_scale="Reds")
                fig.update_layout(height=500, yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig, use_container_width=True)

                # Severidad
                sev_counts = collections.Counter(
                    a.get("alert", {}).get("severity", 0) for a in alerts)
                sev_df = pd.DataFrame(
                    [{"Severidad": k, "Conteo": v} for k, v in sorted(sev_counts.items())])
                c1, c2 = st.columns(2)
                c1.subheader("Severidad (1=high, 3=low)")
                c1.dataframe(sev_df, use_container_width=True, hide_index=True)

                # Últimas 20
                c2.subheader("Últimas 20 alertas")
                last = []
                for a in alerts[-20:]:
                    last.append({
                        "ts": a.get("timestamp", "")[:19],
                        "sig": a.get("alert", {}).get("signature", "")[:60],
                        "sev": a.get("alert", {}).get("severity", ""),
                        "src": a.get("src_ip", "") + ":" + str(a.get("src_port", "")),
                        "dst": a.get("dest_ip", "") + ":" + str(a.get("dest_port", "")),
                    })
                c2.dataframe(pd.DataFrame(last), use_container_width=True, hide_index=True, height=400)

                # ─── Correlación real por 5-tupla (ML JSONL ↔ Suricata) ───
                st.subheader("Correlación ML↔Suricata por flujo (5-tupla)")
                ml_preds = load_sensor_predictions(limit=2000)
                if not ml_preds:
                    st.info(
                        "Sin predicciones del sensor aún. Lanza una captura con el "
                        "sensor (`POST http://<host>:9999/capture/start`) para "
                        "poblar `sensor_predictions.jsonl` y ver la correlación.")
                else:
                    corr = correlate_5tuple(ml_preds, alerts)
                    vc = collections.Counter(r['Veredicto'] for r in corr)
                    total = len(corr)
                    agree = ((vc.get('both_detected', 0) + vc.get('both_clean', 0))
                             / total if total else 0)
                    k1, k2, k3, k4, k5 = st.columns(5)
                    k1.metric("Flujos", total)
                    k2.metric("Ambos detectaron", vc.get('both_detected', 0))
                    k3.metric("Solo ML", vc.get('ml_only', 0))
                    k4.metric("Solo Suricata", vc.get('suricata_only', 0))
                    k5.metric("Acuerdo", f"{agree:.0%}")

                    verdict_badge = {
                        'both_detected': '🔴 Ambos',
                        'ml_only': '🟡 Solo ML',
                        'suricata_only': '🟠 Solo Suricata',
                        'both_clean': '🟢 Limpio',
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
                                f"⚠️ Discrepancias ML vs Suricata ({len(discrepancias)})",
                                expanded=False):
                            st.caption(
                                "Flujos donde un sistema alerta y el otro no — "
                                "casos candidatos a evasión adversarial o firmas "
                                "faltantes.")
                            st.dataframe(pd.DataFrame(discrepancias[:50]),
                                         use_container_width=True, hide_index=True)

                    # Persistir snapshot al historial
                    now_iso = datetime.now(timezone.utc).isoformat()
                    save_history_entry({
                        'timestamp': now_iso,
                        'n_ml_flows': len(ml_preds),
                        'n_suricata_alerts': len(alerts),
                        'verdicts': dict(vc),
                        'agreement_rate': round(agree, 4),
                    })
            else:
                st.info("Aún no hay alertas. Genera tráfico: ataque a 172.25.0.50 desde un container.")
        except Exception as e:
            st.warning(f"Error leyendo eve.json: {e}")
    else:
        st.info(f"`eve.json` no encontrado en {LOGS_DIR}.")

    # ─── Historial de snapshots de correlación ───
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
                st.download_button("Descargar histórico (JSONL)", data=fh.read(),
                                   file_name='lab_history.jsonl',
                                   mime='application/x-ndjson')
        except Exception:
            pass
        st.caption(f"Rotación automática a {HISTORY_MAX_ENTRIES} entradas.")

# ═══════════════════════════════════════════════════════════════
# TAB 3: Adversarial (ART)
# ═══════════════════════════════════════════════════════════════
with tab_adv:
    st.subheader("Robustez adversarial — IBM ART")
    st.markdown("""
Los modelos ML son vulnerables a **perturbaciones adversariales**: pequeños cambios en features
que hacen que el modelo cambie su predicción. En un IDS, un atacante podría modificar timing o
padding de paquetes para evadir detección.

Este panel muestra resultados del notebook `models/01_adversarial_evasion.ipynb` que usa **HopSkipJump**
(ataque black-box basado en decision boundary) contra el modelo v3.
""")

    art_path = os.path.join(LOGS_DIR, "art_evasion_results.json")
    if os.path.exists(art_path):
        try:
            res = json.loads(open(art_path).read())
            c1, c2, c3 = st.columns(3)
            c1.metric("Muestras atacadas", res.get("n_samples_attacked", "?"))
            c2.metric("Tasa de evasión", f"{res.get('evasion_rate', 0):.1%}",
                      delta=f"{res.get('n_evaded', 0)} evadidas", delta_color="inverse")
            c3.metric("Perturbación L2 media", f"{res.get('mean_L2_perturbation', 0):.3f}")

            st.caption(f"Ataque: **{res.get('attack', '?')}** sobre modelo **{res.get('model', '?')}**")

            if res.get("top_perturbed_features"):
                tpf = pd.DataFrame(res["top_perturbed_features"])
                fig = px.bar(tpf, x="mean_abs_delta", y="feature", orientation="h",
                             title="Top 5 features perturbadas por el atacante")
                fig.update_layout(yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig, use_container_width=True)

            st.json(res)
        except Exception as e:
            st.warning(f"Error leyendo resultados ART: {e}")
    else:
        st.info("""
Resultados ART no disponibles. Ejecutar el notebook:

```
docker exec -w /home/app/models ids-jupyter \\
  jupyter nbconvert --to notebook --execute 01_adversarial_evasion.ipynb \\
  --output 01_adversarial_evasion_executed.ipynb
```

O abrir interactivamente en http://192.168.122.10/lab/?token=lab-ids-ml-udla-2026
""")

# ═══════════════════════════════════════════════════════════════
# TAB 4: Métricas del modelo
# ═══════════════════════════════════════════════════════════════
with tab_metrics:
    st.subheader("Métricas del modelo v3")
    try:
        m = requests.get(f"{API_URL}/metrics", headers=headers, timeout=5).json()

        bin_t = m.get("binary", {}).get("test", {})
        mc_t = m.get("multiclass", {}).get("test", {})

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("F1-w binario (test)", f"{bin_t.get('f1_weighted', 0):.4f}")
        c2.metric("F1-macro binario", f"{bin_t.get('f1_macro', 0):.4f}")
        c3.metric("F1-w multiclase", f"{mc_t.get('f1_weighted', 0):.4f}")
        c4.metric("F1-macro multiclase", f"{mc_t.get('f1_macro', 0):.4f}")

        st.caption(f"Pipeline: {m.get('pipeline', '?')} | Features: {m.get('n_features', '?')} | "
                   f"Train: {m.get('n_train', '?'):,} | Val: {m.get('n_val', '?'):,} | Test: {m.get('n_test', '?'):,}")

        # Classification report multiclase
        cr = mc_t if False else m.get("multiclass", {}).get("classification_report", {})
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
            st.subheader("Por clase (multiclase, test)")
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

        # Baselines
        bl = m.get("baselines_on_v3_split", {})
        if bl:
            st.subheader("Baselines sobre split v3 — validación")
            b_df = pd.DataFrame([
                {"Modelo": "Dummy (majority)", "F1-w binario": round(bl.get("dummy_majority_f1_weighted", 0), 4)},
                {"Modelo": f"Stump (1 split en '{bl.get('stump_feature', '?')}')", "F1-w binario": round(bl.get("stump_depth1_f1_weighted", 0), 4)},
                {"Modelo": "Árbol depth=3", "F1-w binario": round(bl.get("tree_depth3_f1_weighted", 0), 4)},
                {"Modelo": "RF v3 (150 árboles)", "F1-w binario": round(bin_t.get("f1_weighted", 0), 4)},
            ])
            st.dataframe(b_df, hide_index=True, use_container_width=True)

        # Feature importance top 10
        fi = m.get("feature_importance_gini_top20", [])
        if fi:
            fi_df = pd.DataFrame(fi[:10])
            fig = px.bar(fi_df, x="importance", y="feature", orientation="h",
                         title="Top 10 features por Gini importance")
            fig.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig, use_container_width=True)

    except Exception as e:
        st.warning(str(e))

st.markdown("---")
st.caption("Maestría en IA Aplicada — UDLA 2026 | [Plan maestro](obj5_validacion/mejoras_criticas/README.md)")

---
marp: true
theme: default
paginate: true
header: 'Laboratorio IDS-ML | UDLA 2026'
footer: 'github.com/exe-keppler/ML-Lab-Capston'
size: 16:9
style: |
  section { font-size: 24px; }
  h1 { color: #1e3a8a; font-size: 42px; }
  h2 { color: #1e40af; font-size: 32px; }
  code { background: #f3f4f6; padding: 2px 6px; border-radius: 3px; }
  pre { font-size: 16px; }
  table { font-size: 18px; }
  .highlight { background: #fef3c7; padding: 2px 4px; }
---

<!-- _class: lead -->
<!-- _paginate: false -->

# Laboratorio IDS-ML
## Detección de intrusiones con Machine Learning + Reglas

**Maestría en IA Aplicada · UDLA 2026**

---

## ¿Qué problema resolvemos?

Una red empresarial promedio genera **millones de flujos por día**. Un analista SOC no puede revisar todo manualmente.

```
Tráfico → Detector → ¿Alarma? → SOC Analyst
              ↑
         "Es ataque" / "Es benigno"
```

**Dos enfoques tradicionales**:
- **Reglas** (Suricata, Snort): firmas conocidas. Bajo FP, no detecta novedades.
- **ML**: aprende patrones. Detecta variantes, pero falsos positivos y *adversarial*.

→ **El lab combina ambos** para responder: ¿son redundantes o complementarios?

---

## Stack del laboratorio

```
                       ┌─────────────┐
   tráfico             │  Suricata   │ ─── eve.json ──┐
   (DVWA target)  ────►│  ET-Open    │                │
                       │   ~50k      │                ▼
                       └─────────────┘            ┌──────┐
                                                  │ Loki │
                       ┌─────────────┐            └──┬───┘
                       │   Sensor    │               │
                       │ (CICFlow)   │ ──┐           ▼
                       └──────┬──────┘   │     ┌──────────┐
                              │          │     │ Grafana  │
                              ▼          │     │ 5 dashbds│
                       ┌─────────────┐   │     └──────────┘
                       │  ML API     │   │
                       │ RF + XGB v2 │ ◄─┘
                       │ + SHAP      │
                       └──────┬──────┘
                              │
                              ▼
                       sensor_predictions.jsonl
                       (model: rf | xgb)
```

11 contenedores Docker. Deploy: `git clone` + `./setup.sh` = **47 segundos**.

---

## ¿Por qué ML para detección de intrusiones?

**Reglas (Suricata)**:
- ✓ Determinísticas, baja tasa de FP en firmas conocidas.
- ✗ No detecta lo que no está en su base.
- ✗ Mantenimiento manual de reglas.

**ML (RF / XGBoost)**:
- ✓ Aprende patrones generales, detecta variantes.
- ✓ Escala con más datos.
- ✗ Falsos positivos en tráfico legítimo atípico.
- ✗ **Vulnerable a evasión adversarial** (lo veremos al final).

**Hipótesis del lab**: son **complementarios**, no sustitutos.

---

# Sección 2 — Dataset y pipeline ML

---

## CICIDS2017

Dataset estándar de la University of New Brunswick (UNB).

- **5 días** de tráfico capturado en una red empresarial simulada.
- **2.3M flujos** etiquetados.
- **15 categorías** originales de ataque, agrupadas a **6** en este lab:
  - `Benign` (85%) — tráfico legítimo
  - `DoS` — Hulk, GoldenEye, Slowloris, Slowhttptest, Heartbleed
  - `DDoS` — flood TCP/UDP volumétrico
  - `Brute Force` — FTP-Patator, SSH-Patator
  - `Reconnaissance` — Port Scan, Bot, Infiltration
  - `Web Attack` — XSS, SQLi, Brute Force web
- **78 features** crudas extraídas con CICFlowMeter (estadísticas de paquete + IAT + flags TCP).

---

## Notebook 01 — EDA

Lo que el dataset esconde antes de tocar nada:

| Hallazgo | Implicación |
|---|---|
| **Desbalance extremo**: Benign 85%, Heartbleed 11 muestras | F1-macro va a sufrir en clases minoritarias |
| **Web Attack tiene encoding roto** (`–` corrupto a `�`) | Necesita normalización |
| **8 columnas constantes** (Bwd PSH/URG flags, etc.) | Drop seguro, no aportan |
| **Inf en features de tasa** (`Flow Bytes/s`) | Cuando `Flow Duration = 0`. Reemplazar con 0. |

→ Sin EDA, esto sale a la luz cuando el modelo ya está entrenado y falla.

---

## Notebook 03 — Feature audit (lo más denso)

De **77 features → 47 features** finales. **30 drops** justificados:

| Razón | Cantidad | Ejemplos |
|---|---|---|
| **Constantes** (varianza 0) | 8 | `Bwd_PSH_Flags`, `CWE_Flag_Count` |
| **Leakage** (delata el label) | 6 | `Init_Bwd_Win_Bytes` = -1 si no hay backward → 100% PortScan |
| **Redundancia matemática** | 7 | `Avg_Packet_Size` ≡ `Packet_Length_Mean` |
| **VIF iterativo > 50** | 9 | `Total_Fwd_Packets`, `Idle_Mean` (multicolinealidad extrema) |

### Lección clave
`Init_Bwd_Win_Bytes = -1` clasifica PortScan con 99% precisión. Pero el modelo aprende **el sentinel**, no el patrón. **Eso es leakage** y arruina el modelo en datos reales.

---

## Notebooks 04 y 05 — Baselines y tuning

**Baselines** (notebook 04):

| Modelo | F1-macro (val full) |
|---|---|
| LogReg | 0.49 (no linealmente separable) |
| KNN | n/a (no escala) |
| **RF default** | **0.64** |

**Tuning** (notebook 05) — 16+16 configs:

| Modelo | F1-macro |
|---|---|
| **RF tuned** ← **winner** | **0.670** |
| XGBoost tuned | 0.645 |
| RF default | 0.635 |
| XGBoost default | 0.632 |

**Hallazgo**: boosting **no siempre domina** al bagging. Depende del dataset.

---

## Notebook 06 — Modelo final v2

Train sobre `train + val` combinados (60K balanceados), eval en **test no visto** (350K).

```
RF v2 binary:        F1-macro 0.9875  (¿es ataque sí/no?)
RF v2 multiclass:    F1-macro 0.6630  (¿qué tipo de ataque?)
XGBoost v2 binary:   F1-macro 0.9814
XGBoost v2 multi:    F1-macro 0.6508
```

**El gap entre binary (0.99) y multi (0.66)** es real:
- Saber "esto es ataque" es fácil.
- Saber **qué tipo** es difícil porque las clases minoritarias (Web Attack: 322 en test, Reconnaissance: 516) tienen muchos falsos positivos por la proporción extrema 296K Benign vs 322 minorías.

---

## Notebook 07 — Adversarial (HopSkipJump)

**Pregunta**: ¿qué tan robusto es el modelo a un atacante adaptativo?

Black-box L2-norm minimization, 25 muestras de cada clase de ataque:

| Modelo | Evasión total | Evasión a Benign | L2 mediano |
|---|---|---|---|
| **RF v2** | **100%** | 87.5% | 2.63 |
| **XGBoost v2** | **100%** | 76.0% | 2.67 |

→ Ambos modelos completamente evadibles con perturbaciones mínimas.

### Implicancia
F1-macro 0.99 (binary) **NO ES** "modelo seguro". Un atacante adaptativo viola los dos. Por eso **Suricata sigue importando** — sus firmas no se evaden con perturbaciones de features.

---

## Notebook 08 — Inference validation

Cierre del ciclo: **¿lo que entrenó el notebook = lo que sirve la API?**

```
30/30 categorías matchean
30/30 probabilidades matchean (tolerancia 1e-3)
30/30 binary matchean
✓ MATCH SHA-256: notebook y API leen el mismo modelo
```

→ **Cero training/serving skew**. El modelo desplegado es bit-exact con el del notebook.

---

# Sección 3 — Stack en producción

---

## ML API hardened

```python
@app.post("/predict", dependencies=[Depends(require_api_key)])
@limiter.limit("120/minute")
def predict(flow: FlowInput, model: str = "rf", explain: bool = True):
    bin_clf, mc_clf, explainer = _resolve_models(model)
    X_s = scaler.transform(np.array(flow.features).reshape(1, -1))
    ...
```

| Mecanismo | Cómo |
|---|---|
| **Auth** | `X-API-Key` header obligatorio |
| **Rate limit** | 120 req/min por IP via `slowapi` |
| **Integridad modelo** | SHA-256 verificado antes de carga (anti pickle RCE) |
| **Dual-model** | `?model=rf\|xgb` (default rf), reportado en `/health.available_models` |
| **Validación** | Rechaza NaN/Inf, batches > 500 |
| **Request ID** | `X-Request-ID` middleware para correlación |

---

## SHAP — explicabilidad per-flujo

`/predict?explain=true` devuelve **por qué** clasificó así:

```json
{
  "category": "Reconnaissance",
  "category_confidence": 0.997,
  "top_contributions": [
    {"feature": "Fwd_IAT_Std",        "shap":  1.99, "value": -0.58},
    {"feature": "PSH_Flag_Count",     "shap": -1.08, "value": -0.91},
    {"feature": "Total_Fwd_Packets",  "shap":  1.02, "value": -0.03},
    {"feature": "Flow_IAT_Min",       "shap":  0.74, "value": -0.12},
    {"feature": "Bwd_Packets_per_s",  "shap":  0.61, "value": -0.43}
  ]
}
```

→ El SOC analyst ve que la decisión vino del **patrón de IAT forward** + ausencia de PSH flags.

**Trade-off**: ~50ms extra por predicción. Sensor batch lo desactiva (`?explain=false`).

---

## Sensor — CICFlowMeter en vivo

Captura tráfico real con scapy + extrae las **mismas 47 features** del modelo:

```bash
curl -X POST http://localhost:9999/capture/start \
  -H 'Content-Type: application/json' \
  -d '{"duration":15,"attack_type":"scan","intensity":80,"inject_dataset":true}'
```

Por cada captura:
1. Genera tráfico contra DVWA con scapy (TCP scan, flood, brute force, etc).
2. Captura paquetes con CICFlowMeter Python.
3. Inyecta también flujos reales de CICIDS2017 (`inject_dataset=true`) para que las predicciones sean clasificables (sin esto cae a Benign por *feature drift* scapy↔CICFlowMeter).
4. Llama `/predict/batch` para **rf y xgb** en paralelo.
5. Persiste predicciones en `sensor_predictions.jsonl` con tag `model`.

---

## Grafana — 3 dashboards SOC enterprise

Cada dashboard responde a un detector específico. Loki indexa `model` como label.

| Dashboard | Filtro Loki | Audiencia |
|---|---|---|
| **SOC Suricata** | `{job="suricata"} \|= "alert"` | Analista que confía en firmas |
| **SOC RF v2** | `{job="ml_predictions", model="rf"}` | Analista que confía en bagging |
| **SOC XGBoost v2** | `{job="ml_predictions", model="xgb"}` | Analista que confía en boosting |

Panels en cada uno: tasa por minuto, distribución de categorías, top src_ip flagged, top dst_port, severidad, stream en vivo.

→ El SOC puede comparar: ¿RF y XGBoost coinciden? ¿Suricata atrapa lo que ML perdió?

---

## Streamlit — dashboard pedagógico

6 tabs en orden didáctico:

| # | Tab | Para qué |
|---|---|---|
| 1 | Intro | ¿Qué hay aquí? Glosario, links, recorrido |
| 2 | Dataset | Pie chart 6 clases, histograma feature, top correlaciones |
| 3 | Métricas | Matriz de confusión **en vivo** + comparativa RF vs XGBoost |
| 4 | Predicción | Selector RF/XGB, sliders top-6 features, **SHAP signed** + MITRE |
| 5 | Ataques | Botones para lanzar capturas y payloads HTTP contra DVWA |
| 6 | Suricata vs ML | Correlación 5-tupla, 4 veredictos: `both_detected`, `ml_only`, `suricata_only`, `both_clean` |

---

## Reproducibilidad — git clone + setup.sh = 47s

```bash
git clone https://github.com/exe-keppler/ML-Lab-Capston.git
cd ML-Lab-Capston
./setup.sh
```

**Smoke test reciente** (medido en una VM con imágenes cacheadas):

```
═══════════ Resumen final ═══════════
Containers corriendo: 11
Setup duración: 47s
Fresh deploy desde GitHub al smoke OK: SI
```

11 contenedores up, ML API healthy con `model:v2` + `available_models:[rf, xgb]` + `integrity:verified`, Streamlit/Grafana/Jupyter/DVWA respondiendo, captura test productiva.

---

# Sección 4 — Limitaciones honestas

---

## El elefante en la habitación

**F1-macro 0.99 binary ≠ modelo seguro**

| Detector | Clean F1 | Bajo HopSkipJump |
|---|---|---|
| RF v2 multiclass | 0.66 | **100% evadible** |
| XGBoost v2 multi | 0.65 | **100% evadible** |
| Suricata (firmas) | n/a | Resiste perturbaciones de features |

**Por qué Suricata resiste**: el atacante puede mover los valores de `Flow_Duration` lo que quiera, pero el payload sigue siendo `' OR 1=1 --` → la regla de SQLi dispara.

**Por qué ML cae**: HopSkipJump encuentra las grietas en el espacio de features. F1-macro 0.99 es el promedio sobre datos limpios; el atacante no juega al promedio.

---

## Caveat metodológico del adversarial

**HopSkipJump perturba en el espacio de features** (los 47 floats).

En la realidad, un atacante no puede *elegir* el `Bwd_Packet_Length_Mean` arbitrariamente — eso lo calcula CICFlowMeter del tráfico real.

**Para un ataque "verdadero"**: hay que modificar el **tráfico generador** (paquetes, timing, payload) y *después* ver qué features producen.
- Eso es **problem-space attack**, no feature-space.
- Mucho más caro de implementar.
- Fuera del alcance de este lab.

→ El resultado adversarial muestra **fragilidad teórica**, no exploit operacional.

---

## Por eso ML + reglas en paralelo

**El SOC enterprise NO debería depender de un solo detector.**

| Caso | Suricata | ML | Veredicto recomendado |
|---|---|---|---|
| `nmap -sS` evidente | ✓ ET SCAN dispara | ✓ Reconnaissance | **Alta confianza** |
| `sqlmap` | ✓ ET WEB SQL | ✓ Web Attack | **Alta confianza** |
| Variante Brute Force novedosa | ✗ no en firmas | ✓ Brute Force | **ML cumple su función** |
| Adversarial modificado | ✓ payload sigue raro | ✗ evade ML | **Reglas cumplen su función** |
| Tráfico legítimo atípico | ✓ no firma → benigno | ✗ FP | **Suricata corrige al ML** |

→ Esa es la conversación SOC enterprise que el lab ilustra en vivo.

---

# Sección 5 — Para futuros estudiantes

---

## Cómo extender el lab

Los **8 notebooks** son la línea base. Cualquier extensión arranca clonando + ejecutando uno desde el principio.

**Ideas concretas** (no implementadas, listas para alguien que tome la posta):

| Idea | Donde toca | Costo |
|---|---|---|
| **SMOTE** sobre minorías antes del fit | nb05 + nb06 | bajo |
| **Stacking** RF + XGBoost (ensemble vote) | nb05 + ml_api | medio |
| **Modelo no supervisado** (Isolation Forest) | nb05 + ml_api `/anomaly` | medio |
| **Problem-space adversarial** (modificar paquetes con scapy) | nb07 | alto |
| **Calibración** de threshold per-clase | ml_api | bajo |
| **GNN** sobre flow graphs | nb09 nuevo | alto |

---

## Demo en vivo

Ahora vamos a:

1. Levantar el lab con `./setup.sh`
2. Abrir Streamlit y mostrar las 6 tabs
3. Lanzar una captura desde la tab Ataques
4. Ver la predicción + SHAP en la tab Predicción
5. Cambiar a XGBoost y comparar
6. Abrir Grafana SOC y ver las alertas en tiempo real

---

<!-- _class: lead -->

# Q&A

**Repo**: github.com/exe-keppler/ML-Lab-Capston

**Stack**: 11 contenedores · 8 notebooks ejecutables · 5 dashboards · `setup.sh` 47s

```bash
git clone https://github.com/exe-keppler/ML-Lab-Capston.git
cd ML-Lab-Capston && ./setup.sh
```

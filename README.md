# Laboratorio IDS-ML + Cybersecurity

Sistema de Detección de Intrusiones basado en Machine Learning con correlación rule-based (Suricata) y evaluación adversarial (IBM ART). Despliegue educativo — Maestría en IA Aplicada, UDLA 2026.

## Stack

| Componente | Rol |
|---|---|
| **FastAPI + RF v2 + XGBoost v2** | ML API dual-model con 47 features CICIDS2017 auditadas. SHAP per-flujo para explicabilidad. |
| **Streamlit** | Dashboard pedagógico de 6 tabs con correlación ML ↔ Suricata por 5-tupla |
| **Suricata + ET-Open (~50k reglas)** | IDS rule-based (host mode, captura sobre bridge docker) |
| **Sensor (CICFlowMeter)** | Captura tráfico, llama RF y XGBoost en paralelo, persiste con tag por modelo |
| **JupyterLab + IBM ART** | 8 notebooks reproducibles (EDA → adversarial → inference validation) |
| **DVWA + MariaDB** | Target vulnerable para ejercicios |
| **Nginx** | Reverse proxy con BasicAuth + rate limit |
| **Loki + Promtail** | Agregación de logs (`eve.json`, `sensor_predictions.jsonl`) |
| **Grafana** | 5 dashboards (2 overview + 3 SOC enterprise: Suricata / RF v2 / XGBoost v2) |

## Requisitos

- Linux (testeado en Fedora 43, Ubuntu 22.04 / 24.04)
- Docker ≥ 24 + plugin `docker compose` v2
- 6 GB RAM libre, 12 GB disco (incluye Loki/Grafana)
- Puertos 80, 3000, 8000, 8080, 8888, 9999 libres
- `openssl` (suele venir en todas las distros)

## Despliegue en un solo comando

```bash
git clone https://github.com/exe-keppler/ML-Lab-Capston.git
cd ML-Lab-Capston
./setup.sh
```

> **Smoke test verificado**: en VM con imágenes cacheadas, `setup.sh` levanta los 11 contenedores funcionales en **47 segundos** (sin intervención manual).

El script:

1. Verifica dependencias (Docker, compose, openssl).
2. Crea `.env` desde `.env.example` si no existe.
3. Genera `configs/nginx/htpasswd` con las credenciales de `.env`.
4. Crea la red docker `ids_network` (subnet 172.25.0.0/24, IPs estáticas para los servicios proxy-eados).
5. Detecta el bridge ID y exporta `SURICATA_INTERFACE` al runtime.
6. Construye las 4 imágenes custom (ml_api, dashboard, sensor, jupyter).
7. Levanta los 11 contenedores y espera healthchecks.
8. Imprime las URLs de acceso.

### Dataset CICIDS2017

El parquet `datasets/cicids_test.parquet` (1.3 MB) ya viene en el repo
— alimenta la tab "Dataset" del dashboard y la inyección de flujos del
sensor. Cobertura 47/47 features, balanceado a 2000 muestras × 6 clases
(Benign, DDoS, DoS, Brute Force, Reconnaissance, Web Attack).

Para los notebooks 01–06 que entrenan desde el principio se necesitan
los parquets raw de CICIDS2017 en `datasets/raw/` (~260 MB,
gitignored). Los notebooks leen `RAW_DIR` del entorno; default
`../datasets/raw/`. Ver instrucciones de descarga en cada notebook.

## Acceso por defecto

> ⚠️ **Cambia las credenciales en producción.** Editá `.env` antes de correr `setup.sh`.

| Servicio | URL | Credenciales |
|---|---|---|
| Dashboard | `http://<host>/` | `lab` / `ids2026` (BasicAuth) |
| Grafana | `http://<host>:3000/` | `admin` / `ids2026` |
| DVWA (target) | `http://<host>:8080/` | `admin` / `password` |
| JupyterLab | `http://<host>:8888/lab?token=<TOKEN>` | token en `.env` |
| ML API | `http://<host>:8000/health` | `X-API-Key` en `.env` |
| Sensor | `http://<host>:9999/health` | sin auth |

## Características clave

### Modelo v2 (activo) — auditado y reproducible

- **F1-macro multiclase 0.675** y **F1-macro binary 0.990** sobre test (350K flujos no vistos), 6 clases (Benign, DDoS, DoS, Brute Force, Reconnaissance, Web Attack). Métricas reales del notebook 06 entrenando sobre 60K muestras balanceadas (10K/clase) de train+val.
- **47 features** tras auditoría: 30 columnas dropeadas en total — 8 constantes (`02_cleaning_preprocessing`) + 6 leakage + 7 redundancia matemática + 9 VIF iterativo (`03_feature_audit`).
- Split **estratificado por (día, etiqueta)** 70/15/15 con seed 42, persistido para reuso entre notebooks (`04_baselines.ipynb` produce `cicids_split.parquet`).
- **Hyperparámetros tuneados** (notebook 05): RF `n_estimators=200, min_samples_leaf=5, class_weight=balanced_subsample`. XGBoost `learning_rate=0.1, max_depth=6, n_estimators=500, subsample=0.8`.
- Modelo verificado por **SHA-256** antes de carga (anti pickle RCE). El histórico v1 queda en `manifest_v1.json` para comparación.

### Dual-model API (RF + XGBoost en paralelo)

```bash
# RF (default)
curl -X POST http://<host>:8000/predict \
     -H "X-API-Key: <key>" \
     -H "Content-Type: application/json" \
     -d '{"features":[...47 floats...]}'

# XGBoost
curl -X POST 'http://<host>:8000/predict?model=xgb' \
     -H "X-API-Key: <key>" \
     -H "Content-Type: application/json" \
     -d '{"features":[...47 floats...]}'

# Sin SHAP (high throughput)
curl -X POST 'http://<host>:8000/predict/batch?model=rf&explain=false' ...
```

`/health` reporta los modelos disponibles:
```json
{"status":"ok","model":"v2","available_models":["rf","xgb"],"integrity":"verified"}
```

### Explicabilidad SHAP per-flujo

El endpoint `/predict?explain=true` (default) devuelve `top_contributions`:
una lista de los features que más empujaron la decisión hacia la clase
predicha (TreeExplainer de SHAP). Visible en la tab Predicción del
dashboard como bar chart signed (rojo = a favor / azul = en contra).

Para batch high-throughput (sensor): `?explain=false` por performance.

### Correlación ML ↔ Suricata por 5-tupla

El tab **"Suricata vs ML"** del dashboard muestra:

1. **Alertas Suricata** (conteo, top firmas, severidad, últimas 20).
2. **Correlación flow-a-alert** por 5-tupla `(src_ip, dst_ip, src_port, dst_port, proto)`, uniendo:
   - Predicciones del sensor (`logs/sensor_predictions.jsonl` con `request_id` y tag `model`)
   - Alertas Suricata (`logs/eve.json` event_type=alert)
3. **4 veredictos:** `both_detected` | `ml_only` | `suricata_only` | `both_clean`.
4. **Historial JSONL** con rotación a 500 snapshots + botón de descarga.

### Hardening por defecto

- Todos los contenedores aplicables: `cap_drop: ALL`, `no-new-privileges:true`.
- Dashboard y ml_api corren como UID 1000 (non-root).
- Sensor y Suricata con `NET_ADMIN`/`NET_RAW` (requerido para raw sockets / AF_PACKET).
- Nginx como usuario `nginx-unprivileged` en puerto 8080 interno.
- IPs estáticas en compose para evitar mismatches DNS en nginx upstream tras recreates.

### Dashboard pedagógico (6 tabs)

| # | Tab | Contenido |
|---|---|---|
| 1 | Intro | Arquitectura, recorrido del lab, links a servicios, glosario |
| 2 | Dataset | Pie chart de clases, histograma por feature, correlación top-10, preview del parquet |
| 3 | Métricas | Matriz de confusión **en vivo** (50 samples/clase → `/predict/batch`), comparativa RF v2 vs XGBoost v2, F1/Precision/Recall, diagnóstico de la clase más débil |
| 4 | Predicción | Selector de modelo (RF / XGBoost), presets del dataset por categoría, sliders en top-6 features, MITRE como badges, **explicación SHAP real** (top 5 features con valores SHAP signed) |
| 5 | Ataques simulados | Botones para lanzar capturas en el sensor + payloads HTTP directos contra DVWA |
| 6 | Suricata vs ML | Correlación 5-tupla con 4 veredictos, top firmas, severidad, matriz 2×2 |

### Observabilidad (Loki + Grafana)

- **Promtail** envía `eve.json` (Suricata) y `sensor_predictions.jsonl` (ML, con tag `model=rf|xgb`) a Loki.
- **Grafana** consume Loki como datasource con dashboards provisionados en `configs/grafana/`:
  - `IDS-ML Lab — Overview` (general)
  - `IDS-ML Lab — Overview v2` (extendido)
  - **`SOC Enterprise — Suricata`** (rule-based, ET-Open ~50k reglas)
  - **`SOC Enterprise — Random Forest v2`** (filtra `model=rf`)
  - **`SOC Enterprise — XGBoost v2`** (filtra `model=xgb`)

### Notebooks (paso a paso del modelo v2)

La carpeta [notebooks/](notebooks/) documenta la construcción completa
del modelo v2 desde el dataset raw hasta el deliverable final. Pensados
como material de estudio: un alumno los lee en orden y reproduce el pipeline.

| # | Notebook | Qué hace |
|---|---|---|
| 01 | [01_eda.ipynb](notebooks/01_eda.ipynb) | Exploración inicial CICIDS2017 (distribución de clases, schema, NaN/Inf, encoding) |
| 02 | [02_cleaning_preprocessing.ipynb](notebooks/02_cleaning_preprocessing.ipynb) | Drop constantes, fix encoding, mapeo a 6 categorías, deduplicación, normalización de columnas |
| 03 | [03_feature_audit.ipynb](notebooks/03_feature_audit.ipynb) | Feature audit: aliases, drop por leakage (Init_Win_Bytes, SYN/CWE/ECE), redundancia (Avg_*, Subflow_*) y VIF iterativo. Llega a las 47 features finales |
| 04 | [04_baselines.ipynb](notebooks/04_baselines.ipynb) | Split estratificado 70/15/15 + baselines (LogReg/KNN/RF default). Comparación apples-to-apples en val balanced y val full |
| 05 | [05_tuning_xgboost.ipynb](notebooks/05_tuning_xgboost.ipynb) | Tuning de RF (16 configs) + tuning de XGBoost (16 configs). Ganador: RF tuned (F1-macro 0.670) sobre XGBoost tuned (0.645) |
| 06 | [06_final_model.ipynb](notebooks/06_final_model.ipynb) | Train final de RF tuned + XGBoost tuned sobre train+val combinados, eval en test (nunca visto). Exporta 7 joblibs v2 + manifest_v2.json (SHA-256) |
| 07 | [07_adversarial_evasion.ipynb](notebooks/07_adversarial_evasion.ipynb) | Adversarial HopSkipJump contra RF v2 y XGBoost v2. Ambos 100% evadibles; RF necesita más perturbación máxima (L2 hasta 1320 vs 100 de XGBoost) |
| 08 | [08_inference_validation.ipynb](notebooks/08_inference_validation.ipynb) | Inference validation end-to-end: carga local v2 + verificación SHA-256 + comparación bit-exact con el ML API en runtime (30/30 matches) |

Todos los notebooks vienen ejecutados en el repo (con outputs visibles en
GitHub render). El container Jupyter del lab los monta automáticamente
en `/home/app/notebooks/` y trae preinstalado: `xgboost`, `statsmodels`,
`adversarial-robustness-toolbox`, `pandas`, `numpy`, `matplotlib`,
`seaborn`, `joblib`, `pyarrow`, `nbconvert`.

## Estructura del repositorio

```
ML-Lab-Capston/
├── README.md
├── setup.sh                       ← deploy en un comando (47s en VM con imágenes cacheadas)
├── .env.example                   ← plantilla credenciales
├── docker-compose.yml             ← stack de 11 contenedores
├── build/
│   ├── ml_api/                    ← FastAPI + RF v2 + XGBoost v2 + SHAP
│   ├── dashboard/                 ← Streamlit 6 tabs + correlación 5-tupla + SHAP UI
│   ├── sensor/                    ← CICFlowMeter + dual-model batch + JSONL tagged
│   └── jupyter/                   ← JupyterLab + ART + statsmodels + xgboost preinstalados
├── configs/
│   ├── nginx/nginx.conf           ← proxy + BasicAuth + rate limit
│   ├── suricata/suricata.yaml     ← config empresarial (49k reglas)
│   ├── loki/                      ← config Loki
│   ├── promtail/                  ← shipping de eve.json + sensor JSONL (con tag model)
│   └── grafana/                   ← provisioning + 5 dashboards (2 overview + 3 SOC)
├── notebooks/                     ← 8 notebooks 01-08 ejecutados con outputs
└── models/                        ← artefactos v1 (histórico) + v2 (activo) + manifest SHA-256
```

## Operación

```bash
# Ver estado
docker compose ps

# Logs de un servicio
docker compose logs -f ml_api
docker compose logs -f sensor

# Reiniciar un servicio
docker compose restart dashboard

# Parar todo (preserva volúmenes y red ids_network)
docker compose down

# Parar y borrar volúmenes (reset completo)
docker compose down -v && docker network rm ids_network

# Ejecutar un notebook headless
docker exec -w /home/app/notebooks ids-jupyter \
  jupyter nbconvert --to notebook --execute 07_adversarial_evasion.ipynb \
  --output 07_adversarial_evasion_executed.ipynb
```

## Lanzar una captura (ejemplo)

```bash
# POST al sensor: 20s, intensity 80, inyecta flujos CICIDS2017 reales
# (sin inject_dataset las predicciones son mayoritariamente Benign por
# limitación del feature extractor de scapy vs CICFlowMeter de training).
curl -X POST http://localhost:9999/capture/start \
  -H "Content-Type: application/json" \
  -d '{"duration": 20, "attack_type": "scan", "intensity": 80, "inject_dataset": true}'

# Ver resultados
curl http://localhost:9999/capture/results | jq '.summary'
```

Las predicciones se persisten en `logs/sensor_predictions.jsonl`
(con tag `model=rf|xgb` por línea) y el dashboard las correlaciona
automáticamente con `logs/eve.json` por 5-tupla. Los 3 dashboards SOC
de Grafana se alimentan del mismo stream filtrando por modelo.

## Créditos

- Dataset: [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (UNB)
- Validación cruzada: [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) (UNSW Canberra)
- Reglas Suricata: [ET-Open](https://rules.emergingthreats.net/open/)
- Adversarial: [IBM Adversarial Robustness Toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox)
- Explicabilidad: [SHAP](https://github.com/shap/shap) (Lundberg & Lee 2017)

## Licencia

MIT — Uso educativo / investigación.

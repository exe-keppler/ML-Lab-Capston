# Laboratorio IDS-ML + Cybersecurity

Sistema de Detección de Intrusiones basado en Machine Learning con correlación rule-based (Suricata) y evaluación adversarial (IBM ART). Despliegue educativo — Maestría en IA Aplicada, UDLA 2026.

## Stack

| Componente | Rol |
|---|---|
| **FastAPI + Random Forest v3** | ML API con 47 features CICIDS2017 auditado |
| **Streamlit** | Dashboard pedagógico de 6 tabs con correlación ML ↔ Suricata por 5-tupla |
| **Suricata + ET-Open (~50k reglas)** | IDS rule-based (host mode, captura sobre bridge docker) |
| **Sensor (CICFlowMeter)** | Captura tráfico, inyecta muestras CICIDS2017 y extrae features en vivo |
| **JupyterLab + IBM ART** | Notebooks para ataques adversariales |
| **DVWA + MariaDB** | Target vulnerable para ejercicios |
| **Nginx** | Reverse proxy con BasicAuth + rate limit |
| **Loki + Promtail** | Agregación de logs (`eve.json`, `sensor_predictions.jsonl`) |
| **Grafana** | Dashboards de observabilidad en tiempo real |

## Requisitos

- Linux (testeado en Fedora 43, Ubuntu 22.04 / 24.04)
- Docker ≥ 24 + plugin `docker compose` v2
- 6 GB RAM libre, 12 GB disco (incluye Loki/Grafana)
- Puertos 80, 3000, 8000, 8080, 8888, 9999 libres
- `openssl` (suele venir en todas las distros)

## Despliegue en un solo comando

```bash
git clone https://github.com/exe-keppler/Laboratorio-MLCyber.git
cd Laboratorio-MLCyber
./setup.sh
```

El script:

1. Verifica dependencias (Docker, compose, openssl).
2. Crea `.env` desde `.env.example` si no existe.
3. Genera `configs/nginx/htpasswd` con las credenciales de `.env`.
4. Detecta la interfaz del bridge Docker para Suricata.
5. Construye las 4 imágenes custom (ml_api, dashboard, sensor, jupyter).
6. Levanta los 11 contenedores y espera healthchecks.
7. Imprime las URLs de acceso.

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

### Modelo v3 auditado

- F1-macro multiclase **0.875** sobre test, 6 clases (Benign, DDoS, DoS, Brute Force, Reconnaissance, Web Attack).
- **47 features** tras auditoría: drop de 31 columnas (8 constantes + 9 con leakage documentado + 14 redundantes por VIF).
- Split **estratificado por (día, etiqueta)** 70/15/15 con deduplicación previa (−27.95 %).
- Modelo verificado por **SHA-256** antes de carga (anti pickle RCE).

### Correlación ML ↔ Suricata por 5-tupla

El tab **"Suricata vs ML"** del dashboard muestra:

1. **Alertas Suricata** (conteo, top firmas, severidad, últimas 20).
2. **Correlación flow-a-alert** por 5-tupla `(src_ip, dst_ip, src_port, dst_port, proto)`, uniendo:
   - Predicciones del sensor (`logs/sensor_predictions.jsonl` con `request_id`)
   - Alertas Suricata (`logs/eve.json` event_type=alert)
3. **4 veredictos:** `both_detected` | `ml_only` | `suricata_only` | `both_clean`.
4. **Historial JSONL** con rotación a 500 snapshots + botón de descarga.

### Hardening por defecto

- Todos los contenedores aplicables: `cap_drop: ALL`, `no-new-privileges:true`.
- Dashboard y ml_api corren como UID 1000 (non-root).
- Sensor y Suricata con `NET_ADMIN`/`NET_RAW` (requerido para raw sockets / AF_PACKET).
- Nginx como usuario `nginx-unprivileged` en puerto 8080 interno.

### Dashboard pedagógico (6 tabs)

| # | Tab | Contenido |
|---|---|---|
| 1 | 📚 Intro | Arquitectura, recorrido del lab, links a servicios, glosario |
| 2 | 📁 Dataset | Pie chart de clases, histograma por feature, correlación top-10, preview del parquet |
| 3 | 📊 Métricas | Matriz de confusión **en vivo** (50 samples/clase → `/predict/batch`), F1/Precision/Recall, diagnóstico de la clase más débil |
| 4 | 🔮 Predicción | Presets del dataset por categoría, sliders en top-6 features, MITRE como badges, explicación heurística Gini×valor |
| 5 | ⚔️ Ataques simulados | Botones para lanzar capturas en el sensor + payloads HTTP directos contra DVWA |
| 6 | ⚖️ Suricata vs ML | Correlación 5-tupla con 4 veredictos, top firmas, severidad, matriz 2×2 |

### Observabilidad (Loki + Grafana)

- **Promtail** envía `eve.json` (Suricata) y `sensor_predictions.jsonl` (ML) a Loki.
- **Grafana** consume Loki como datasource con dashboards provisionados en `configs/grafana/`.
- Útil para ver volumen de alertas, top firmas, ratio attack/benign en tiempo real.

### Evaluación adversarial

Notebook [notebooks/01_adversarial_evasion.ipynb](notebooks/01_adversarial_evasion.ipynb):

- **HopSkipJump** (black-box, L2) contra RF v3.
- **84 % de tasa de evasión** con perturbación L2 ≈ 0.003.
- Resultados en `logs/art_evasion_results.json`.

## Estructura del repositorio

```
Laboratorio-MLCyber/
├── README.md
├── WALKTHROUGH.md                 ← guía de demos y ataques
├── BITACORA_*.md                  ← bitácoras de sesiones
├── setup.sh                       ← deploy en un comando
├── attack.sh                      ← ataques desde el host (nmap, sqli, xss, ...)
├── .env.example                   ← plantilla credenciales
├── docker-compose.yml             ← stack de 11 contenedores
├── build/
│   ├── ml_api/                    ← FastAPI + RF v3 + auth + SHA-256 verify
│   ├── dashboard/                 ← Streamlit 6 tabs + correlación 5-tupla
│   ├── sensor/                    ← CICFlowMeter + request_id + JSONL
│   └── jupyter/                   ← JupyterLab + ART + SHAP
├── configs/
│   ├── nginx/nginx.conf           ← proxy + BasicAuth + rate limit
│   ├── suricata/suricata.yaml     ← config empresarial (49k reglas)
│   ├── loki/                      ← config Loki
│   ├── promtail/                  ← shipping de eve.json + sensor JSONL
│   └── grafana/                   ← provisioning + dashboards
├── notebooks/                     ← 01_adversarial_evasion.ipynb (HopSkipJump)
└── models/                        ← 32 MB artefactos RF v3 + manifest SHA-256
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

# Parar todo
docker compose down

# Parar y borrar volúmenes (reset completo)
docker compose down -v

# Ejecutar el notebook adversarial headless
docker exec -w /home/app/models ids-jupyter \
  jupyter nbconvert --to notebook --execute 01_adversarial_evasion.ipynb \
  --output 01_adversarial_evasion_executed.ipynb
```

## Lanzar una captura (ejemplo)

```bash
# POST al sensor para capturar 20s de tráfico contra DVWA
curl -X POST http://localhost:9999/capture/start \
  -H "Content-Type: application/json" \
  -d '{"duration": 20, "attack_type": "scan", "intensity": 40}'

# Ver resultados
curl http://localhost:9999/capture/results | jq '.summary'
```

Las predicciones se persisten en `logs/sensor_predictions.jsonl` y el dashboard las correlaciona automáticamente con `logs/eve.json`.

## Créditos

- Dataset: [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (UNB)
- Validación cruzada: [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) (UNSW Canberra)
- Reglas Suricata: [ET-Open](https://rules.emergingthreats.net/open/)
- Adversarial: [IBM Adversarial Robustness Toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox)

## Licencia

MIT — Uso educativo / investigación.

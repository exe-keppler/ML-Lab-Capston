# Scripts legacy

Scripts one-shot de la sesión de despliegue/diagnóstico **2026-04-23** sobre el host
`192.168.0.126` (ver [`BITACORA_2026-04-23.md`](../../../BITACORA_2026-04-23.md)).

> ⚠️ **No son portables.** Todos asumen `PROJ=/home/operador/Laboratorio-MLCyber`,
> el venv `/home/operador/kaggle_env`, y la red docker
> `laboratorio-mlcyber_ids_network`. Quedan acá como referencia histórica;
> no formar parte del flujo `setup.sh`.

| Script | Qué hizo |
|---|---|
| `diag.sh` | Diagnóstico inicial del stack (containers, eve.json, predictions). |
| `diag_grafana.sh` | Diagnóstico específico de Grafana/Loki/Promtail. |
| `fix_and_verify.sh` | Aplicó el fix de `SURICATA_INTERFACE` y verificó eve.json. |
| `tests.sh` | Suite de tests end-to-end (health, predict, sensor capture). |
| `test_inference.sh`, `test_inference2.sh` | Iteraciones de testing del endpoint `/predict`. |
| `fill_grafana.sh`, `fill2.sh` | Generaron tráfico para poblar dashboards Grafana. |
| `verify_dashboards.sh` | Validó que los paneles de Grafana tuvieran datos. |
| `kaggle_setup.sh` | Instaló `kaggle` CLI en venv y configuró credenciales. |
| `kaggle_download.sh` | Descargó `cicids2017-cleaned-and-preprocessed` (685 MB CSV). |
| `preprocess.sh` | CSV → parquet 12000×48 balanceado a 6 clases. |
| `final_push.sh` | Push final del dataset + restart de servicios. |
| `apply_dashboard_v3.sh` | Aplicó la reescritura del dashboard a 6 tabs. |

Si necesitás reproducir alguno en otro host, ajustá los paths/red al nuevo entorno.

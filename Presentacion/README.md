# Presentación — Laboratorio IDS-ML

Material para una exposición de ~45 minutos a estudiantes universitarios sobre el laboratorio IDS-ML.

## Contenido

| Archivo | Para qué |
|---|---|
| `slides.md` | Source en Markdown (Marp). Cómoda para versionar y editar. |
| `build_pptx.py` | Script que genera el `.pptx` final desde Python (sin dependencias de browser). |
| `exports/Laboratorio-IDS-ML.pptx` | **Presentación lista** (30 slides). Generada por `build_pptx.py`. |
| `demo_guiado.md` | Guion paso a paso para la demo en vivo (~10–15 min). |
| `tomar_screenshots.sh` | Helper para capturar Streamlit + Grafana (placeholders en slide 27). |
| `screenshots/` | Donde van las capturas (vacío por defecto). |

## Cómo regenerar la presentación

```bash
cd Presentacion
python3 build_pptx.py     # → exports/Laboratorio-IDS-ML.pptx (30 slides)
```

Requisitos: `pip install --user python-pptx`.

## Cómo agregar capturas reales

La slide 27 ("Capturas del lab") tiene 4 placeholders. Cuando existan los archivos en `screenshots/`, el script los integra automáticamente. Filenames esperados:

```
screenshots/
├── 01_streamlit_metricas.png
├── 02_streamlit_shap.png
├── 03_grafana_suricata.png
└── 04_grafana_rf.png
```

### Opción A — Helper script (browser headless)

```bash
chmod +x tomar_screenshots.sh
./tomar_screenshots.sh
```

Detecta `chromium`, `google-chrome` o `firefox` (incluyendo flatpak). Necesita el lab levantado en `192.168.122.10`. Para apuntar a otro host:

```bash
LAB_HOST=mi-vm.local ./tomar_screenshots.sh
```

### Opción B — Manual

1. Abrir cada URL en el browser:
   - `http://192.168.122.10/` (login lab/ids2026) → tab Métricas, F11 fullscreen
   - `http://192.168.122.10/` → tab Predicción → clasificar un Reconnaissance
   - `http://192.168.122.10:3000/d/soc-suricata` (login admin/ids2026)
   - `http://192.168.122.10:3000/d/soc-rf-v2`
2. Capturar pantalla (Linux: `gnome-screenshot`, `flameshot`).
3. Guardar en `screenshots/` con los nombres exactos de arriba.

Después regenerar el PPTX:

```bash
python3 build_pptx.py
```

## Estructura de la presentación (30 slides, ~40 min)

| # | Sección | Contenido |
|---|---|---|
| 1 | Portada | Título + repo |
| 2–4 | Contexto | Problema, stack, ML vs reglas |
| 5–12 | Pipeline ML | 8 notebooks: EDA → cleaning → audit → baselines → tuning → final → adversarial → validation |
| 13–19 | Stack producción | API hardened, SHAP, sensor, Grafana SOC, Streamlit, reproducibilidad |
| 20–23 | Limitaciones | Adversarial 100% evasión, caveats, ML+reglas complementarios |
| 24–27 | Para futuros | Cómo extender, demo en vivo, capturas |
| 28 | Recursos | Links a CICIDS2017, ART, SHAP, Suricata |
| 29–30 | Q&A + cierre | |

## Tips para el día de la presentación

1. **Levantar el lab antes de empezar la clase** — `setup.sh` toma 47s en VM con caché, pero la primera vez son 5 min de build.
2. **Tener las 4 pestañas abiertas en el browser** (ver `demo_guiado.md` Apéndice).
3. **Plan B**: si la red falla durante la demo, los screenshots de la slide 27 + las métricas de los notebooks 06/07 (en GitHub) son suficientes para mostrar resultados.
4. **Tiempo**: 30 slides × ~1 min cada una (excepto las de sección que son 30s) + demo 10 min + Q&A 5 min ≈ **45 min total**.

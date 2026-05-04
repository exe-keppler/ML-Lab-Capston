#!/usr/bin/env bash
# Helper para tomar screenshots de la demo del lab.
#
# Uso: ./tomar_screenshots.sh
#
# Asume que Streamlit y Grafana están accesibles en 192.168.122.10.
# Detecta el browser disponible (chromium / google-chrome / firefox).
# Las capturas van a Presentacion/screenshots/.

set +e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/screenshots"
mkdir -p "$OUT"

HOST="${LAB_HOST:-192.168.122.10}"
TIMEOUT_SEC="${TIMEOUT_SEC:-12}"

# Detectar browser
BROWSER=""
for b in chromium chromium-browser google-chrome chrome brave-browser; do
    if command -v "$b" >/dev/null 2>&1; then
        BROWSER="$b"
        break
    fi
done

# Fallback: flatpak chrome / chromium
if [ -z "$BROWSER" ] && command -v flatpak >/dev/null 2>&1; then
    if flatpak list --app 2>/dev/null | grep -qi chromium; then
        BROWSER="flatpak run org.chromium.Chromium"
    elif flatpak list --app 2>/dev/null | grep -qi google-chrome; then
        BROWSER="flatpak run com.google.Chrome"
    fi
fi

if [ -z "$BROWSER" ]; then
    cat <<EOF
[!] No se encontró browser headless instalado.
    Opciones:
      sudo dnf install -y chromium                 # Fedora
      sudo apt install -y chromium-browser         # Debian/Ubuntu
      flatpak install -y flathub org.chromium.Chromium

    O instalar playwright:
      pip install --user playwright && playwright install chromium

    Alternativa manual: abrir cada URL listada abajo y guardar PNG en
    Presentacion/screenshots/ con los nombres exactos.
EOF
    exit 1
fi

echo "Browser: $BROWSER"

# Capturas a tomar (filename → URL)
declare -a SHOTS=(
    "01_streamlit_intro.png|http://lab:ids2026@${HOST}/"
    "02_streamlit_metricas.png|http://lab:ids2026@${HOST}/?embed=true&tab=Metricas"
    "03_streamlit_shap.png|http://lab:ids2026@${HOST}/?embed=true&tab=Prediccion"
    "04_grafana_suricata.png|http://${HOST}:3000/d/soc-suricata?kiosk&orgId=1"
    "05_grafana_rf.png|http://${HOST}:3000/d/soc-rf-v2?kiosk&orgId=1"
    "06_grafana_xgb.png|http://${HOST}:3000/d/soc-xgb-v2?kiosk&orgId=1"
    "07_jupyter_overview.png|http://${HOST}:8888/lab?token=lab-ids-ml-udla-2026"
)

for entry in "${SHOTS[@]}"; do
    fname="${entry%%|*}"
    url="${entry##*|}"
    out_path="$OUT/$fname"
    echo "  → $fname"
    timeout $TIMEOUT_SEC $BROWSER \
        --headless --disable-gpu --no-sandbox \
        --window-size=1600,1000 \
        --hide-scrollbars \
        --screenshot="$out_path" \
        --virtual-time-budget=8000 \
        "$url" >/dev/null 2>&1
    if [ -f "$out_path" ]; then
        size=$(du -h "$out_path" | cut -f1)
        echo "     OK ($size)"
    else
        echo "     FALLÓ"
    fi
    sleep 1
done

echo
echo "Capturas en: $OUT"
ls -lh "$OUT" 2>/dev/null

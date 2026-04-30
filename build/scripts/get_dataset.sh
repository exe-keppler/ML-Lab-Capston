#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# get_dataset.sh — descarga CICIDS2017 desde Kaggle y lo procesa
#                  al parquet que consumen sensor + dashboard.
# Uso:
#   ./build/scripts/get_dataset.sh           # skip si ya existe
#   FORCE=1 ./build/scripts/get_dataset.sh   # forzar regenerar
# Requisitos:
#   - python3 + pip
#   - ~/.kaggle/kaggle.json (https://www.kaggle.com/settings)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DATASETS_DIR="$PROJ_ROOT/datasets"
RAW_DIR="$DATASETS_DIR/raw"
OUTPUT="$DATASETS_DIR/cicids_v3_test.parquet"
KAGGLE_DATASET="ericanacletoribeiro/cicids2017-cleaned-and-preprocessed"

RESET=$'\033[0m'; GREEN=$'\033[0;32m'; RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; BOLD=$'\033[1m'
say()  { printf "${BLUE}▸${RESET} %s\n" "$*"; }
ok()   { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}!${RESET} %s\n" "$*"; }
fail() { printf "${RED}✗${RESET} %s\n" "$*"; exit 1; }

printf "${BOLD}━━ Descarga + preprocess dataset CICIDS2017 ━━${RESET}\n"

# ─────────────────────────────────────────────────────────────
# 0. Skip si ya existe
# ─────────────────────────────────────────────────────────────
if [ -f "$OUTPUT" ] && [ -z "${FORCE:-}" ]; then
    SIZE=$(du -h "$OUTPUT" | awk '{print $1}')
    ok "Dataset ya existe: $OUTPUT ($SIZE)"
    ok "Para regenerar: FORCE=1 $0"
    exit 0
fi

# ─────────────────────────────────────────────────────────────
# 1. Prerequisites
# ─────────────────────────────────────────────────────────────
command -v python3 >/dev/null 2>&1 || fail "python3 no disponible"
command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1 \
    || fail "pip3/pip no disponible (apt install python3-pip)"
PIP=$(command -v pip3 || command -v pip)

if [ ! -f "$HOME/.kaggle/kaggle.json" ]; then
    fail "Falta ~/.kaggle/kaggle.json. Crealo en https://www.kaggle.com/settings → 'Create New Token'."
fi
chmod 600 "$HOME/.kaggle/kaggle.json"
ok "Credenciales Kaggle OK"

# ─────────────────────────────────────────────────────────────
# 2. Instalar deps Python si faltan (al user, no sudo)
# ─────────────────────────────────────────────────────────────
NEED=()
python3 -c "import kaggle" 2>/dev/null || NEED+=(kaggle)
python3 -c "import pandas" 2>/dev/null || NEED+=(pandas)
python3 -c "import pyarrow" 2>/dev/null || NEED+=(pyarrow)
python3 -c "import numpy" 2>/dev/null || NEED+=(numpy)

if [ ${#NEED[@]} -gt 0 ]; then
    say "Instalando deps Python (--user): ${NEED[*]}"
    "$PIP" install --user --quiet --break-system-packages "${NEED[@]}" 2>/dev/null \
        || "$PIP" install --user --quiet "${NEED[@]}" \
        || fail "pip install falló. Probá: $PIP install --user ${NEED[*]}"
    # Asegurar que ~/.local/bin esté en PATH para esta sesión
    export PATH="$HOME/.local/bin:$PATH"
    ok "Deps instaladas"
else
    ok "Deps Python ya disponibles"
fi

# ─────────────────────────────────────────────────────────────
# 3. Descargar dataset desde Kaggle
# ─────────────────────────────────────────────────────────────
mkdir -p "$RAW_DIR"

# Si ya hay CSV descargado, skip descarga
EXISTING_CSV=$(find "$RAW_DIR" -type f -iname "*.csv" 2>/dev/null | head -1 || true)
if [ -n "$EXISTING_CSV" ] && [ -z "${FORCE:-}" ]; then
    ok "CSV ya descargado: $EXISTING_CSV"
    RAW_CSV="$EXISTING_CSV"
else
    say "Descargando $KAGGLE_DATASET (~210 MB) → $RAW_DIR/"
    (cd "$RAW_DIR" && python3 -m kaggle datasets download -d "$KAGGLE_DATASET" --unzip)
    RAW_CSV=$(find "$RAW_DIR" -type f -iname "*.csv" | head -1)
    [ -n "$RAW_CSV" ] || fail "No se encontró CSV tras la descarga"
    ok "CSV: $RAW_CSV ($(du -h "$RAW_CSV" | awk '{print $1}'))"
fi

# ─────────────────────────────────────────────────────────────
# 4. Preprocess CSV → parquet con las 47 features del modelo
# ─────────────────────────────────────────────────────────────
say "Procesando CSV → $OUTPUT ..."

RAW_CSV="$RAW_CSV" OUTPUT="$OUTPUT" python3 <<'PYEOF'
import os, re, sys
import pandas as pd
import numpy as np

RAW = os.environ['RAW_CSV']
OUT = os.environ['OUTPUT']

MODEL_FEATURES = [
    "Flow_Duration","Total_Fwd_Packets","Total_Backward_Packets",
    "Total_Length_of_Fwd_Packets","Total_Length_of_Bwd_Packets",
    "Fwd_Packet_Length_Max","Fwd_Packet_Length_Min","Fwd_Packet_Length_Mean",
    "Bwd_Packet_Length_Max","Bwd_Packet_Length_Min","Bwd_Packet_Length_Mean","Bwd_Packet_Length_Std",
    "Flow_Bytes_per_s","Flow_Packets_per_s",
    "Flow_IAT_Mean","Flow_IAT_Std","Flow_IAT_Max","Flow_IAT_Min",
    "Fwd_IAT_Mean","Fwd_IAT_Std","Fwd_IAT_Min",
    "Bwd_IAT_Total","Bwd_IAT_Mean","Bwd_IAT_Std","Bwd_IAT_Max","Bwd_IAT_Min",
    "Fwd_PSH_Flags","Fwd_URG_Flags","Bwd_Packets_per_s",
    "Min_Packet_Length","Max_Packet_Length","Packet_Length_Mean","Packet_Length_Std","Packet_Length_Variance",
    "FIN_Flag_Count","RST_Flag_Count","PSH_Flag_Count","ACK_Flag_Count","URG_Flag_Count",
    "Down_per_Up_Ratio","act_data_pkt_fwd","min_seg_size_forward",
    "Active_Mean","Active_Std","Active_Max","Active_Min","Idle_Std",
]

LABEL_MAP = {
    'BENIGN': 'Benign', 'Benign': 'Benign', 'benign': 'Benign', 'Normal Traffic': 'Benign',
    'DDoS': 'DDoS',
    'DoS Hulk': 'DoS', 'DoS GoldenEye': 'DoS', 'DoS Slowhttptest': 'DoS', 'DoS slowloris': 'DoS', 'Heartbleed': 'DoS', 'DoS': 'DoS',
    'FTP-Patator': 'Brute Force', 'SSH-Patator': 'Brute Force', 'Brute Force': 'Brute Force',
    'Web Attack – XSS': 'Web Attack', 'Web Attack – Sql Injection': 'Web Attack', 'Web Attack – Brute Force': 'Web Attack',
    'Web Attack - XSS': 'Web Attack', 'Web Attack - Sql Injection': 'Web Attack', 'Web Attack - Brute Force': 'Web Attack',
    'Web Attack XSS': 'Web Attack', 'Web Attack Sql Injection': 'Web Attack', 'Web Attack Brute Force': 'Web Attack',
    'Web Attacks': 'Web Attack',
    'PortScan': 'Reconnaissance', 'Port Scan': 'Reconnaissance', 'Port Scanning': 'Reconnaissance',
    'Bot': 'Reconnaissance', 'Botnet': 'Reconnaissance', 'Bots': 'Reconnaissance', 'Infiltration': 'Reconnaissance',
}

def fallback_map(v):
    if pd.isna(v): return 'Benign'
    s = str(v).lower()
    if 'benign' in s or s == 'normal': return 'Benign'
    if 'ddos' in s: return 'DDoS'
    if 'dos' in s or 'heartbleed' in s: return 'DoS'
    if 'patator' in s or 'brute' in s: return 'Brute Force'
    if 'web' in s or 'xss' in s or 'sql' in s: return 'Web Attack'
    if 'scan' in s or 'bot' in s or 'infiltrat' in s or 'recon' in s: return 'Reconnaissance'
    return None

# Aliases para variantes de nombre en distintas versiones de CICIDS2017
# (raw column name → schema esperado por el modelo).
ALIAS = {
    'Fwd Packets Length Total': 'Total_Length_of_Fwd_Packets',
    'Bwd Packets Length Total': 'Total_Length_of_Bwd_Packets',
    'Packet Length Min':        'Min_Packet_Length',
    'Packet Length Max':        'Max_Packet_Length',
    'Fwd Act Data Packets':     'act_data_pkt_fwd',
    'Fwd Seg Size Min':         'min_seg_size_forward',
}

def norm_col(c):
    c = c.strip().replace('/s', '_per_s').replace('/', '_per_')
    return re.sub(r'\s+', '_', c)

print(f"  [1/5] Leyendo CSV...")
df = pd.read_csv(RAW, low_memory=False)
print(f"        shape: {df.shape}")

label_col = next((c for c in ['Attack Type','Label','label','Category','Class'] if c in df.columns), None)
if not label_col:
    sys.exit(f"ERROR: no se encontró columna label en {list(df.columns)[:15]}")
print(f"        label column: {label_col}")

print(f"  [2/5] Mapeando labels → 6 categorías")
df['Label_6'] = df[label_col].map(LABEL_MAP)
mask_unmapped = df['Label_6'].isna()
if mask_unmapped.any():
    df.loc[mask_unmapped, 'Label_6'] = df.loc[mask_unmapped, label_col].apply(fallback_map)
df = df[df['Label_6'].notna()]
print(f"        distribución: {df['Label_6'].value_counts().to_dict()}")

print(f"  [3/5] Aliases + normalización de nombres de columnas")
df = df.rename(columns=ALIAS)
df = df.rename(columns={c: norm_col(c) for c in df.columns})
available = [f for f in MODEL_FEATURES if f in df.columns]
missing = [f for f in MODEL_FEATURES if f not in df.columns]
print(f"        disponibles: {len(available)}/{len(MODEL_FEATURES)}; imputadas con 0: {len(missing)}")
for f in missing:
    df[f] = 0.0

print(f"  [4/5] Limpieza + balanceo (max 2000/clase)")
out = df[MODEL_FEATURES + ['Label_6']].copy()
out[MODEL_FEATURES] = out[MODEL_FEATURES].replace([np.inf, -np.inf], 0.0).fillna(0.0).astype(float)

rng = np.random.default_rng(42)
parts = [grp.sample(n=min(2000, len(grp)), random_state=42) for _, grp in out.groupby('Label_6')]
balanced = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"        shape final: {balanced.shape}")

print(f"  [5/5] Escribiendo parquet")
balanced.to_parquet(OUT, index=False)
size_kb = os.path.getsize(OUT) / 1024
print(f"        OK: {OUT} ({size_kb:.1f} KB)")
PYEOF

ok "Parquet generado: $OUTPUT"

# ─────────────────────────────────────────────────────────────
# 5. Avisar si los containers están corriendo
# ─────────────────────────────────────────────────────────────
if command -v docker >/dev/null 2>&1 \
   && docker ps --format '{{.Names}}' 2>/dev/null | grep -qE '^(ids-sensor|ids-dashboard)$'; then
    say "Detectados containers del lab corriendo."
    say "Los volúmenes son bind mounts → el dataset ya está accesible."
    say "Si querés forzar refresco del dashboard: docker compose restart dashboard sensor"
fi

ok "Listo."

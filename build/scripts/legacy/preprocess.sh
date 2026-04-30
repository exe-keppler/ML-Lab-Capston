#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
VENV=/home/operador/kaggle_env
RAW=$PROJ/datasets/raw/cicids2017_cleaned.csv
OUT=$PROJ/datasets/cicids_v3_test.parquet

"$VENV/bin/python3" <<'PYEOF'
import pandas as pd, numpy as np, sys, re

RAW = '/home/operador/Laboratorio-MLCyber/datasets/raw/cicids2017_cleaned.csv'
OUT = '/home/operador/Laboratorio-MLCyber/datasets/cicids_v3_test.parquet'

# 47 features EXACTAS del modelo (ids-ml-api /features)
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
    "Active_Mean","Active_Std","Active_Max","Active_Min","Idle_Std"
]

# Mapeo labels CICIDS2017 -> 6 categorias del modelo
LABEL_MAP = {
    'BENIGN': 'Benign','Benign': 'Benign','benign': 'Benign',
    'DDoS': 'DDoS',
    'DoS Hulk': 'DoS','DoS GoldenEye': 'DoS','DoS Slowhttptest': 'DoS','DoS slowloris': 'DoS','Heartbleed': 'DoS',
    'FTP-Patator': 'Brute Force','SSH-Patator': 'Brute Force',
    'Web Attack – XSS': 'Web Attack','Web Attack – Sql Injection': 'Web Attack','Web Attack – Brute Force': 'Web Attack',
    'Web Attack - XSS': 'Web Attack','Web Attack - Sql Injection': 'Web Attack','Web Attack - Brute Force': 'Web Attack',
    'Web Attack XSS': 'Web Attack','Web Attack Sql Injection': 'Web Attack','Web Attack Brute Force': 'Web Attack',
    'PortScan': 'Reconnaissance','Port Scan': 'Reconnaissance',
    'Bot': 'Reconnaissance','Botnet': 'Reconnaissance','Infiltration': 'Reconnaissance',
}

def norm_col(c):
    """CICIDS 'Flow Bytes/s' -> 'Flow_Bytes_per_s'"""
    c = c.strip()
    c = c.replace('/s', '_per_s').replace('/', '_per_')
    c = re.sub(r'\s+', '_', c)
    return c

print(f"[1/6] Leyendo {RAW} ...")
df = pd.read_csv(RAW, low_memory=False)
print(f"  shape original: {df.shape}")
print(f"  columnas label candidatas: {[c for c in df.columns if 'attack' in c.lower() or 'label' in c.lower() or 'class' in c.lower()]}")

label_col = None
for cand in ['Attack Type','Label','label','Category','Class']:
    if cand in df.columns:
        label_col = cand
        break
if not label_col:
    print("ERROR: sin columna label"); sys.exit(1)
print(f"  label column: {label_col}")

print(f"\n[2/6] Distribucion original:")
print(df[label_col].value_counts().head(20))

# Mapear label a 6 categorias
df['Label_6'] = df[label_col].map(LABEL_MAP)
# Normalizar strings intermedios no mapeados
unmapped = df[df['Label_6'].isna()][label_col].unique()
if len(unmapped):
    print(f"\n  labels NO mapeados: {list(unmapped)[:10]}")
    # Fallback: intentar coincidencia por substring
    def fallback_map(v):
        if pd.isna(v): return 'Benign'
        s = str(v).lower()
        if 'benign' in s or s=='normal': return 'Benign'
        if 'ddos' in s: return 'DDoS'
        if 'dos' in s or 'heartbleed' in s: return 'DoS'
        if 'patator' in s or 'brute' in s: return 'Brute Force'
        if 'web' in s or 'xss' in s or 'sql' in s: return 'Web Attack'
        if 'scan' in s or 'bot' in s or 'infiltrat' in s or 'recon' in s: return 'Reconnaissance'
        return None
    df.loc[df['Label_6'].isna(), 'Label_6'] = df.loc[df['Label_6'].isna(), label_col].apply(fallback_map)

print(f"\n[3/6] Distribucion tras mapeo Label_6:")
print(df['Label_6'].value_counts())

# Normalizar nombres de columnas a estilo _
norm_map = {c: norm_col(c) for c in df.columns}
df = df.rename(columns=norm_map)

# Imprimir columnas normalizadas que MATCHEAN con features del modelo
available = [f for f in MODEL_FEATURES if f in df.columns]
missing = [f for f in MODEL_FEATURES if f not in df.columns]
print(f"\n[4/6] Features del modelo disponibles: {len(available)}/{len(MODEL_FEATURES)}")
if missing:
    print(f"  MISSING ({len(missing)}): {missing}")
    # Imputar con 0.0 las faltantes
    for f in missing:
        df[f] = 0.0

# Reordenar: primero las 47 features en orden exacto, luego Label_6
out_cols = MODEL_FEATURES + ['Label_6']
df_out = df[out_cols].copy()

# Limpiar: reemplazar inf/nan, castear a float
df_out[MODEL_FEATURES] = df_out[MODEL_FEATURES].replace([np.inf, -np.inf], 0.0).fillna(0.0).astype(float)
df_out = df_out[df_out['Label_6'].notna()]

print(f"\n[5/6] Balanceando (muestra estratificada)")
# Tomar hasta 2000 por categoria para mantener archivo pequeno
rng = np.random.default_rng(42)
parts = []
for cat, grp in df_out.groupby('Label_6'):
    n = min(2000, len(grp))
    parts.append(grp.sample(n=n, random_state=42))
balanced = pd.concat(parts, ignore_index=True)
balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"  shape final: {balanced.shape}")
print(f"  distribucion final:")
print(balanced['Label_6'].value_counts())

print(f"\n[6/6] Guardando parquet en {OUT}")
balanced.to_parquet(OUT, index=False)
import os
print(f"  tamano: {os.path.getsize(OUT)/1024:.1f} KB")
print(f"\nOK")
PYEOF

echo
echo '--- archivo generado ---'
ls -lh $OUT

echo
echo '--- copiando al contenedor ids-sensor ---'
docker cp "$OUT" ids-sensor:/app/datasets/cicids_v3_test.parquet
docker exec ids-sensor ls -lh /app/datasets/

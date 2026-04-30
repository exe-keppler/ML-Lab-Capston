#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
VENV=/home/operador/kaggle_env
sec() { echo; echo "===== $* ====="; }

sec "1. Regenerar parquet con Benign incluido"
"$VENV/bin/python3" <<'PYEOF'
import pandas as pd, numpy as np, re

RAW = '/home/operador/Laboratorio-MLCyber/datasets/raw/cicids2017_cleaned.csv'
OUT = '/home/operador/Laboratorio-MLCyber/datasets/cicids_v3_test.parquet'

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

def fallback_map(v):
    if pd.isna(v): return 'Benign'
    s = str(v).lower()
    if 'benign' in s or 'normal' in s: return 'Benign'  # FIX: substring
    if 'ddos' in s: return 'DDoS'
    if 'dos' in s or 'heartbleed' in s: return 'DoS'
    if 'patator' in s or 'brute' in s: return 'Brute Force'
    if 'web' in s or 'xss' in s or 'sql' in s: return 'Web Attack'
    if 'scan' in s or 'bot' in s or 'infiltrat' in s or 'recon' in s: return 'Reconnaissance'
    return None

def norm_col(c):
    c = c.strip().replace('/s', '_per_s').replace('/', '_per_')
    return re.sub(r'\s+', '_', c)

print(f"[1] Leyendo CSV ...")
df = pd.read_csv(RAW, low_memory=False)
print(f"  shape: {df.shape}")

df['Label_6'] = df['Attack Type'].apply(fallback_map)
print(f"  distribucion:")
print(df['Label_6'].value_counts())

df = df.rename(columns={c: norm_col(c) for c in df.columns})

missing = [f for f in MODEL_FEATURES if f not in df.columns]
for f in missing:
    df[f] = 0.0
print(f"  features imputadas con 0: {missing}")

df_out = df[MODEL_FEATURES + ['Label_6']].copy()
df_out[MODEL_FEATURES] = df_out[MODEL_FEATURES].replace([np.inf,-np.inf], 0.0).fillna(0.0).astype(float)
df_out = df_out[df_out['Label_6'].notna()]

# Balancear con 2000 por categoria (Benign incluido)
parts = []
for cat, grp in df_out.groupby('Label_6'):
    parts.append(grp.sample(n=min(2000, len(grp)), random_state=42))
balanced = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

print(f"\n  parquet final shape: {balanced.shape}")
print(f"  categorias:")
print(balanced['Label_6'].value_counts())

balanced.to_parquet(OUT, index=False)
import os
print(f"\n  guardado: {OUT} ({os.path.getsize(OUT)/1024:.0f} KB)")
PYEOF

sec "2. Verificar que el sensor lo ve"
docker exec ids-sensor ls -lh /app/datasets/
docker exec ids-sensor python3 -c "
import pandas as pd
df = pd.read_parquet('/app/datasets/cicids_v3_test.parquet')
print('shape:', df.shape)
print('cols label:', 'Label_6' in df.columns)
print('cats:', df['Label_6'].value_counts().to_dict())
"

sec "3. Limpiar predictions.jsonl anterior para ver solo las nuevas"
> /home/operador/Laboratorio-MLCyber/logs/sensor_predictions.jsonl

sec "4. Disparar /capture/start con inject_dataset=true"
RESP=$(curl -s -X POST http://localhost:9999/capture/start \
  -H 'Content-Type: application/json' \
  -d '{"duration":10,"attack_type":"mixed","intensity":5,"inject_dataset":true}')
echo "$RESP"

sec "5. Esperar a que termine (max 120s)"
for i in $(seq 1 30); do
  ST=$(curl -s http://localhost:9999/capture/status | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("status","?"), d.get("flows_extracted","?"))' 2>/dev/null)
  printf '  i=%d %s\n' "$i" "$ST"
  echo "$ST" | grep -q "^done" && break
  sleep 5
done

sec "6. Log del sensor (ver [Inject])"
docker logs --tail 50 ids-sensor 2>&1 | grep -E "Inject|flujos|OK|error" | tail -20

sec "7. sensor_predictions.jsonl: distribucion"
wc -l /home/operador/Laboratorio-MLCyber/logs/sensor_predictions.jsonl
python3 <<'PY'
import json, collections
cats = collections.Counter(); att = collections.Counter(); inj = collections.Counter()
with open('/home/operador/Laboratorio-MLCyber/logs/sensor_predictions.jsonl') as f:
    for l in f:
        try:
            d = json.loads(l)
            cats[d.get('category','?')] += 1
            att[str(d.get('is_attack'))] += 1
        except: pass
print('Total:', sum(cats.values()))
print('Categorias:', dict(cats))
print('is_attack:', dict(att))
PY

sec "8. Loki: flujos ATAQUE ahora?"
docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
  'http://localhost:3100/loki/api/v1/query_range?query=sum(count_over_time(%7Bjob%3D%22ml_predictions%22%2C%20is_attack%3D%22true%22%7D%5B1h%5D))' 2>/dev/null \
  | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); r=d["data"]["result"]; v=r[0]["values"][-1][1] if r and r[0].get("values") else "0"; print("Ataques detectados (query dashboard):", v)'

sec "9. Loki: distribucion por categoria ahora"
docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
  'http://localhost:3100/loki/api/v1/query_range?query=sum%20by(category)%20(count_over_time(%7Bjob%3D%22ml_predictions%22%7D%5B1h%5D))' 2>/dev/null \
  | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
for r in d.get("data",{}).get("result",[]):
    cat = r.get("metric",{}).get("category","?")
    vals = r.get("values",[])
    tot = vals[-1][1] if vals else "0"
    print(f"  {cat}: {tot}")
'

echo; echo "===== FIN ====="

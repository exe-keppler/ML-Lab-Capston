#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
VENV=/home/operador/kaggle_env
DATASET=ericanacletoribeiro/cicids2017-cleaned-and-preprocessed
RAW_DIR="$PROJ/datasets/raw"
sec() { echo; echo "===== $* ====="; }

sec "1. Crear directorio"
mkdir -p "$RAW_DIR"
chown -R operador:operador "$PROJ/datasets"

sec "2. Descargar $DATASET (~210 MB)"
sudo -u operador bash -c "export KAGGLE_CONFIG_DIR=/home/operador/.kaggle; cd '$RAW_DIR' && $VENV/bin/kaggle datasets download -d $DATASET --unzip 2>&1" | tail -15

sec "3. Listar archivos descargados"
ls -lh "$RAW_DIR/"
echo '-- tamanos de CSVs/parquets --'
find "$RAW_DIR" -type f \( -iname "*.csv" -o -iname "*.parquet" \) -exec du -h {} \;

sec "4. Inspeccionar primer archivo (columnas + sample labels)"
FIRST=$(find "$RAW_DIR" -type f \( -iname "*.csv" -o -iname "*.parquet" \) | head -1)
echo "archivo: $FIRST"
"$VENV/bin/python3" <<PYEOF
import pandas as pd, sys
path = '$FIRST'
if path.endswith('.parquet'):
    df = pd.read_parquet(path)
else:
    df = pd.read_csv(path, nrows=50000, low_memory=False)
print('shape:', df.shape)
print('columnas (primeras 30):')
for c in list(df.columns)[:30]:
    print(f'  {repr(c)}')
print('...total columnas:', len(df.columns))
label_col = None
for cand in ['Label','label','Category','Class','Attack','Label_6']:
    if cand in df.columns:
        label_col = cand
        break
if label_col:
    print(f'\nlabel column: {label_col}')
    print('values:', df[label_col].value_counts().head(20).to_dict())
else:
    print('\nNo se detecto columna de label (buscadas: Label/label/Category/Class/Attack)')
    print('ultimas 5 columnas:', list(df.columns)[-5:])
PYEOF

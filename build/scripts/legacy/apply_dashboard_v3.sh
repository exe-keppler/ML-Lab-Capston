#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
sec() { echo; echo "===== $* ====="; }

sec "1. Syntax check app.py"
python3 -c "import ast; ast.parse(open('$PROJ/build/dashboard/src/app.py').read()); print('OK')"

sec "2. Parchear docker-compose: agregar mount datasets + HOST_IP env"
cp "$PROJ/docker-compose.yml" "$PROJ/docker-compose.yml.bak_$(date +%s)"

# Insertar "- DATASETS_DIR=/app/datasets" y "- HOST_IP=192.168.0.126" dentro de environment: del dashboard
# y agregar el mount datasets a volumes del dashboard
python3 <<'PYEOF'
import re
path = '/home/operador/Laboratorio-MLCyber/docker-compose.yml'
src = open(path).read()

# Localizar bloque dashboard:
# Estrategia: regex desde "^  dashboard:" hasta la próxima línea "^  [a-z]" (otro servicio) o final
m = re.search(r'(  dashboard:\n(?:    .*\n)+?)(?=^  [a-z_]+:|\Z)', src, re.MULTILINE)
if not m:
    print('ERROR: no encontré bloque dashboard'); exit(1)
block = m.group(1)
orig = block

# Añadir HOST_IP en environment
if 'HOST_IP=' not in block:
    block = re.sub(
        r'(      - LOGS_DIR=/app/logs\n)',
        r'\1      - HOST_IP=192.168.0.126\n      - DATASETS_DIR=/app/datasets\n',
        block
    )

# Añadir volume datasets
if './datasets:/app/datasets' not in block:
    block = re.sub(
        r'(      - \./logs:/app/logs:rw\n)',
        r'\1      - ./datasets:/app/datasets:ro\n',
        block
    )

if block != orig:
    src = src.replace(orig, block)
    open(path, 'w').write(src)
    print('OK: compose parcheado')
else:
    print('ya estaba parcheado')
PYEOF

sec "3. Verificacion del parche"
grep -A 18 '^  dashboard:' "$PROJ/docker-compose.yml"

sec "4. Build + recreate dashboard"
cd "$PROJ" && docker compose build dashboard 2>&1 | tail -6
cd "$PROJ" && docker compose up -d --force-recreate --no-deps dashboard 2>&1 | tail -4
sleep 10

sec "5. Dashboard logs + HTTP check"
docker logs --tail 15 ids-dashboard 2>&1 | tail -15
echo
echo '-- HTTP via nginx proxy --'
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -u lab:ids2026 -m 5 http://localhost:80/

sec "6. Verificar que dashboard ve el parquet"
docker exec ids-dashboard ls -lh /app/datasets/ 2>&1
docker exec ids-dashboard python3 -c "
import pandas as pd
df = pd.read_parquet('/app/datasets/cicids_v3_test.parquet')
print('dataset shape:', df.shape)
print('categorias:', df['Label_6'].value_counts().to_dict())
" 2>&1

echo; echo "===== FIN ====="

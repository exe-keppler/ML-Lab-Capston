#!/usr/bin/env bash
set +e
sec() { echo; echo "===== $* ====="; }

ENV_FILE=/home/operador/Laboratorio-MLCyber/.env
API_KEY=$(grep '^IDS_API_KEY=' "$ENV_FILE" | cut -d= -f2-)

sec "1. Schema /predict (OpenAPI)"
docker exec ids-ml-api curl -s http://localhost:8000/openapi.json \
  | python3 -c '
import sys, json
spec = json.load(sys.stdin)
paths = spec.get("paths", {})
for p in ["/predict", "/predict/batch"]:
    if p in paths:
        post = paths[p].get("post", {})
        print(f">>> {p}")
        rb = post.get("requestBody", {}).get("content", {}).get("application/json", {})
        schema_ref = rb.get("schema", {}).get("$ref", "")
        print("schema_ref:", schema_ref)
        if schema_ref:
            name = schema_ref.split("/")[-1]
            s = spec.get("components", {}).get("schemas", {}).get(name, {})
            print("schema:", json.dumps(s, indent=2)[:800])
'

sec "2. /features (lista de features esperadas)"
docker exec ids-ml-api curl -s -H "X-API-Key: $API_KEY" http://localhost:8000/features 2>&1 | head -c 1000; echo

sec "3. POST /predict con muestra benigna (features=0)"
# Construir payload con features: dict de nombre->0
FEATURES_JSON=$(docker exec ids-ml-api curl -s -H "X-API-Key: $API_KEY" http://localhost:8000/features 2>/dev/null)
PAYLOAD=$(python3 -c "
import json
data = json.loads('''$FEATURES_JSON''')
# El endpoint puede devolver una lista de nombres, o un dict con 'features'
if isinstance(data, dict) and 'features' in data:
    names = data['features']
elif isinstance(data, list):
    names = data
else:
    names = list(data.keys()) if isinstance(data, dict) else []
payload = {'features': {n: 0.0 for n in names}}
print(json.dumps(payload))
" 2>/dev/null)

if [ -n "$PAYLOAD" ]; then
  echo "-- Payload tamano: ${#PAYLOAD} chars --"
  echo "$PAYLOAD" | head -c 300; echo
  docker exec -e PAYLOAD="$PAYLOAD" -e KEY="$API_KEY" ids-ml-api bash -c \
    'curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d "$PAYLOAD" http://localhost:8000/predict' | head -c 500; echo
else
  echo "No se pudo construir payload automaticamente. Intento manual..."
  docker exec -e KEY="$API_KEY" ids-ml-api bash -c \
    'curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d "{\"features\":{}}" http://localhost:8000/predict' | head -c 500; echo
fi

sec "4. /metrics ML API"
docker exec ids-ml-api curl -s -H "X-API-Key: $API_KEY" http://localhost:8000/metrics 2>&1 | head -c 500; echo

sec "5. /mitre (mapping)"
docker exec ids-ml-api curl -s -H "X-API-Key: $API_KEY" http://localhost:8000/mitre 2>&1 | head -c 500; echo

sec "6. Loki: job=ml_predictions?"
docker exec ids-loki wget -qO- 'http://localhost:3100/loki/api/v1/label/job/values' 2>&1
echo
docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
  'http://localhost:3100/loki/api/v1/query?query=%7Bjob%3D%22ml_predictions%22%7D&limit=5' 2>&1 | head -c 500; echo

sec "7. Promtail config completa (ver jobs ml_predictions)"
grep -A 30 'ml_predictions\|ml-api\|ml_api\|job_name' /home/operador/Laboratorio-MLCyber/configs/promtail/promtail-config.yml | head -60

sec "8. Interfaces candidatas para Suricata"
ip -br link
echo '-- Promisc posible en ens18? --'
cat /sys/class/net/ens18/operstate 2>&1
cat /sys/class/net/ens18/carrier 2>&1 | xargs -I{} echo "carrier={}"

echo; echo "===== FIN ====="

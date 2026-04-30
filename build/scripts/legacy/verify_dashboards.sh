#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
NET=laboratorio-mlcyber_ids_network
DVWA_IP=172.25.0.50
sec() { echo; echo "===== $* ====="; }

# Helper URL-encode: python3 inline
urlenc() { python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }

# Rango: ultimos 60 min en ns
NOW=$(date +%s)
START=$(( (NOW - 3600) * 1000000000 ))
END=$(( NOW * 1000000000 ))

query_range() {
  local q="$1"
  local enc=$(urlenc "$q")
  docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
    "http://localhost:3100/loki/api/v1/query_range?query=$enc&start=$START&end=$END&limit=100" 2>/dev/null
}

sec "1. Dispara otra ronda de captura (datos frescos para Grafana)"
# Lanzar ataques tipificados en el sensor para diversificar predicciones
curl -s -X POST http://localhost:9999/capture/start \
  -H 'Content-Type: application/json' \
  -d '{"duration":15,"attack_type":"flood","intensity":40,"inject_dataset":true}' | head -c 200; echo
echo 'esperando 25s...'
sleep 25

sec "2. Segunda ronda: scan"
curl -s -X POST http://localhost:9999/capture/start \
  -H 'Content-Type: application/json' \
  -d '{"duration":15,"attack_type":"scan","intensity":40,"inject_dataset":true}' | head -c 200; echo
sleep 25

sec "3. Tercera ronda: bruteforce"
curl -s -X POST http://localhost:9999/capture/start \
  -H 'Content-Type: application/json' \
  -d '{"duration":12,"attack_type":"bruteforce","intensity":40,"inject_dataset":true}' | head -c 200; echo
sleep 20

sec "4. Esperar a que termine el ultimo"
for i in $(seq 1 20); do
  ST=$(curl -s http://localhost:9999/capture/status | python3 -c 'import sys,json; print(json.loads(sys.stdin.read()).get("status","?"))' 2>/dev/null)
  printf '  i=%d st=%s\n' "$i" "$ST"
  [ "$ST" = "done" ] || [ "$ST" = "idle" ] && break
  sleep 4
done

sec "5. predictions.jsonl: conteos por categoria"
python3 <<PYEOF
import json, collections
cats = collections.Counter()
is_attack = collections.Counter()
with open('$PROJ/logs/sensor_predictions.jsonl') as f:
    for l in f:
        try:
            d = json.loads(l); cats[d.get('category','?')]+=1; is_attack[str(d.get('is_attack'))]+=1
        except: pass
print('Total lineas:', sum(cats.values()))
print('Categorias:', dict(cats))
print('is_attack:', dict(is_attack))
PYEOF

sec "6. eve.json: alert count"
grep -c '\"event_type\":\"alert\"' "$PROJ/logs/eve.json"
echo '-- top firmas --'
python3 <<PYEOF
import json, collections
sigs = collections.Counter()
with open('$PROJ/logs/eve.json') as f:
    for l in f:
        try:
            d = json.loads(l)
            if d.get('event_type')=='alert':
                sigs[d.get('alert',{}).get('signature','?')]+=1
        except: pass
for s,c in sigs.most_common(10):
    print(f'  {c}  {s[:80]}')
PYEOF

sec "7. Loki query: panel 'Alertas Suricata (rango)'"
query_range 'sum(count_over_time({job="suricata", event_type="alert"}[1h]))' | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); r=d.get("data",{}).get("result",[]); v=r[0].get("values",[])[-1] if r and r[0].get("values") else None; print("Alertas (query_range):", v[1] if v else "SIN DATOS")'

sec "8. Loki query: panel 'Flujos ATAQUE (ML)'"
query_range 'sum(count_over_time({job="ml_predictions", is_attack="true"}[1h]))' | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); r=d.get("data",{}).get("result",[]); v=r[0].get("values",[])[-1] if r and r[0].get("values") else None; print("Ataques ML:", v[1] if v else "SIN DATOS")'

sec "9. Loki query: panel 'Total flujos procesados ML'"
query_range 'sum(count_over_time({job="ml_predictions"}[1h]))' | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); r=d.get("data",{}).get("result",[]); v=r[0].get("values",[])[-1] if r and r[0].get("values") else None; print("Total ML:", v[1] if v else "SIN DATOS")'

sec "10. Loki query: panel 'Distribución ML por categoría'"
query_range 'sum by(category) (count_over_time({job="ml_predictions"}[1h]))' | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
for r in d.get("data",{}).get("result",[]):
    cat = r.get("metric",{}).get("category","?")
    vals = r.get("values",[])
    tot = sum(int(v[1]) for v in vals) if vals else 0
    print(f"  {cat}: {tot}")
'

sec "11. Loki query: panel 'Severidad Suricata'"
query_range 'sum by(alert_severity) (count_over_time({job="suricata", event_type="alert"}[1h]))' | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
for r in d.get("data",{}).get("result",[]):
    sev = r.get("metric",{}).get("alert_severity","?")
    vals = r.get("values",[])
    tot = sum(int(v[1]) for v in vals) if vals else 0
    print(f"  sev={sev}: {tot}")
'

sec "12. Loki query: Top 15 firmas"
query_range 'topk(15, sum by(alert_signature) (count_over_time({job="suricata", event_type="alert"} | json | alert_signature != "" [1h])))' | python3 -c '
import sys, json
d = json.loads(sys.stdin.read())
for r in d.get("data",{}).get("result",[])[:15]:
    sig = r.get("metric",{}).get("alert_signature","?")
    vals = r.get("values",[])
    tot = sum(int(float(v[1])) for v in vals) if vals else 0
    print(f"  {tot}  {sig[:70]}")
'

sec "13. Grafana: verificar dashboard provisioning y datasource uid"
docker exec ids-grafana wget -qO- --user admin --password "${GRAFANA_PASSWORD:-ids2026}" \
  http://localhost:3000/api/datasources 2>/dev/null | python3 -c 'import sys,json; ds=json.load(sys.stdin); [print(f"  name={x[\"name\"]} uid={x[\"uid\"]} type={x[\"type\"]} url={x[\"url\"]}") for x in ds]'

sec "14. Grafana: dashboards cargados"
docker exec ids-grafana wget -qO- --user admin --password "${GRAFANA_PASSWORD:-ids2026}" \
  'http://localhost:3000/api/search?type=dash-db' 2>/dev/null | python3 -c 'import sys,json; ds=json.load(sys.stdin); [print(f"  [{x[\"type\"]}] {x[\"title\"]} uid={x[\"uid\"]}") for x in ds]'

echo; echo "===== FIN ====="

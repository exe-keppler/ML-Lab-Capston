#!/usr/bin/env bash
set +e

section() { echo; echo "===== $* ====="; }

section "0. Contenedores corriendo"
docker ps --format 'table {{.Names}}\t{{.Status}}' | head -15

section "1. Grafana :3000 /api/health"
curl -sf -m 5 http://localhost:3000/api/health; echo

section "2. DVWA :8080"
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -m 5 http://localhost:8080/

section "3. Nginx proxy :80"
curl -s -o /dev/null -w 'HTTP %{http_code} (tiempo=%{time_total}s)\n' -m 5 http://localhost:80/

section "4. Jupyter :8888"
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -m 5 http://localhost:8888/

section "5. Sensor TCP :9999"
timeout 3 bash -c ': < /dev/tcp/localhost/9999' && echo "TCP 9999 abierto" || echo "TCP 9999 inalcanzable"

section "6. ML API endpoints"
for ep in / /health /docs /openapi.json /predict /ready /status; do
  code=$(docker exec ids-ml-api curl -s -o /dev/null -w '%{http_code}' -m 3 "http://localhost:8000$ep" 2>/dev/null)
  printf '  %-15s -> HTTP %s\n' "$ep" "$code"
done

section "6b. ML API /openapi.json (rutas)"
docker exec ids-ml-api curl -s -m 5 http://localhost:8000/openapi.json 2>/dev/null \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("title:",d.get("info",{}).get("title")); print("version:",d.get("info",{}).get("version")); print("paths:",list(d.get("paths",{}).keys()))' 2>&1 | head -20

section "6c. ML API /health respuesta"
docker exec ids-ml-api curl -s -m 5 http://localhost:8000/health 2>/dev/null || \
docker exec ids-ml-api wget -qO- http://localhost:8000/health 2>/dev/null

section "7. Loki /ready"
docker exec ids-loki wget -qO- http://localhost:3100/ready 2>&1 | head -3

section "8. Loki labels (ingesta activa)"
docker exec ids-loki wget -qO- 'http://localhost:3100/loki/api/v1/labels' 2>&1 | head -3

section "8b. Loki series por job (ultimos 15 min)"
END=$(date +%s)000000000
START=$(( $(date +%s) - 900 ))000000000
docker exec ids-loki wget -qO- "http://localhost:3100/loki/api/v1/label/job/values" 2>&1 | head -3

section "8c. Loki query_range: cualquier log ultimos 5 min"
docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
  "http://localhost:3100/loki/api/v1/query?query=%7Bjob%3D~%22.%2B%22%7D&limit=3" 2>&1 | head -c 500; echo

section "9. Suricata eve.json"
docker exec ids-suricata ls -lh /var/log/suricata/eve.json 2>&1
docker exec ids-suricata bash -c 'wc -l /var/log/suricata/eve.json 2>/dev/null || stat -c "%s bytes" /var/log/suricata/eve.json' 2>&1
echo '-- muestra (ultima linea, 300 chars) --'
docker exec ids-suricata bash -c 'tail -1 /var/log/suricata/eve.json 2>/dev/null' | head -c 300; echo

section "10. Promtail posiciones (lineas leidas por archivo)"
docker exec ids-promtail cat /tmp/positions.yaml 2>&1 | head -30

section "11. DVWA DB ping"
docker exec ids-dvwa-db mysqladmin -uroot -ppassword ping 2>&1 | tail -2

section "12. Modelos cargados en ml-api"
docker exec ids-ml-api ls -lh /app/models 2>&1 || docker exec ids-ml-api find / -name '*.joblib' 2>/dev/null | head -5

section "12b. ML API prueba de inferencia"
# Intentar varios payloads tipicos
echo '-- POST /predict con flow vacio --'
docker exec ids-ml-api curl -s -m 5 -X POST http://localhost:8000/predict \
  -H 'Content-Type: application/json' -d '{}' 2>&1 | head -c 400; echo
echo '-- POST /predict con features dummy --'
docker exec ids-ml-api curl -s -m 5 -X POST http://localhost:8000/predict \
  -H 'Content-Type: application/json' \
  -d '{"features":{"Flow Duration":100,"Total Fwd Packets":10,"Total Backward Packets":8}}' 2>&1 | head -c 400; echo

section "13. Pipeline end-to-end: generar evento -> ver en Loki"
# Generar una entrada obvia via curl al proxy (genera log nginx)
for i in 1 2 3; do curl -s -o /dev/null -m 3 "http://localhost:80/__pruebafuncional_$(date +%s)_$i" ; done
sleep 3
docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
  'http://localhost:3100/loki/api/v1/query?query=%7Bjob%3D~%22.%2B%22%7D%20%7C%3D%20%22__pruebafuncional%22&limit=5' 2>&1 | head -c 500; echo

section "14. Errores recientes por contenedor"
for c in ids-grafana ids-ml-api ids-sensor ids-promtail ids-suricata ids-loki ids-proxy ids-dashboard ids-dvwa ids-dvwa-db ids-jupyter; do
  n=$(docker logs --tail 200 "$c" 2>&1 | grep -ciE 'error|fatal|panic|traceback')
  w=$(docker logs --tail 200 "$c" 2>&1 | grep -ci warning)
  printf '  %-18s errores=%s warnings=%s\n' "$c" "$n" "$w"
done

section "15. Recursos"
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' | head -15

section "16. ML API log tail"
docker logs --tail 20 ids-ml-api 2>&1 | tail -20

echo; echo "===== FIN ====="

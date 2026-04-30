#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
NET=laboratorio-mlcyber_ids_network
DVWA_IP=172.25.0.50
sec() { echo; echo "===== $* ====="; }

API_KEY=$(grep '^IDS_API_KEY=' "$PROJ/.env" | cut -d= -f2-)

sec "1. Revertir Suricata a docker bridge br-d969b8da97d0"
# Backup nuevo
cp "$PROJ/.env" "$PROJ/.env.bak_$(date +%s)"
sed -i 's|^SURICATA_INTERFACE=.*$|SURICATA_INTERFACE=br-d969b8da97d0|' "$PROJ/.env"
grep SURICATA_INTERFACE "$PROJ/.env"

sec "2. Truncar eve.json y recreate suricata"
: > "$PROJ/logs/eve.json"
cd "$PROJ" && docker compose up -d --force-recreate --no-deps suricata 2>&1 | tail -5
sleep 12
echo '-- verificacion interfaz en suricata --'
docker logs --tail 100 ids-suricata 2>&1 | grep -iE 'af-packet|thread|engine started|runmodes' | tail -10

sec "3. Sensor /capture/start (attack_type=mixed, inject_dataset=true)"
# El sensor genera trafico + captura + inyecta flujos CICIDS -> escribe predictions.jsonl
RESP=$(curl -s -m 5 -X POST http://localhost:9999/capture/start \
  -H 'Content-Type: application/json' \
  -d '{"duration":25,"attack_type":"mixed","intensity":30,"inject_dataset":true}')
echo "$RESP"

sec "4. Lanzar ataques reales contra DVWA (en paralelo con captura sensor)"
# nmap - scan de puertos (dispara ET SCAN signatures)
docker run --rm -d --name ataque_nmap --network "$NET" instrumentisto/nmap \
  -sS -sV -T4 -p 20-100 --script=http-enum "$DVWA_IP" >/dev/null 2>&1 &

# Nikto scan - muchas signatures Web Attack
docker run --rm -d --name ataque_nikto --network "$NET" \
  sullo/nikto -h "http://$DVWA_IP" -maxtime 20 -Tuning 12 >/dev/null 2>&1 &

# Bruteforce de login (ET BRUTEFORCE)
docker run --rm -d --name ataque_brute --network "$NET" curlimages/curl:latest sh -c "
  for pw in admin password 123456 letmein qwerty root toor admin123 password123 dvwa; do
    curl -sS -o /dev/null -L -c /tmp/c -b /tmp/c \
      --data-urlencode \"username=admin\" --data-urlencode \"password=\$pw\" \
      --data-urlencode 'Login=Login' \"http://$DVWA_IP/login.php\" &
  done; wait; sleep 2
" >/dev/null 2>&1 &

echo 'Ataques lanzados en background. Esperando 30s para que terminen...'
sleep 30
echo '-- estado de ataques --'
docker ps --filter 'name=ataque_' --format '{{.Names}}: {{.Status}}'
docker ps -a --filter 'name=ataque_' --format '{{.Names}}: {{.Status}}' | head -5

sec "5. Estado sensor tras ventana"
curl -s http://localhost:9999/capture/status 2>&1 | head -c 300; echo
echo '-- logs sensor (ultimas 20) --'
docker logs --tail 20 ids-sensor 2>&1 | tail -20

sec "6. Archivos de logs generados"
ls -lh "$PROJ/logs/"

sec "7. Contenido de sensor_predictions.jsonl (ultimas 3)"
[ -f "$PROJ/logs/sensor_predictions.jsonl" ] && {
  wc -l "$PROJ/logs/sensor_predictions.jsonl"
  tail -3 "$PROJ/logs/sensor_predictions.jsonl" | head -c 600
  echo
} || echo 'NO EXISTE sensor_predictions.jsonl'

sec "8. eve.json: total eventos y alertas"
wc -l "$PROJ/logs/eve.json"
echo '-- conteo por event_type --'
python3 -c "
import json
counts = {}
with open('$PROJ/logs/eve.json') as f:
    for line in f:
        try:
            d = json.loads(line)
            t = d.get('event_type','?')
            counts[t] = counts.get(t,0)+1
        except: pass
for k,v in sorted(counts.items(), key=lambda x:-x[1]):
    print(f'  {k}: {v}')
"
echo '-- muestra alerta (si hay) --'
grep '\"event_type\":\"alert\"' "$PROJ/logs/eve.json" | head -1 | head -c 400; echo

sec "9. Loki: labels + jobs disponibles"
docker exec ids-loki wget -qO- http://localhost:3100/loki/api/v1/labels 2>/dev/null
echo
docker exec ids-loki wget -qO- http://localhost:3100/loki/api/v1/label/job/values 2>/dev/null

sec "10. Loki metrics"
docker exec ids-loki wget -qO- http://localhost:3100/metrics 2>/dev/null | grep -E 'loki_distributor_lines_received_total|loki_ingester_streams_created_total' | head -5

sec "11. Loki: alertas Suricata?"
docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
  'http://localhost:3100/loki/api/v1/query?query=%7Bjob%3D%22suricata%22%2C%20event_type%3D%22alert%22%7D&limit=3' 2>/dev/null | head -c 500
echo

sec "12. Loki: predicciones ML?"
docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
  'http://localhost:3100/loki/api/v1/query?query=%7Bjob%3D%22ml_predictions%22%7D&limit=3' 2>/dev/null | head -c 500
echo

echo; echo "===== FIN ====="

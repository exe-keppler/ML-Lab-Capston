#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
sec() { echo; echo "===== $* ====="; }

API_KEY=$(grep '^IDS_API_KEY=' "$PROJ/.env" | cut -d= -f2-)

############################
# PARTE 1: Test inferencia #
############################
sec "1. /predict baseline (47 ceros)"
PAYLOAD='{"features":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}'
docker exec -e K="$API_KEY" -e P="$PAYLOAD" ids-ml-api \
  bash -c 'curl -s -X POST -H "X-API-Key: $K" -H "Content-Type: application/json" -d "$P" http://localhost:8000/predict'
echo

sec "2. /predict patron DDoS-like"
PAYLOAD='{"features":[100,1000,5,50000,300,500,50,100.5,60,60,60,5,500000,10000,0.1,0.05,1,0,0.1,0.05,0,0,0,0,0,0,0,0,200,50,500,150,80,6400,0,1,50,50,0,0.1,50,20,10,5,20,5,10]}'
docker exec -e K="$API_KEY" -e P="$PAYLOAD" ids-ml-api \
  bash -c 'curl -s -X POST -H "X-API-Key: $K" -H "Content-Type: application/json" -d "$P" http://localhost:8000/predict'
echo

sec "3. /predict/batch 3 flows"
PAYLOAD='{"flows":[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[100,1000,5,50000,300,500,50,100.5,60,60,60,5,500000,10000,0.1,0.05,1,0,0.1,0.05,0,0,0,0,0,0,0,0,200,50,500,150,80,6400,0,1,50,50,0,0.1,50,20,10,5,20,5,10],[500,10,5,1000,500,100,20,50,100,50,75,15,2000,15,33,10,50,20,40,15,10,100,50,20,80,10,0,0,10,40,150,95,30,900,0,0,5,15,0,0.5,10,20,5,2,8,3,5]]}'
docker exec -e K="$API_KEY" -e P="$PAYLOAD" ids-ml-api \
  bash -c 'curl -s -X POST -H "X-API-Key: $K" -H "Content-Type: application/json" -d "$P" http://localhost:8000/predict/batch' | head -c 800
echo

###########################
# PARTE 2: Fix Suricata  #
###########################
sec "4. Estado previo docker-compose (linea eth0)"
grep -n 'eth0\|SURICATA_INTERFACE' "$PROJ/docker-compose.yml" "$PROJ/.env"

sec "5. Backup + Parche docker-compose + .env"
cp "$PROJ/docker-compose.yml" "$PROJ/docker-compose.yml.bak_$(date +%s)"
cp "$PROJ/.env" "$PROJ/.env.bak_$(date +%s)"

# Parche 1: reemplazar '-i', 'eth0' por '-i', '${SURICATA_INTERFACE}' en el command de suricata
sed -i 's|"-i", "eth0"|"-i", "${SURICATA_INTERFACE}"|' "$PROJ/docker-compose.yml"

# Parche 2: .env -> interfaz real ens18
sed -i 's|^SURICATA_INTERFACE=.*$|SURICATA_INTERFACE=ens18|' "$PROJ/.env"

echo '-- verificacion del parche --'
grep -n 'SURICATA_INTERFACE\|"-i"' "$PROJ/docker-compose.yml" "$PROJ/.env"

sec "6. Truncar logs viejos y restart suricata (recreate para tomar nuevo command)"
: > "$PROJ/logs/eve.json"
: > "$PROJ/logs/suricata.log"
cd "$PROJ" && docker compose up -d --force-recreate --no-deps suricata 2>&1 | tail -10

echo '-- esperando 10s para que Suricata arranque --'
sleep 10
echo '-- logs de Suricata tras restart --'
docker logs --tail 20 ids-suricata 2>&1 | tail -20

sec "7. Verificacion: eve.json ahora?"
ls -lh "$PROJ/logs/eve.json"
echo '-- tamano en bytes --'
stat -c '%s bytes' "$PROJ/logs/eve.json"

sec "8. Generar trafico visible por ens18 (curl externo al DVWA)"
# ens18 es la NIC fisica del host. Traffic desde el mismo host al puerto expuesto :8080 pasa por ens18.
for i in 1 2 3 4 5; do
  curl -s -o /dev/null "http://192.168.0.126:8080/?test_pipeline=$i" &
done
# tambien un barrido que suricata deberia ver
for i in 1 2 3; do
  curl -s -o /dev/null -m 2 "http://192.168.0.126/admin" &
  curl -s -o /dev/null -m 2 "http://192.168.0.126/../../../etc/passwd" &
  curl -s -o /dev/null -m 2 "http://192.168.0.126/?cmd=cat+/etc/shadow" &
done
wait
sleep 5

sec "9. eve.json tras trafico"
wc -l "$PROJ/logs/eve.json"
echo '-- ultimos 2 eventos --'
tail -2 "$PROJ/logs/eve.json" | head -c 600
echo

sec "10. Promtail lee el archivo ahora?"
docker exec ids-promtail cat /tmp/positions.yaml 2>&1 | head -5

sec "11. Loki recibe logs?"
docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
  'http://localhost:3100/loki/api/v1/query?query=%7Bjob%3D%22suricata%22%7D&limit=3' 2>&1 | head -c 500
echo
docker exec ids-loki wget -qO- http://localhost:3100/metrics 2>/dev/null \
  | grep 'loki_ingester_streams_created_total' | head -3

sec "12. Estado final contenedores"
docker ps --format 'table {{.Names}}\t{{.Status}}'

echo; echo "===== FIN ====="

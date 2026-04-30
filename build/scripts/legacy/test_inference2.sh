#!/usr/bin/env bash
set +e
sec() { echo; echo "===== $* ====="; }

ENV_FILE=/home/operador/Laboratorio-MLCyber/.env
API_KEY=$(grep '^IDS_API_KEY=' "$ENV_FILE" | cut -d= -f2-)

sec "1. /predict con 47 floats (baseline ceros - esperado: Benign)"
PAYLOAD_ZEROS='{"features":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}'
docker exec -e KEY="$API_KEY" -e P="$PAYLOAD_ZEROS" ids-ml-api \
  bash -c 'curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d "$P" http://localhost:8000/predict'
echo

sec "2. /predict con valores altos tipicos de DDoS (flujo corto y masivo)"
# Flow Duration pequeno, muchos packets, bytes altos
PAYLOAD_DDOS='{"features":[100,1000,5,50000,300,500,50,100.5,60,60,60,5,500000,10000,0.1,0.05,1,0,0.1,0.05,0,0,0,0,0,0,0,0,200,50,500,150,80,6400,0,1,50,50,0,0.1,50,20,10,5,20,5,10]}'
docker exec -e KEY="$API_KEY" -e P="$PAYLOAD_DDOS" ids-ml-api \
  bash -c 'curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d "$P" http://localhost:8000/predict'
echo

sec "3. /predict/batch (3 flows)"
PAYLOAD_BATCH='{"flows":[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],[100,1000,5,50000,300,500,50,100.5,60,60,60,5,500000,10000,0.1,0.05,1,0,0.1,0.05,0,0,0,0,0,0,0,0,200,50,500,150,80,6400,0,1,50,50,0,0.1,50,20,10,5,20,5,10],[500,10,5,1000,500,100,20,50,100,50,75,15,2000,15,33,10,50,20,40,15,10,100,50,20,80,10,0,0,10,40,150,95,30,900,0,0,5,15,0,0.5,10,20,5,2,8,3,5]]}'
docker exec -e KEY="$API_KEY" -e P="$PAYLOAD_BATCH" ids-ml-api \
  bash -c 'curl -s -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d "$P" http://localhost:8000/predict/batch' | head -c 800
echo

sec "4. Sensor: que archivos de logs escribe?"
docker exec ids-sensor ls -la /app/logs 2>/dev/null || docker exec ids-sensor ls -la /logs 2>&1
echo '-- volumes --'
docker inspect ids-sensor --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'
echo '-- sensor logs (tail) --'
docker logs --tail 15 ids-sensor 2>&1

sec "5. Archivo sensor_predictions.jsonl en el host"
ls -la /home/operador/Laboratorio-MLCyber/logs/ 2>&1

sec "6. Generar prediccion via sensor para que escriba log"
# El sensor escucha TCP:9999; ver si acepta un flow serializado
echo '-- enviando paquete TCP al sensor --'
echo '{"test":"functional"}' | timeout 3 nc localhost 9999 2>&1
sleep 2
echo '-- sensor logs tras envio --'
docker logs --tail 10 ids-sensor 2>&1

sec "7. Loki: label values por stream"
docker exec ids-loki wget -qO- 'http://localhost:3100/loki/api/v1/label/job/values' 2>&1
echo

sec "8. Forzar write test en eve.json (comprobar que promtail lo ve)"
echo '{"timestamp":"2026-04-24T01:30:00.000000+0000","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","alert":{"signature":"PRUEBA_FUNCIONAL","category":"Test","severity":3,"gid":1,"signature_id":99999}}' >> /home/operador/Laboratorio-MLCyber/logs/eve.json
echo "escrito, esperando 10s para que promtail lo envie a loki..."
sleep 10
echo '-- promtail posiciones --'
docker exec ids-promtail cat /tmp/positions.yaml 2>&1 | head -5
echo '-- loki query PRUEBA_FUNCIONAL --'
docker exec ids-loki wget -qO- --header 'Content-Type: application/json' \
  'http://localhost:3100/loki/api/v1/query?query=%7Bjob%3D%22suricata%22%7D%20%7C%3D%20%22PRUEBA_FUNCIONAL%22&limit=3' 2>&1 | head -c 600
echo

echo; echo "===== FIN ====="

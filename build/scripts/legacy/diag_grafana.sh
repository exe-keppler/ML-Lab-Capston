#!/usr/bin/env bash
set +e
PROJ=/home/operador/Laboratorio-MLCyber
sec() { echo; echo "===== $* ====="; }

sec "A. Queries usadas por los dashboards"
for f in "$PROJ"/configs/grafana/dashboards/*.json; do
  echo "--- $(basename $f) ---"
  python3 -c "
import json,sys
with open('$f') as x: d=json.load(x)
for p in d.get('panels',[]):
    t=p.get('title','(no title)')
    for tg in p.get('targets',[]):
        ex=tg.get('expr','')
        if ex: print(f'  [{t}] {ex[:160]}')
"
done

sec "B. Datasource Grafana"
cat "$PROJ/configs/grafana/provisioning/datasources/loki.yml" 2>&1

sec "C. Grafana -> ping a Loki"
docker exec ids-grafana wget -qO- http://loki:3100/ready 2>&1 | head -3
docker exec ids-grafana wget -qO- http://loki:3100/loki/api/v1/labels 2>&1 | head -3

sec "D. Sensor: que escribe y donde"
docker exec ids-sensor ls -la /app/logs /logs 2>&1 | head -20
echo '-- sensor_predictions.jsonl en el host --'
ls -la "$PROJ/logs/" | grep -E 'sensor|predict|lab_history'
echo '-- logs recientes del sensor --'
docker logs --tail 25 ids-sensor 2>&1 | tail -25

sec "E. Sensor: que interfaz captura? como genera flows?"
docker inspect ids-sensor --format '{{json .Config.Env}}' 2>&1 | python3 -c "import json,sys; [print(e) for e in json.loads(sys.stdin.read())]" | grep -iE 'capture|interface|api|ml|log'
echo '-- comando del sensor --'
docker inspect ids-sensor --format '{{.Config.Cmd}} {{.Config.Entrypoint}}'
echo '-- net mode --'
docker inspect ids-sensor --format '{{.HostConfig.NetworkMode}}'

sec "F. Promtail scrape config (todos los jobs)"
grep -E 'job_name|__path__' "$PROJ/configs/promtail/promtail-config.yml"

sec "G. Paths esperados por promtail existen?"
for p in /logs/eve.json /logs/sensor_predictions.jsonl /logs/lab_history.jsonl; do
  ls -la "$PROJ$p" 2>&1
done

sec "H. Archivos en logs/ (todos)"
ls -la "$PROJ/logs/" 2>&1

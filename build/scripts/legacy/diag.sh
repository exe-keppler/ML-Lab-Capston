#!/usr/bin/env bash
set +e

sec() { echo; echo "===== $* ====="; }

sec "A. .env (claves del stack)"
# Solo mostrar claves, no valores completos
grep -E '^[A-Z_]+=' /home/operador/Laboratorio-MLCyber/.env 2>/dev/null | sed 's/\(=.\{0,8\}\).*/\1…(oculto)/'

sec "B. Suricata config interfaz y logs"
docker exec ids-suricata bash -c 'grep -E "^\s*-\s*interface|community-id|runmode" /etc/suricata/suricata.yaml 2>/dev/null | head -10'
echo "-- Suricata logs ultimas 30 lineas --"
docker logs --tail 30 ids-suricata 2>&1 | tail -30

sec "C. Suricata ls log dir"
docker exec ids-suricata ls -la /var/log/suricata/ 2>&1

sec "D. Suricata interfaces disponibles"
docker exec ids-suricata ip -br link 2>&1 | head -10
docker exec ids-suricata bash -c 'suricata --list-runmodes 2>&1 | head -5'

sec "E. Compose: configuracion de red de Suricata"
grep -A 12 'suricata:' /home/operador/Laboratorio-MLCyber/docker-compose.yml | head -30

sec "F. Promtail config"
cat /home/operador/Laboratorio-MLCyber/configs/promtail/promtail-config.yml 2>&1 | head -40

sec "G. Loki ultimas 40 lineas logs"
docker logs --tail 40 ids-loki 2>&1 | tail -40

sec "H. Loki metrics (eventos ingresados)"
docker exec ids-loki wget -qO- http://localhost:3100/metrics 2>/dev/null | grep -E 'loki_distributor_bytes_received_total|loki_distributor_lines_received_total|loki_ingester_streams_created_total' | head -10

sec "I. ids-proxy errores"
docker logs --tail 20 ids-proxy 2>&1 | tail -20

sec "J. ids-dvwa errores"
docker logs --tail 20 ids-dvwa 2>&1 | tail -20

sec "K. Promtail logs (ultimas 30)"
docker logs --tail 30 ids-promtail 2>&1 | tail -30

sec "L. Volumes montados en Suricata"
docker inspect ids-suricata --format '{{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Type}}){{"\n"}}{{end}}' 2>&1

sec "M. Volumes montados en Promtail"
docker inspect ids-promtail --format '{{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Type}}){{"\n"}}{{end}}' 2>&1

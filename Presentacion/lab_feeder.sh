#!/usr/bin/env bash
# lab_feeder.sh — corre indefinidamente generando capturas con params
# random para alimentar de data continua a los dashboards SOC.
#
# Lanzar:
#   nohup bash /tmp/lab_feeder.sh > /tmp/lab_feeder.log 2>&1 &
#
# Detener:
#   pkill -f lab_feeder.sh
set +e

SENSOR=http://localhost:9999
LOG=${LAB_FEEDER_LOG:-/tmp/lab_feeder.log}

# Tipos de captura. Pesos: scan, mixed y bruteforce más frecuentes
# para que predominen ataques (vs benign).
TYPES=(scan scan flood mixed mixed bruteforce normal)
INTENSITIES=(40 50 60 70 80)
DURATIONS=(8 10 12 15 18)

# Sleeps entre capturas (segundos). Mezcla cortos y medios.
SLEEPS=(30 45 60 90 120 180)

iter=0
while true; do
    iter=$((iter + 1))

    type=${TYPES[$((RANDOM % ${#TYPES[@]}))]}
    intens=${INTENSITIES[$((RANDOM % ${#INTENSITIES[@]}))]}
    dur=${DURATIONS[$((RANDOM % ${#DURATIONS[@]}))]}
    sleep_s=${SLEEPS[$((RANDOM % ${#SLEEPS[@]}))]}

    echo "[$(date +'%H:%M:%S')] iter=$iter capture: type=$type intensity=$intens dur=${dur}s — siguiente en ${sleep_s}s"

    # Disparar captura
    resp=$(curl -s -X POST "$SENSOR/capture/start" \
        -H 'Content-Type: application/json' \
        -d "{\"duration\":$dur,\"attack_type\":\"$type\",\"intensity\":$intens,\"inject_dataset\":true}" \
        --max-time 5)
    echo "    resp: ${resp:0:150}"

    # Esperar la duración del capture + buffer
    sleep $((dur + 8))

    # Sleep adicional random antes del próximo
    sleep "$sleep_s"
done

FROM python:3.12-slim

LABEL description="IDS-ML Sensor: CICFlowMeter + request_id + correlacion 5-tupla"

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    tcpdump tshark libpcap-dev gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

RUN mkdir -p /app/logs

ENV PYTHONPATH=/app/src
ENV API_URL=http://ml_api:8000
ENV CAPTURE_INTERFACE=eth0
ENV TARGET_IP=172.25.0.50
ENV LOGS_DIR=/app/logs

# Nota: corre como root porque scapy requiere raw sockets.
# Hardening: cap_drop ALL + cap_add NET_ADMIN/NET_RAW + no-new-privileges en compose.

EXPOSE 9999

CMD ["python3", "src/sensor_server.py"]

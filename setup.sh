#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# Laboratorio IDS-ML + Cybersecurity — deploy en un comando
# Maestría en IA Aplicada — UDLA 2026
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RESET='\033[0m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'

say()  { printf "${BLUE}▸${RESET} %s\n" "$*"; }
ok()   { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}!${RESET} %s\n" "$*"; }
fail() { printf "${RED}✗${RESET} %s\n" "$*"; exit 1; }

printf "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}║  Laboratorio IDS-ML Lab UDLA — setup                         ║${RESET}\n"
printf "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}\n"

# ─────────────────────────────────────────────────────────────
# 1. Dependencias
# ─────────────────────────────────────────────────────────────
say "Verificando Docker..."
command -v docker >/dev/null 2>&1 || fail "Docker no instalado. https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || fail "Docker daemon no accesible (¿grupo docker o permisos?)."
ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

say "Verificando docker compose..."
docker compose version >/dev/null 2>&1 || fail "Plugin 'docker compose' no disponible."
ok "$(docker compose version --short 2>/dev/null || echo 'v2')"

say "Verificando openssl (para hash htpasswd)..."
command -v openssl >/dev/null 2>&1 || fail "openssl requerido para generar htpasswd."
ok "openssl disponible"

# ─────────────────────────────────────────────────────────────
# 2. .env
# ─────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        ok ".env creado desde .env.example"
        warn "Revisa .env y cambia las credenciales por defecto antes de producción."
    else
        fail "No existe .env ni .env.example"
    fi
else
    ok ".env existente — se reutiliza"
fi

set -a; . ./.env; set +a

# ─────────────────────────────────────────────────────────────
# 3. htpasswd para nginx
# ─────────────────────────────────────────────────────────────
HTPASSWD_FILE="configs/nginx/htpasswd"
if [ ! -f "$HTPASSWD_FILE" ]; then
    say "Generando $HTPASSWD_FILE..."
    HASH=$(openssl passwd -apr1 "$NGINX_PASSWORD")
    printf "%s:%s\n" "$NGINX_USER" "$HASH" > "$HTPASSWD_FILE"
    ok "htpasswd generado para usuario '$NGINX_USER'"
else
    ok "htpasswd existente — se reutiliza"
fi

# ─────────────────────────────────────────────────────────────
# 4. Detectar interfaz para Suricata
# ─────────────────────────────────────────────────────────────
# Estrategia: pre-crear la red 'ids_network' (nombre fijo en el compose
# vía 'name: ids_network'), inspeccionar el bridge ID y exportarlo a .env.
# El compose lee ${SURICATA_INTERFACE} del .env en runtime — sin sed.

if [ -z "${SURICATA_INTERFACE:-}" ]; then
    say "Detectando interfaz para Suricata..."

    if ! docker network inspect ids_network >/dev/null 2>&1; then
        docker network create \
            --driver bridge \
            --subnet 172.25.0.0/24 \
            ids_network >/dev/null
        ok "Red docker 'ids_network' creada"
    else
        ok "Red docker 'ids_network' ya existe — se reutiliza"
    fi

    BRIDGE_ID=$(docker network inspect ids_network -f '{{ .Id }}' 2>/dev/null | cut -c1-12)

    if [ -n "$BRIDGE_ID" ]; then
        SURICATA_INTERFACE="br-$BRIDGE_ID"
        ok "Bridge docker detectado: $SURICATA_INTERFACE"
    else
        # Fallback: primera NIC física no-loopback / no-docker / no-veth.
        SURICATA_INTERFACE=$(ip -o link show 2>/dev/null \
            | awk -F': ' '$2 !~ /^(lo|docker|br-|veth|virbr)/ {print $2; exit}')
        SURICATA_INTERFACE="${SURICATA_INTERFACE:-eth0}"
        warn "No se detectó bridge docker; usando interfaz física '$SURICATA_INTERFACE'."
        warn "Suricata verá tráfico host pero NO el container-to-container del lab."
    fi

    # Persistir en .env
    if grep -q '^SURICATA_INTERFACE=' .env; then
        sed -i.bak "s|^SURICATA_INTERFACE=.*|SURICATA_INTERFACE=$SURICATA_INTERFACE|" .env && rm -f .env.bak
    else
        echo "SURICATA_INTERFACE=$SURICATA_INTERFACE" >> .env
    fi
else
    ok "SURICATA_INTERFACE ya definido en .env: $SURICATA_INTERFACE"
fi

# Re-exportar para que 'docker compose' vea el valor actualizado
# (el primer 'source .env' pudo haber leído un valor vacío).
export SURICATA_INTERFACE

# ─────────────────────────────────────────────────────────────
# 5. Directorios runtime
# ─────────────────────────────────────────────────────────────
mkdir -p logs datasets
chmod 777 logs    # Suricata corre como root y sensor/dashboard escriben JSONL
ok "logs/ y datasets/ creados"

# ─────────────────────────────────────────────────────────────
# 6. Build + up
# ─────────────────────────────────────────────────────────────
say "Construyendo imágenes Docker (primera vez tarda 3-5 min)..."
docker compose build --parallel

say "Levantando stack..."
docker compose up -d

# ─────────────────────────────────────────────────────────────
# 7. Esperar healthchecks
# ─────────────────────────────────────────────────────────────
say "Esperando healthchecks..."
for i in $(seq 1 60); do
    sleep 2
    STATUS=$(docker compose ps --format json 2>/dev/null | grep -c '"Health":"healthy"' || true)
    if [ "$STATUS" -ge 2 ]; then
        ok "Servicios saludables"
        break
    fi
    if [ "$i" -eq 60 ]; then
        warn "Timeout esperando healthchecks — revisa con 'docker compose logs'"
    fi
done

# ─────────────────────────────────────────────────────────────
# 8. URLs de acceso
# ─────────────────────────────────────────────────────────────
IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

printf "\n${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${BOLD}║  ${GREEN}STACK LEVANTADO${RESET}${BOLD}                                            ║${RESET}\n"
printf "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}\n"

cat <<EOF

  Dashboard (Streamlit):  ${BOLD}http://${IP}/${RESET}
    Usuario: ${NGINX_USER}  |  Password: ${NGINX_PASSWORD}

  JupyterLab:             ${BOLD}http://${IP}:8888/lab?token=${JUPYTER_TOKEN}${RESET}

  ML API (directo):       ${BOLD}http://${IP}:8000/health${RESET}
    Header: X-API-Key: ${IDS_API_KEY}

  Sensor (capturas):      ${BOLD}http://${IP}:9999/health${RESET}

  Útiles:
    docker compose logs -f <servicio>
    docker compose down            # parar stack
    docker compose up -d           # reiniciar

EOF

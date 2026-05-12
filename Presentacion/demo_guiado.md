# Demo guiado — Laboratorio IDS-ML

Guion paso a paso para una demo en vivo de **~10-15 minutos**. Cada
sección tiene comandos exactos, qué señalar, y qué pregunta responde.

> **Pre-requisito**: el lab debe estar levantado en `192.168.122.10`.
> Si no, ejecutar antes de empezar:
> ```
> ssh operador@192.168.122.10
> cd ~/ML-Lab-Capston && sudo bash setup.sh
> ```

---

## Setup de la demo (antes de la clase)

Tener abiertas 4 pestañas en el navegador:

1. **Streamlit Dashboard**: `http://192.168.122.10/`
   - User: `lab` / Pass: `ids2026`
2. **Grafana Suricata SOC**: `http://192.168.122.10:3000/d/soc-suricata`
3. **Grafana RF v2 SOC**: `http://192.168.122.10:3000/d/soc-rf-v2`
4. **Grafana XGBoost v2 SOC**: `http://192.168.122.10:3000/d/soc-xgb-v2`
   - Para Grafana: `admin` / `ids2026`

Tener en una terminal SSH abierta a `operador@192.168.122.10`.

---

## Paso 1 — La promesa: deploy reproducible (1 min)

**Objetivo**: mostrar que el lab arranca con un solo comando.

```bash
# En el server
cd ~/ML-Lab-Capston
git log -1 --oneline
docker compose ps
```

**Qué señalar**:
- 11 contenedores up (ml_api, dashboard, sensor, jupyter, suricata, dvwa,
  loki, promtail, grafana, dvwa-db, proxy).
- `ids-ml-api` y `ids-suricata` con estado `healthy`.

**Frase clave**: *"git clone + 47 segundos de setup.sh y todo esto está corriendo."*

---

## Paso 2 — El modelo activo (1 min)

```bash
docker exec ids-ml-api curl -s http://localhost:8000/health | python3 -m json.tool
```

**Salida esperada**:
```json
{
  "status": "ok",
  "version": "3.0.0",
  "model": "v2",
  "n_features": 47,
  "categories": ["Benign", "Brute Force", "DDoS", "DoS",
                 "Reconnaissance", "Web Attack"],
  "integrity": "verified",
  "available_models": ["rf", "xgb"]
}
```

**Qué señalar**:
- `"model": "v2"` → la versión activa.
- `"integrity": "verified"` → SHA-256 de los joblibs validó contra `manifest.json`.
- `"available_models": ["rf", "xgb"]` → dual-model.

---

## Paso 3 — Streamlit, recorrido en orden (4 min)

Abrir tab `http://192.168.122.10/`.

### Tab 1 — Intro (15s)
*"Esta es la página de bienvenida. Links a todos los servicios, glosario."*

### Tab 2 — Dataset (30s)
*"CICIDS2017 balanceado a 6 categorías. 12K muestras del repo, las usamos para todo lo en-vivo."*

Mostrar:
- Pie chart de las 6 clases (igualadas).
- Histograma de una feature (ej. `Flow_Duration`).
- Heatmap de correlaciones top-10.

### Tab 3 — Métricas (1 min)
*"Esta tab calcula la matriz de confusión EN VIVO contra el ML API."*

Click en **Recalcular matriz de confusión**.

Mostrar:
- F1-weighted binary 0.995 — el modelo distingue ataque/benigno casi perfecto.
- F1-macro multi 0.66 — saber **qué tipo** de ataque es más difícil.
- **Comparativa RF v2 vs XGBoost v2** abajo: ambos cerca pero RF gana por ~0.02.

**Frase clave**: *"Boosting no siempre supera a bagging. Depende del dataset."*

### Tab 4 — Predicción + SHAP (2 min)
*"Vamos a clasificar UN flujo y ver POR QUÉ el modelo decidió eso."*

1. Click **Reconnaissance** en los presets de clase.
2. Selector de modelo: dejar **RF**.
3. Click **Clasificar con el modelo v2 (RF)**.
4. Mostrar:
   - Resultado: `ATAQUE detectado — categoría: Reconnaissance` con confidence ~99%.
   - **MITRE mapping**: TA0007 Discovery, T1046 Network Service Scanning.
   - **SHAP bar chart** con barras rojas (a favor) y azules (en contra):
     - `Fwd_IAT_Std` rojo grande → la varianza de IAT empuja MÁS hacia Reconnaissance.
     - `PSH_Flag_Count` azul → empuja en contra (este flujo no tiene PSH).
5. Cambiar selector a **XGBoost**, click clasificar otra vez.
6. Comparar: ¿el SHAP es similar? ¿Qué features predominan en cada modelo?

**Frase clave**: *"El SOC analyst no solo recibe 'es Reconnaissance' — recibe POR QUÉ. Eso es la diferencia entre un detector útil y una caja negra."*

---

## Paso 4 — Lanzar una captura real (2 min)

Volver a la **Tab 5 — Ataques simulados**.

Click en **scan** con intensidad 80, duración 15s, **inject_dataset ON**.

Esperar ~25s. Mientras corre, explicar:

*"El sensor está usando CICFlowMeter para extraer features del tráfico real
contra DVWA. Después llama al API DOS VECES — una con `?model=rf`, otra con
`?model=xgb`. Cada predicción queda taggeada con el modelo en
`sensor_predictions.jsonl`."*

Cuando termine: refrescar la **Tab 6 — Suricata vs ML**.

Mostrar:
- KPIs: total flujos, ambos detectan, solo ML, solo Suricata, agreement %.
- Tabla flow-a-alert con la 5-tupla, ML categoría, signature Suricata.
- 4 veredictos posibles.

**Frase clave**: *"Cuando los dos coinciden, alta confianza. Cuando uno
detecta solo, ahí está la conversación SOC interesante."*

---

## Paso 5 — Grafana SOC enterprise (3 min)

Abrir las 3 pestañas de Grafana en orden:

### SOC Suricata
*"Vista para un analista que confía en firmas."*
- Tasa de alertas / minuto.
- Top 15 firmas (ej. `ET SCAN Possible Nmap User-Agent Observed`).
- Top src_ip / dest_ip flagged.
- Stream en vivo con la última alerta.

### SOC RF v2
*"Vista para un analista que confía en el RF."*
- Predicciones por minuto separadas en attack vs benign.
- Distribución de categorías (pie).
- Top src_ip flagged como ataque.
- Tasa de ataque % con thresholds (verde/amarillo/rojo).

### SOC XGBoost v2
*"Mismo SOC pero filtrando por XGBoost. Ejercicio: ¿coincide con RF?"*

**Frase clave**: *"3 detectores corren en paralelo sobre el mismo tráfico.
El SOC enterprise no apuesta a uno solo — los compara."*

---

## Paso 6 — La fragilidad honesta (2 min)

Volver al server, abrir el **notebook 07** o mostrar el resultado:

```bash
docker exec ids-jupyter cat /home/app/notebooks/07_adversarial_evasion.ipynb \
  | python3 -c "import json,sys; nb=json.load(sys.stdin); print([o for c in nb['cells'] for o in c.get('outputs',[]) if 'text' in o][-1]['text'][:500])"
```

O mostrar la conclusión del notebook 07 directamente:

```
RF v2:        evasión total 100% (24/24), benign 87.5%, L2 mediano 2.63
XGBoost v2:   evasión total 100% (25/25), benign 76%,   L2 mediano 2.67
```

**Frase clave**:
*"F1-macro 0.99 NO ES seguridad. Un atacante adaptativo evade ambos modelos
con perturbaciones mínimas. Esa es la razón por la que Suricata sigue
existiendo — sus firmas no se evaden con cambios en feature space."*

*"Pero ojo — esto es feature-space adversarial, no problem-space. Para un
ataque real el atacante tiene que generar tráfico distinto, lo cual es
mucho más difícil. Lo dejo como trabajo futuro en el repo."*

---

## Paso 7 — Cierre con el repo (30s)

Mostrar GitHub:

```
github.com/exe-keppler/ML-Lab-Capston
```

- 8 notebooks ejecutados con outputs visibles.
- README completo.
- `setup.sh` portable.
- Modelo + manifest verificable por SHA-256.

**Frase final**:
*"Este repo es una **línea base**. Cualquier extensión —SMOTE, stacking,
modelo no supervisado, defensas adversariales, problem-space attacks—
arranca con git clone y un notebook. Los invito a hacer fork."*

---

## Paso 8 (opcional, avanzado) — Tráfico externo: nmap desde la laptop del estudiante

**Objetivo pedagógico**: mostrar la diferencia arquitectónica entre un IDS
host-mode (Suricata) y un detector ML in-network (sensor del lab), y cómo
se complementan en un SOC.

### Pre-requisito: que Suricata vea la NIC física

Por default Suricata escucha el bridge docker (`br-XXXXXXXX`), así que NO
ve nada que entre por la NIC física del host. Para esta demo cambiá la
interfaz a la NIC física del server (`ens33`, `eth0`, etc.):

```bash
# En el server, detectar la NIC física
NIC=$(ip -o link show | awk -F': ' '$2 !~ /^(lo|docker|br-|veth|virbr)/ {print $2; exit}')
echo "NIC física: $NIC"

# Editar .env y recrear suricata
sudo sed -i "s|^SURICATA_INTERFACE=.*|SURICATA_INTERFACE=$NIC|" .env
sudo docker compose up -d --force-recreate suricata
sudo docker logs --tail 10 ids-suricata   # debe decir "Engine started"
```

> ⚠️ **NO usar `SURICATA_INTERFACE=any`** — AF_PACKET no lo soporta y el
> container entra en loop de reinicio (`af-packet: any: failed to find
> interface`). `setup.sh` ahora lo detecta y lo sobrescribe al bridge.

Para volver al default después de la demo, dejar `SURICATA_INTERFACE=` vacío
y correr `setup.sh` o `docker compose up -d suricata` otra vez.

### Workflow (3 pasos)

**Paso 1 — Estudiante lanza nmap desde su laptop**:

```bash
# Desde la laptop del estudiante (no desde el server)
nmap -sS -p 1-1000 192.168.122.10
```

**Paso 2 — Verificar que Suricata detectó**:

Abrir `http://192.168.122.10:3000/d/soc-suricata`. En el panel **Top firmas**
buscar entradas tipo `ET SCAN Possible Nmap User-Agent` o `ET POLICY Suspicious
inbound to mySQL`. La IP origen del estudiante aparece en **Top src_ip flagged**.

**Paso 3 — Reproducir el mismo TIPO de ataque internamente para que el ML lo clasifique**:

```bash
# Desde el server, simular el scan dentro del lab
curl -X POST http://192.168.122.10:9999/capture/start \
  -H "Content-Type: application/json" \
  -d '{"attack_type":"scan","duration":15,"intensity":80}'
```

Esperar 20s. Refrescar `http://192.168.122.10:3000/d/soc-rf-v2` y `/soc-xgb-v2`:
ambos clasifican el flujo como **Reconnaissance** con alta confidence.

### La pregunta inevitable: "¿por qué el ML no detectó el nmap externo directamente?"

**Respuesta arquitectónica** (esto es la frase clave de la demo):

> *"Suricata corre en `network_mode: host`, ve todas las interfaces. El ML sensor
> está dentro del bridge docker — solo ve tráfico que pasa por su veth. Esto **no
> es una limitación del lab**: es representativo de cómo se despliega ML en SOC
> reales. Suricata es IDS host-level clásico; un detector ML se despliega como
> NDR conectado a mirror port o como colector NetFlow/IPFIX, nunca como sniffer
> host-mode. Por eso el ejercicio del lab es lanzar el ataque externamente para
> ver Suricata, y reproducirlo internamente para ver el ML — son dos puntos de
> visibilidad distintos, complementarios."*

### Apéndice C: endpoint `/capture/passive` (extensión futura)

Existe un endpoint pasivo en el sensor (no genera tráfico, solo escucha):

```bash
curl -X POST http://192.168.122.10:9999/capture/passive \
  -H "Content-Type: application/json" \
  -d '{"duration":30,"interface":"","bpf_filter":"ip and tcp"}'
```

Útil si en el futuro alguien relanza el sensor en `network_mode: host` para
experimentar con captura externa real (requiere cambios en compose y `API_URL`).

---

## Apéndice A — Plan B si algo falla en vivo

| Síntoma | Solución rápida |
|---|---|
| Streamlit muestra 502 | `sudo docker compose restart reverse_proxy dashboard` |
| Grafana sin data | Lanzar otra captura sensor desde Tab Ataques |
| Captura tarda mucho | Bajar `intensity` a 40 y `duration` a 8 |
| ML API 401 | Verificar que `IDS_API_KEY` del `.env` matchea el header X-API-Key |

---

## Apéndice B — Comandos útiles para Q&A

```bash
# ¿Cuántas predicciones se han hecho?
wc -l ~/ML-Lab-Capston/logs/sensor_predictions.jsonl

# ¿Cuántas alertas Suricata?
grep -c '"event_type":"alert"' ~/ML-Lab-Capston/logs/eve.json

# ¿Qué features usa el modelo?
docker exec ids-ml-api curl -s -H "X-API-Key: val-key-capstone-2026-change-me" \
  http://localhost:8000/features | python3 -m json.tool | head -20

# ¿Cuáles son los hyperparámetros?
docker exec ids-ml-api curl -s -H "X-API-Key: val-key-capstone-2026-change-me" \
  http://localhost:8000/metrics | python3 -m json.tool | grep -A 5 best_params
```

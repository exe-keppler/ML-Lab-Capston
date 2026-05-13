# Video de defensa — guion de 3 minutos

**Formato**: screen capture del lab corriendo + voz en vivo del expositor.
**Duración objetivo**: 3:00 (margen ±10s).
**Hilo central**: complementariedad ML ↔ firmas como aporte conceptual.

---

## Setup antes de grabar (5 min)

> Si algo de esto falla, la grabación va a tener huecos. Hacelo TODO antes
> de abrir el grabador.

### 1. El lab tiene que estar caliente

```bash
ssh operador@192.168.10.129
cd ~/ML-Lab-Capston
docker compose ps     # los 11 contenedores deben estar Up + ml_api healthy
```

### 2. El feeder corriendo para que Grafana tenga data fresca

```bash
# En la VM:
sudo setsid nohup bash /tmp/lab_feeder.sh > /tmp/lab_feeder.log 2>&1 < /dev/null &
tail -f /tmp/lab_feeder.log     # verificar que esté disparando capturas
# Ctrl+C para salir del tail (el feeder sigue en background)
```

Si `lab_feeder.sh` no está en `/tmp/` de la VM:

```bash
scp Presentacion/lab_feeder.sh operador@192.168.10.129:/tmp/
```

### 3. Lanzar UN combo end-to-end ANTES de la grabación

Esto puebla el JSONL del sensor y el `eve.json` de Suricata para que el
tab "Suricata vs ML" tenga discrepancias visibles. Sin esto, la matriz
2×2 sale vacía y la demo no muestra el punto principal.

Abrir el dashboard → tab **Ataques** → **Lanzar combo completo**. Esperar
~45s. Confirmar que aparezcan KPIs no-cero (alertas Suricata ≥ 10,
predicciones ML ≥ 100).

### 4. Tener las 4 pestañas pre-cargadas en el browser (orden exacto)

| Tab # | URL | Para qué |
|---|---|---|
| 1 | `http://192.168.10.129/` (login lab/ids2026) → tab **Intro** | Diagrama del pipeline |
| 2 | mismo dashboard → tab **Suricata vs ML** | Matriz de acuerdo |
| 3 | `http://192.168.10.129:3000/d/soc-rf-v2` (admin/ids2026) | Panel RF en vivo |
| 4 | `http://192.168.10.129:3000/d/soc-suricata` | Panel Suricata en vivo |

Activar **modo focus** del browser (F11 fullscreen) en las 4 tabs.

### 5. Tener el notebook 07 abierto en JupyterLab

`http://192.168.10.129:8888/lab?token=lab-ids-ml-udla-2026` → abrir
`notebooks/07_adversarial_evasion.ipynb` → scrollear hasta la **conclusión
final** (última celda markdown con los números de evasión 100%).

### 6. Grabador de pantalla configurado

- Resolución 1920×1080 mínimo.
- Cursor visible y resaltado (en OBS: filtros → "Mouse highlight").
- Audio testing: nivel del mic ≈ −12 dB en silencio, ≈ −6 dB hablando.

---

## El guion (3:00 exactos)

> **Cómo leer este documento**:
> - `[ACCIÓN]` = lo que hacés en pantalla (NO se dice).
> - Texto en cursiva = lo que decís palabra por palabra.
> - `(pausa)` = silencio de ~0.5s para que el espectador procese el cambio.

---

### 🎬 0:00 — 0:20 · Hook + problema (20s)

`[ACCIÓN] Tab 3 abierta: Grafana SOC Suricata en vivo. Cursor sobre el panel "Top firmas".`

> *"Esto es un IDS por firmas — Suricata, 50 mil reglas ET Open."*

`[ACCIÓN] Switch a Tab 4: Grafana SOC RF v2.`

> *"Y esto es un detector de Machine Learning, Random Forest sobre CICIDS2017."*

`[ACCIÓN] Volver a Tab 1: Streamlit, tab Intro.`

> *"Cada uno tiene errores distintos. Los puse a correr juntos sobre el mismo
> tráfico para ver qué pasa cuando se complementan. (pausa)"*

---

### 🎬 0:20 — 0:50 · Pipeline + arquitectura (30s)

`[ACCIÓN] Cursor sobre el diagrama Graphviz del pipeline. Resaltar lentamente cada nodo.`

> *"El tráfico se separa en dos caminos paralelos. El sensor lo captura,
> CICFlowMeter extrae 47 features por flujo, y un par de modelos —Random
> Forest y XGBoost— predicen categoría más una explicación SHAP."*

`[ACCIÓN] Cursor baja al camino de Suricata en el diagrama.`

> *"En paralelo, Suricata mira los mismos paquetes pero busca patrones
> conocidos: SQL injection, XSS, escaneos, malware UA strings."*

`[ACCIÓN] Cursor termina en "Promtail → Loki → Grafana".`

> *"Los dos veredictos se centralizan en Loki, y Grafana los muestra. (pausa)"*

---

### 🎬 0:50 — 1:30 · Demo: ataque + detección dual (40s)

`[ACCIÓN] Tab Streamlit → tab Ataques → click "Lanzar combo completo".`

> *"Voy a lanzar un combo de ataques —un mix de DoS, scan, brute force, más
> payloads HTTP de SQL injection, XSS, y user agents tipo Nikto."*

`[ACCIÓN] Mientras corre la barra de progreso (~30s), cambiar a Tab 3 (Grafana Suricata).`

> *"Ya están entrando alertas en Suricata."*

`[ACCIÓN] Switch a Tab 4 (Grafana RF v2). Mostrar el panel "Predicciones por minuto" subiendo.`

> *"Y el RF está clasificando flujos como Reconnaissance y Brute Force casi
> en simultáneo."*

`[ACCIÓN] Volver brevemente a Streamlit, mostrar las métricas finales del combo (+N alertas, +N predicciones).`

> *"Ambos pipelines registraron el evento. (pausa) ¿Pero coincidieron?"*

---

### 🎬 1:30 — 2:15 · El core: matriz de acuerdo (45s)

`[ACCIÓN] Tab 2: Streamlit → tab "Suricata vs ML". Cursor sobre la matriz 2×2.`

> *"Acá está la respuesta. Cruzo las predicciones del ML contra las alertas
> de Suricata por 5-tupla —misma IP, mismo puerto, mismo protocolo— y
> obtengo cuatro cuadrantes."*

`[ACCIÓN] Cursor sobre cada cuadrante de la matriz en orden:`

> *"Arriba a la izquierda: ambos detectaron. Alta confianza, ataque casi
> seguro."*
>
> *"Arriba a la derecha: solo el ML. Suricata no tenía firma para este
> patrón —candidato a variante nueva o zero-day."*
>
> *"Abajo a la izquierda: solo Suricata. El ML no aprendió esa familia, o
> la firma está dando falso positivo."*
>
> *"Abajo a la derecha: ambos limpios. Probablemente tráfico benigno."*

`[ACCIÓN] Cursor sobre el KPI "Acuerdo (sobre ML)" → mostrar el porcentaje.`

> *"Las dos esquinas de la diagonal son donde el sistema se autovalida. Las
> otras dos son donde está el aprendizaje real del SOC. (pausa)"*

---

### 🎬 2:15 — 2:45 · La honestidad: fragilidad del ML (30s)

`[ACCIÓN] Switch a JupyterLab → notebook 07_adversarial_evasion.ipynb → última conclusión.`

> *"Una salvedad importante. Si confiara solo en el ML, este ataque
> adversarial que está en el notebook 7 le mete 100% de evasión a ambos
> modelos —RF y XGBoost— con perturbaciones mínimas, una distancia L2 de
> 2.6 en el espacio de features."*

`[ACCIÓN] Mostrar la línea concreta del notebook: "evasión total 100% (24/24)".`

> *"Cien por ciento. Es la razón por la que las firmas siguen existiendo en
> los SOC modernos: una regla bien escrita no se evade con un gradiente.
> (pausa) Por eso la complementariedad no es un nice-to-have."*

---

### 🎬 2:45 — 3:00 · Cierre (15s)

`[ACCIÓN] Volver a Streamlit → tab Intro → cursor sobre la frase "IDS híbrido".`

> *"El aporte del lab no es que ML detecte mejor —no lo hace—. Es mostrar
> dónde coinciden, dónde discrepan, y por qué un SOC necesita los dos."*

`[ACCIÓN] Cursor abajo del dashboard → mostrar el link al repo en el footer.`

> *"Todo el código y los notebooks reproducibles están en GitHub. Gracias."*

`[ACCIÓN] Stop recording.`

---

## Tips de grabación

1. **Grabá 2 takes mínimo**. La primera vez siempre suena rígido. La tercera
   ya suena natural.
2. **Cortes en las pausas marcadas**. Si te equivocás en un bloque, pausá 3
   segundos en silencio y repetí el bloque desde la última `(pausa)`. En
   post-producción cortás el error en el silencio.
3. **No subas el volumen del feeder en la VM** — corre headless, no genera
   audio. Pero sí mutea cualquier notificación del sistema (Slack, Discord,
   mail).
4. **Mantené el cursor LENTO**. Lo que vos ves obvio, el espectador lo
   procesa con 1-2 segundos de delay. Si haces un movimiento rápido,
   no te van a seguir.
5. **El audio importa más que el video**. Si el video se ve "casero" pero
   se escucha claro, pasa. Lo inverso no.

---

## Plan B si algo se rompe en grabación

| Síntoma | Solución rápida en pre-grabación |
|---|---|
| Grafana muestra "No data" | `sudo docker exec ids-promtail rm -f /tmp/positions.yaml && sudo docker restart ids-promtail`, esperá 30s. |
| Suricata vs ML sin discrepancias | Lanzar `nmap -sS 192.168.10.129` desde otra máquina; después combo otra vez. |
| Streamlit 502 / tarda | `sudo docker compose restart reverse_proxy dashboard`, esperá 20s. |
| Sensor no responde | `sudo docker compose restart sensor`, esperá 15s. |
| El feeder murió | Re-lanzá: ver sección "Setup paso 2". |

Si algo se rompe **durante** la grabación, no pares. Terminá el bloque,
cortás en post-producción. Tener 5 takes mediocres es mejor que 0 takes
"perfectos".

---

## Checklist final antes de presionar REC

- [ ] Los 11 contenedores `Up` en `docker compose ps`.
- [ ] `lab_feeder.sh` corriendo en la VM.
- [ ] Combo end-to-end ya ejecutado (KPIs ≥ 10 alertas + ≥ 100 predicciones).
- [ ] 4 pestañas en el browser pre-cargadas y en F11 fullscreen.
- [ ] Notebook 07 abierto en la conclusión final.
- [ ] Mic test OK (≈ −6 dB hablando).
- [ ] Notificaciones del sistema **desactivadas**.
- [ ] Cronómetro visible para chequear el 3:00.

---

## Después de grabar

1. Edición: cortes en las pausas marcadas, normalizar audio a −16 LUFS.
2. Exportar como `mp4` H.264, 1920×1080, 30 fps, bitrate ≥ 5 Mbps.
3. Subtítulos opcionales (Whisper local lo hace en 2 min).
4. Guardar el `mp4` en `Presentacion/exports/video_defensa_3min.mp4`.

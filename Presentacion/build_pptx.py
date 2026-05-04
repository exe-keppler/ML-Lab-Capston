#!/usr/bin/env python3
"""Genera Laboratorio-IDS-ML.pptx con python-pptx.

Diseño consistente: tema azul corporativo, layouts simples (título +
contenido en bullets / tablas / código). Sin emojis, sin colores chillones,
fuente sobria. Listo para presentar a una clase universitaria.

Uso:
    python3 build_pptx.py

Output:
    exports/Laboratorio-IDS-ML.pptx
"""
import os
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.dml.color import RGBColor
from pptx.oxml.ns import qn
from copy import deepcopy

# ─── Configuración global ───
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "exports")
os.makedirs(OUT_DIR, exist_ok=True)
OUT = os.path.join(OUT_DIR, "Laboratorio-IDS-ML.pptx")
SCREENSHOTS_DIR = os.path.join(HERE, "screenshots")

# Paleta corporativa sobria
NAVY = RGBColor(0x1E, 0x3A, 0x8A)        # azul oscuro — títulos
BLUE = RGBColor(0x1E, 0x40, 0xAF)        # azul medio — subtítulos
GREY = RGBColor(0x4B, 0x55, 0x63)        # gris — texto cuerpo
LIGHT = RGBColor(0xF3, 0xF4, 0xF6)       # gris muy claro — fondo de código
DARK_TEXT = RGBColor(0x11, 0x18, 0x27)   # casi negro — body
ACCENT = RGBColor(0xCA, 0x8A, 0x04)      # ámbar — destacar

# Fuentes
FONT_TITLE = "Calibri"
FONT_BODY = "Calibri"
FONT_CODE = "Consolas"

prs = Presentation()
prs.slide_width = Inches(13.333)   # 16:9
prs.slide_height = Inches(7.5)
SLIDE_W, SLIDE_H = prs.slide_width, prs.slide_height

# ─── Helpers ───
def add_blank_slide():
    blank = prs.slide_layouts[6]
    return prs.slides.add_slide(blank)


def add_textbox(slide, x, y, w, h, text, *, font=FONT_BODY, size=18,
                bold=False, color=DARK_TEXT, align=PP_ALIGN.LEFT,
                anchor=MSO_ANCHOR.TOP):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.vertical_anchor = anchor
    tf.word_wrap = True
    tf.margin_left = Inches(0.05)
    tf.margin_right = Inches(0.05)
    p = tf.paragraphs[0]
    p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.name = font
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = color
    return tb


def add_title_bar(slide, title):
    """Banda azul superior con el título."""
    bar = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0), Inches(0),
        SLIDE_W, Inches(0.85)
    )
    bar.fill.solid()
    bar.fill.fore_color.rgb = NAVY
    bar.line.fill.background()
    tf = bar.text_frame
    tf.margin_left = Inches(0.4)
    tf.margin_right = Inches(0.4)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    run = p.add_run()
    run.text = title
    run.font.name = FONT_TITLE
    run.font.size = Pt(28)
    run.font.bold = True
    run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)


def add_footer(slide, page_no, total):
    add_textbox(slide, 0.4, 7.1, 6, 0.3,
                "Laboratorio IDS-ML · UDLA 2026",
                size=10, color=GREY)
    add_textbox(slide, 11.5, 7.1, 1.4, 0.3,
                f"{page_no} / {total}",
                size=10, color=GREY, align=PP_ALIGN.RIGHT)


def add_bullets(slide, x, y, w, h, items, size=18):
    """items: list of strings or (text, indent_level)."""
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        if isinstance(item, tuple):
            text, level = item
        else:
            text, level = item, 0
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.level = level
        p.alignment = PP_ALIGN.LEFT
        p.space_after = Pt(8)
        run = p.add_run()
        bullet = "•" if level == 0 else "○"
        run.text = f"{bullet}  {text}"
        run.font.name = FONT_BODY
        run.font.size = Pt(size - level * 2)
        run.font.color.rgb = DARK_TEXT
    return tb


def add_code_block(slide, x, y, w, h, code, size=14):
    """Bloque de código con fondo gris claro."""
    box = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h)
    )
    box.fill.solid()
    box.fill.fore_color.rgb = LIGHT
    box.line.color.rgb = GREY
    box.line.width = Pt(0.5)
    tf = box.text_frame
    tf.margin_left = Inches(0.15)
    tf.margin_right = Inches(0.15)
    tf.margin_top = Inches(0.1)
    tf.margin_bottom = Inches(0.1)
    tf.word_wrap = True
    lines = code.split("\n")
    for i, line in enumerate(lines):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.alignment = PP_ALIGN.LEFT
        run = p.add_run()
        run.text = line
        run.font.name = FONT_CODE
        run.font.size = Pt(size)
        run.font.color.rgb = DARK_TEXT
    return box


def add_table(slide, x, y, w, h, headers, rows, *, header_color=NAVY,
              first_col_bold=True, body_size=14):
    """Tabla simple con header coloreado."""
    cols = len(headers)
    rows_n = len(rows) + 1
    table_shape = slide.shapes.add_table(rows_n, cols,
                                          Inches(x), Inches(y),
                                          Inches(w), Inches(h))
    table = table_shape.table
    # header
    for j, hdr in enumerate(headers):
        cell = table.cell(0, j)
        cell.fill.solid()
        cell.fill.fore_color.rgb = header_color
        tf = cell.text_frame
        tf.margin_left = Inches(0.08); tf.margin_right = Inches(0.08)
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        run = p.add_run()
        run.text = hdr
        run.font.name = FONT_BODY; run.font.size = Pt(body_size + 1)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    # body
    for i, row in enumerate(rows, start=1):
        for j, val in enumerate(row):
            cell = table.cell(i, j)
            tf = cell.text_frame
            tf.margin_left = Inches(0.08); tf.margin_right = Inches(0.08)
            p = tf.paragraphs[0]
            p.alignment = PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER
            run = p.add_run()
            run.text = str(val)
            run.font.name = FONT_BODY; run.font.size = Pt(body_size)
            run.font.color.rgb = DARK_TEXT
            if first_col_bold and j == 0:
                run.font.bold = True
    return table_shape


def add_image_or_placeholder(slide, x, y, w, h, image_filename, caption=""):
    """Inserta una imagen si existe en screenshots/, sino placeholder."""
    img_path = os.path.join(SCREENSHOTS_DIR, image_filename)
    if os.path.isfile(img_path):
        slide.shapes.add_picture(img_path, Inches(x), Inches(y),
                                  Inches(w), Inches(h))
        if caption:
            add_textbox(slide, x, y + h + 0.05, w, 0.3,
                        caption, size=11, color=GREY,
                        align=PP_ALIGN.CENTER)
    else:
        # Placeholder con borde punteado
        ph = slide.shapes.add_shape(
            MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
        ph.fill.solid(); ph.fill.fore_color.rgb = LIGHT
        ph.line.color.rgb = GREY; ph.line.width = Pt(1)
        tf = ph.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
        run = p.add_run()
        run.text = f"[ Screenshot: {image_filename} ]"
        run.font.name = FONT_CODE; run.font.size = Pt(12)
        run.font.color.rgb = GREY
        run.font.italic = True
        if caption:
            add_textbox(slide, x, y + h + 0.05, w, 0.3,
                        caption, size=11, color=GREY,
                        align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════
# SLIDES
# ════════════════════════════════════════════════════════════════
TOTAL = 30  # update si agrega/quita

# ─── Slide 1: Portada ───
def slide_portada():
    s = add_blank_slide()
    # Fondo azul
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    bg.fill.solid(); bg.fill.fore_color.rgb = NAVY
    bg.line.fill.background()
    # Título
    add_textbox(s, 0.8, 2.2, 11.7, 1.2,
                "Laboratorio IDS-ML",
                font=FONT_TITLE, size=64, bold=True,
                color=RGBColor(0xFF, 0xFF, 0xFF))
    # Subtítulo
    add_textbox(s, 0.8, 3.4, 11.7, 0.8,
                "Detección de intrusiones con Machine Learning + Reglas",
                size=28, color=RGBColor(0xC7, 0xD2, 0xFE))
    # Línea separadora
    line = s.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                               Inches(0.8), Inches(4.3),
                               Inches(2.5), Inches(0.06))
    line.fill.solid(); line.fill.fore_color.rgb = ACCENT
    line.line.fill.background()
    # Pie
    add_textbox(s, 0.8, 4.6, 11.7, 0.6,
                "Maestría en IA Aplicada · UDLA 2026",
                size=22, color=RGBColor(0xE5, 0xE7, 0xEB))
    add_textbox(s, 0.8, 6.6, 11.7, 0.5,
                "github.com/exe-keppler/ML-Lab-Capston",
                font=FONT_CODE, size=14, color=RGBColor(0xC7, 0xD2, 0xFE))


# ─── Slide 2: Problema ───
def slide_problema():
    s = add_blank_slide()
    add_title_bar(s, "¿Qué problema resolvemos?")
    add_textbox(s, 0.6, 1.2, 12, 0.6,
                "Una red empresarial promedio genera millones de flujos por día. Un analista SOC no puede revisar todo manualmente.",
                size=18, color=GREY)
    # Diagrama tipo flowchart simple
    add_textbox(s, 0.6, 2.3, 12.2, 0.5,
                "El flujo del problema:", size=18, bold=True, color=BLUE)
    add_code_block(s, 0.6, 2.9, 12.2, 1.2,
"""Tráfico  →  Detector  →  ¿Alarma?  →  SOC Analyst
                  ↑
            "Es ataque"  /  "Es benigno" """, size=16)
    add_textbox(s, 0.6, 4.4, 12.2, 0.5,
                "Dos enfoques tradicionales:",
                size=18, bold=True, color=BLUE)
    add_bullets(s, 0.6, 5.0, 12.2, 1.5, [
        "Reglas (Suricata, Snort): firmas conocidas. Bajo FP, no detecta novedades.",
        "ML: aprende patrones. Detecta variantes, pero falsos positivos y vulnerable a adversarial.",
        ("El lab combina ambos para responder: ¿son redundantes o complementarios?", 1),
    ])
    add_footer(s, 2, TOTAL)


# ─── Slide 3: Stack ───
def slide_stack():
    s = add_blank_slide()
    add_title_bar(s, "Stack del laboratorio")
    add_code_block(s, 0.6, 1.2, 12.2, 4.5,
"""                       ┌─────────────┐
   tráfico               │   Suricata  │ ─── eve.json ──┐
   (DVWA target)  ──────►│   ET-Open   │                │
                         │    ~50k     │                ▼
                         └─────────────┘            ┌──────┐
                                                    │ Loki │
                         ┌─────────────┐            └──┬───┘
                         │   Sensor    │               │
                         │ (CICFlow)   │ ──┐           ▼
                         └──────┬──────┘   │     ┌──────────┐
                                │          │     │ Grafana  │
                                ▼          │     │  5 dash  │
                         ┌─────────────┐   │     └──────────┘
                         │   ML API    │   │
                         │ RF + XGB v2 │ ◄─┘
                         │   + SHAP    │
                         └──────┬──────┘
                                │
                                ▼
                         sensor_predictions.jsonl
                         (model: rf | xgb)""", size=12)
    add_textbox(s, 0.6, 5.9, 12.2, 0.5,
                "11 contenedores Docker. Deploy: git clone + ./setup.sh = 47 segundos.",
                size=16, bold=True, color=BLUE)
    add_footer(s, 3, TOTAL)


# ─── Slide 4: ML vs reglas ───
def slide_ml_vs_reglas():
    s = add_blank_slide()
    add_title_bar(s, "¿Por qué ML para detección de intrusiones?")
    add_textbox(s, 0.6, 1.2, 5.8, 0.5, "Reglas (Suricata)",
                size=22, bold=True, color=BLUE)
    add_bullets(s, 0.6, 1.8, 5.8, 4, [
        "Determinísticas",
        "Baja FP en firmas conocidas",
        "No detecta lo que no está en su base",
        "Mantenimiento manual de reglas",
    ], size=16)
    add_textbox(s, 6.8, 1.2, 5.8, 0.5, "ML (RF / XGBoost)",
                size=22, bold=True, color=BLUE)
    add_bullets(s, 6.8, 1.8, 5.8, 4, [
        "Aprende patrones generales",
        "Detecta variantes de ataques",
        "Escala con más datos",
        "Falsos positivos en tráfico atípico",
        "Vulnerable a evasión adversarial",
    ], size=16)
    add_textbox(s, 0.6, 5.7, 12.2, 0.7,
                "Hipótesis del lab: son COMPLEMENTARIOS, no sustitutos.",
                size=22, bold=True, color=ACCENT, align=PP_ALIGN.CENTER)
    add_footer(s, 4, TOTAL)


# ─── Slide 5: Sección 2 cover ───
def slide_seccion2():
    s = add_blank_slide()
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    bg.fill.solid(); bg.fill.fore_color.rgb = NAVY
    bg.line.fill.background()
    add_textbox(s, 0.8, 2.8, 11.7, 1.2,
                "Sección 2",
                size=36, color=RGBColor(0xC7, 0xD2, 0xFE))
    add_textbox(s, 0.8, 3.6, 11.7, 1.2,
                "Dataset y pipeline ML",
                size=56, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
    add_textbox(s, 0.8, 5.4, 11.7, 0.5,
                "8 notebooks reproducibles · 2.3M flujos · 47 features auditadas",
                size=18, color=RGBColor(0xC7, 0xD2, 0xFE))


# ─── Slide 6: CICIDS2017 ───
def slide_dataset():
    s = add_blank_slide()
    add_title_bar(s, "CICIDS2017 — el dataset")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "University of New Brunswick (UNB). Estándar para benchmarking de IDS.",
                size=16, color=GREY)
    add_table(s, 0.6, 1.9, 12.2, 4.5,
              ["Categoría (6 finales)", "Subtipos originales", "% del total"],
              [
                  ["Benign", "tráfico legítimo", "85.5%"],
                  ["DoS",    "Hulk, GoldenEye, Slowloris, Slowhttptest, Heartbleed", "8.4%"],
                  ["DDoS",   "flood TCP/UDP volumétrico", "5.5%"],
                  ["Brute Force", "FTP-Patator, SSH-Patator", "0.4%"],
                  ["Reconnaissance", "PortScan, Bot, Infiltration", "0.15%"],
                  ["Web Attack", "XSS, SQLi, Brute Force web", "0.09%"],
              ], body_size=14)
    add_textbox(s, 0.6, 6.5, 12.2, 0.5,
                "5 días de tráfico · 2.3M flujos · 78 features crudas (CICFlowMeter)",
                size=14, color=GREY, align=PP_ALIGN.CENTER)
    add_footer(s, 6, TOTAL)


# ─── Slide 7: EDA ───
def slide_eda():
    s = add_blank_slide()
    add_title_bar(s, "Notebook 01 — EDA: lo que el dataset esconde")
    add_table(s, 0.6, 1.3, 12.2, 4.5,
              ["Hallazgo", "Implicación"],
              [
                  ["Desbalance extremo (Benign 85%, Heartbleed 11)", "F1-macro va a sufrir en minorías"],
                  ["Web Attack tiene encoding roto (`–` corrupto)", "Necesita normalización"],
                  ["8 columnas con varianza 0", "Drop seguro, no aportan señal"],
                  ["Inf en features de tasa (Flow Bytes/s)", "Cuando Flow Duration = 0 → reemplazar con 0"],
                  ["Pares Fwd/Bwd correlacionados", "Candidatos a colinealidad (VIF)"],
              ], body_size=14)
    add_textbox(s, 0.6, 6.0, 12.2, 0.6,
                "Sin EDA, todo esto sale a la luz cuando el modelo ya está entrenado y falla.",
                size=18, bold=True, color=ACCENT, align=PP_ALIGN.CENTER)
    add_footer(s, 7, TOTAL)


# ─── Slide 8: Feature audit ───
def slide_audit():
    s = add_blank_slide()
    add_title_bar(s, "Notebook 03 — Feature audit (lo más denso)")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "De 77 features → 47 features finales. 30 drops justificados:",
                size=18, bold=True, color=BLUE)
    add_table(s, 0.6, 1.9, 12.2, 3.2,
              ["Razón", "Cantidad", "Ejemplos"],
              [
                  ["Constantes (varianza 0)", "8", "Bwd_PSH_Flags, CWE_Flag_Count"],
                  ["Leakage (delata el label)", "6", "Init_Bwd_Win_Bytes = -1 si no hay backward → 100% PortScan"],
                  ["Redundancia matemática", "7", "Avg_Packet_Size ≡ Packet_Length_Mean"],
                  ["VIF iterativo > 50", "9", "Total_Fwd_Packets, Idle_Mean"],
              ], body_size=14)
    add_textbox(s, 0.6, 5.4, 12.2, 0.5,
                "Lección clave",
                size=20, bold=True, color=ACCENT)
    add_textbox(s, 0.6, 5.9, 12.2, 1.2,
                "Init_Bwd_Win_Bytes = -1 clasifica PortScan con 99% precisión. Pero el modelo aprende el sentinel, no el patrón. Eso es leakage y arruina el modelo en datos reales.",
                size=15, color=DARK_TEXT)
    add_footer(s, 8, TOTAL)


# ─── Slide 9: Baselines ───
def slide_baselines():
    s = add_blank_slide()
    add_title_bar(s, "Notebooks 04 y 05 — Baselines y tuning")
    add_textbox(s, 0.6, 1.2, 5.8, 0.5,
                "Baselines (nb04)", size=20, bold=True, color=BLUE)
    add_table(s, 0.6, 1.8, 5.8, 2.5,
              ["Modelo", "F1-macro (val)"],
              [
                  ["LogReg", "0.49"],
                  ["KNN", "n/a (no escala)"],
                  ["RF default", "0.64"],
              ], body_size=15)
    add_textbox(s, 6.8, 1.2, 5.8, 0.5,
                "Tuning 16+16 configs (nb05)", size=20, bold=True, color=BLUE)
    add_table(s, 6.8, 1.8, 5.8, 2.5,
              ["Modelo", "F1-macro"],
              [
                  ["RF tuned ← winner", "0.670"],
                  ["XGBoost tuned", "0.645"],
                  ["RF default", "0.635"],
                  ["XGBoost default", "0.632"],
              ], body_size=15)
    add_textbox(s, 0.6, 5.0, 12.2, 0.5,
                "Hallazgo importante:", size=20, bold=True, color=ACCENT)
    add_textbox(s, 0.6, 5.5, 12.2, 1.5,
                "Boosting NO siempre domina al bagging. Depende del dataset. En CICIDS2017 con desbalance extremo, RF + class_weight='balanced_subsample' + min_samples_leaf=5 supera a XGBoost tuneado.",
                size=16, color=DARK_TEXT)
    add_footer(s, 9, TOTAL)


# ─── Slide 10: Modelo final ───
def slide_modelo_final():
    s = add_blank_slide()
    add_title_bar(s, "Notebook 06 — Modelo final v2")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "Train sobre train+val combinados (60K balanceados), eval en test no visto (350K).",
                size=16, color=GREY)
    add_table(s, 0.6, 1.9, 12.2, 2.5,
              ["Modelo", "F1-macro", "F1-weighted", "Accuracy"],
              [
                  ["RF v2 binary",        "0.9875", "0.9937", "0.9937"],
                  ["RF v2 multiclass",    "0.6630", "0.9727", "0.9565"],
                  ["XGBoost v2 binary",   "0.9814", "0.9906", "0.9905"],
                  ["XGBoost v2 multi",    "0.6508", "0.9746", "0.9609"],
              ], body_size=14)
    add_textbox(s, 0.6, 4.7, 12.2, 0.5,
                "El gap entre binary (0.99) y multi (0.66) es real",
                size=18, bold=True, color=ACCENT)
    add_bullets(s, 0.6, 5.3, 12.2, 1.8, [
        "Saber 'esto es ataque' es fácil — F1-macro 0.99 binary lo confirma.",
        "Saber QUÉ TIPO de ataque es difícil porque las clases minoritarias (Web Attack: 322 en test, Reconnaissance: 516)",
        ("…tienen muchos falsos positivos por la proporción 296K Benign vs 322 minorías. 1% FP en Benign = 3000 errores.", 1),
    ], size=14)
    add_footer(s, 10, TOTAL)


# ─── Slide 11: Adversarial ───
def slide_adversarial():
    s = add_blank_slide()
    add_title_bar(s, "Notebook 07 — Adversarial (HopSkipJump)")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "Black-box L2-norm minimization, 25 muestras de cada clase de ataque.",
                size=16, color=GREY)
    add_table(s, 0.6, 1.9, 12.2, 1.8,
              ["Modelo", "Evasión total", "Evasión a Benign", "L2 mediano"],
              [
                  ["RF v2",      "100%", "87.5%", "2.63"],
                  ["XGBoost v2", "100%", "76.0%", "2.67"],
              ], body_size=15)
    add_textbox(s, 0.6, 4.0, 12.2, 0.5,
                "Implicancia para el SOC:",
                size=20, bold=True, color=ACCENT)
    add_textbox(s, 0.6, 4.6, 12.2, 1.6,
                "F1-macro 0.99 (binary) NO ES 'modelo seguro'. Un atacante adaptativo viola los dos modelos con perturbaciones mínimas. Por eso Suricata sigue importando — sus firmas no se evaden con perturbaciones de features.",
                size=15, color=DARK_TEXT)
    add_textbox(s, 0.6, 6.3, 12.2, 0.6,
                "Caveat: HopSkipJump perturba feature space, no problem space. Trabajo futuro = atacar el tráfico real.",
                size=13, color=GREY, align=PP_ALIGN.CENTER)
    add_footer(s, 11, TOTAL)


# ─── Slide 12: nb08 inference validation ───
def slide_nb08():
    s = add_blank_slide()
    add_title_bar(s, "Notebook 08 — Inference validation")
    add_textbox(s, 0.6, 1.2, 12.2, 0.6,
                "¿Lo que entrenó el notebook = lo que sirve la API?",
                size=22, bold=True, color=BLUE)
    add_code_block(s, 0.6, 2.1, 12.2, 2,
"""Categoría matches:    30/30
Probabilidad matches: 30/30  (tolerancia 1e-3)
Binary matches:       30/30

SHA-256 local:    7a1ecaf97d4aa17a8462b243c0512b5dd0c626a79021b095f68532689bf497f0
SHA-256 manifest: 7a1ecaf97d4aa17a8462b243c0512b5dd0c626a79021b095f68532689bf497f0

✓ MATCH: notebook y API leen el mismo modelo.""", size=14)
    add_textbox(s, 0.6, 4.4, 12.2, 0.6,
                "Cero training/serving skew",
                size=22, bold=True, color=ACCENT)
    add_textbox(s, 0.6, 5.0, 12.2, 1.5,
                "El modelo desplegado es bit-exact con el del notebook. No hay drift por bugs de scaler, label encoder o versión de sklearn. Esa garantía es la que permite usar el lab como referencia académica reproducible.",
                size=15, color=DARK_TEXT)
    add_footer(s, 12, TOTAL)


# ─── Slide 13: Sección 3 cover ───
def slide_seccion3():
    s = add_blank_slide()
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    bg.fill.solid(); bg.fill.fore_color.rgb = NAVY
    bg.line.fill.background()
    add_textbox(s, 0.8, 2.8, 11.7, 1.2,
                "Sección 3",
                size=36, color=RGBColor(0xC7, 0xD2, 0xFE))
    add_textbox(s, 0.8, 3.6, 11.7, 1.2,
                "Stack en producción",
                size=56, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
    add_textbox(s, 0.8, 5.4, 11.7, 0.5,
                "ML API hardened · Dual-model · SHAP · Sensor real · Grafana SOC enterprise",
                size=18, color=RGBColor(0xC7, 0xD2, 0xFE))


# ─── Slide 14: ML API ───
def slide_ml_api():
    s = add_blank_slide()
    add_title_bar(s, "ML API hardened (FastAPI)")
    add_code_block(s, 0.6, 1.2, 12.2, 1.6,
"""@app.post("/predict", dependencies=[Depends(require_api_key)])
@limiter.limit("120/minute")
def predict(flow: FlowInput, model: str = "rf", explain: bool = True):
    bin_clf, mc_clf, explainer = _resolve_models(model)
    X_s = scaler.transform(np.array(flow.features).reshape(1, -1))
    ...""", size=12)
    add_table(s, 0.6, 3.0, 12.2, 3.7,
              ["Mecanismo", "Cómo"],
              [
                  ["Auth",            "X-API-Key header obligatorio"],
                  ["Rate limit",      "120 req/min por IP via slowapi"],
                  ["Integridad modelo", "SHA-256 verificado antes de carga (anti pickle RCE)"],
                  ["Dual-model",      "?model=rf|xgb (default rf), reportado en /health.available_models"],
                  ["Validación",      "Rechaza NaN/Inf, batches > 500"],
                  ["Request ID",      "X-Request-ID middleware para correlación"],
              ], body_size=14)
    add_footer(s, 14, TOTAL)


# ─── Slide 15: SHAP ───
def slide_shap():
    s = add_blank_slide()
    add_title_bar(s, "SHAP — explicabilidad per-flujo")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "/predict?explain=true devuelve por qué clasificó así:",
                size=18, color=BLUE, bold=True)
    add_code_block(s, 0.6, 1.9, 12.2, 3.2,
"""{
  "category": "Reconnaissance",
  "category_confidence": 0.997,
  "top_contributions": [
    {"feature": "Fwd_IAT_Std",        "shap":  1.99, "value": -0.58},
    {"feature": "PSH_Flag_Count",     "shap": -1.08, "value": -0.91},
    {"feature": "Total_Fwd_Packets",  "shap":  1.02, "value": -0.03},
    {"feature": "Flow_IAT_Min",       "shap":  0.74, "value": -0.12},
    {"feature": "Bwd_Packets_per_s",  "shap":  0.61, "value": -0.43}
  ]
}""", size=12)
    add_textbox(s, 0.6, 5.3, 12.2, 1.5,
                "El SOC analyst ve que la decisión vino del patrón de IAT forward + ausencia de PSH flags. No es una caja negra: es una decisión interpretable.",
                size=14, color=DARK_TEXT)
    add_textbox(s, 0.6, 6.6, 12.2, 0.5,
                "Trade-off: ~50ms extra/predicción. Sensor batch lo desactiva (?explain=false).",
                size=12, color=GREY, align=PP_ALIGN.CENTER)
    add_footer(s, 15, TOTAL)


# ─── Slide 16: Sensor ───
def slide_sensor():
    s = add_blank_slide()
    add_title_bar(s, "Sensor — CICFlowMeter en vivo")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "Captura tráfico real con scapy + extrae las MISMAS 47 features del modelo:",
                size=16, color=GREY)
    add_code_block(s, 0.6, 1.9, 12.2, 1.4,
"""curl -X POST http://localhost:9999/capture/start \\
  -H 'Content-Type: application/json' \\
  -d '{"duration":15,"attack_type":"scan","intensity":80,
       "inject_dataset":true}'""", size=14)
    add_textbox(s, 0.6, 3.6, 12.2, 0.5,
                "Por cada captura:", size=18, bold=True, color=BLUE)
    add_bullets(s, 0.6, 4.2, 12.2, 3, [
        "Genera tráfico contra DVWA con scapy (TCP scan, flood, brute force, etc).",
        "Captura paquetes con CICFlowMeter Python.",
        "Inyecta también flujos reales de CICIDS2017 (inject_dataset=true).",
        "Llama /predict/batch para RF y XGBoost en paralelo.",
        "Persiste predicciones en sensor_predictions.jsonl con tag model.",
    ], size=14)
    add_footer(s, 16, TOTAL)


# ─── Slide 17: Grafana SOC ───
def slide_grafana():
    s = add_blank_slide()
    add_title_bar(s, "Grafana — 3 dashboards SOC enterprise")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "Cada dashboard responde a un detector específico. Loki indexa 'model' como label.",
                size=14, color=GREY)
    add_table(s, 0.6, 1.9, 12.2, 2.4,
              ["Dashboard", "Filtro Loki", "Audiencia"],
              [
                  ["SOC Suricata", "{job=\"suricata\"} |= \"alert\"", "Analista que confía en firmas"],
                  ["SOC RF v2",    "{job=\"ml_predictions\", model=\"rf\"}", "Confía en bagging"],
                  ["SOC XGB v2",   "{job=\"ml_predictions\", model=\"xgb\"}", "Confía en boosting"],
              ], body_size=12)
    add_textbox(s, 0.6, 4.5, 12.2, 0.5,
                "Panels comunes en cada uno:", size=18, bold=True, color=BLUE)
    add_bullets(s, 0.6, 5.0, 12.2, 1.8, [
        "Tasa por minuto, distribución de categorías, severidad.",
        "Top src_ip flagged, top dst_port.",
        "Stream en vivo con drilldown a request_id.",
        "El SOC compara: ¿RF y XGBoost coinciden? ¿Suricata atrapa lo que ML perdió?",
    ], size=14)
    add_footer(s, 17, TOTAL)


# ─── Slide 18: Streamlit ───
def slide_streamlit():
    s = add_blank_slide()
    add_title_bar(s, "Streamlit — dashboard pedagógico")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "6 tabs en orden didáctico:", size=18, bold=True, color=BLUE)
    add_table(s, 0.6, 1.9, 12.2, 4.5,
              ["#", "Tab", "Contenido"],
              [
                  ["1", "Intro",         "Glosario, links, recorrido del lab"],
                  ["2", "Dataset",       "Pie chart 6 clases, histograma feature, top correlaciones"],
                  ["3", "Métricas",      "Matriz de confusión EN VIVO + comparativa RF vs XGBoost"],
                  ["4", "Predicción",    "Selector RF/XGB, sliders top-6, SHAP signed + MITRE"],
                  ["5", "Ataques",       "Lanzar capturas y payloads HTTP contra DVWA"],
                  ["6", "Suricata vs ML", "Correlación 5-tupla, 4 veredictos"],
              ], body_size=13)
    add_footer(s, 18, TOTAL)


# ─── Slide 19: Reproducibilidad ───
def slide_reproducible():
    s = add_blank_slide()
    add_title_bar(s, "Reproducibilidad — git clone + setup.sh = 47s")
    add_code_block(s, 0.6, 1.2, 12.2, 1.4,
"""git clone https://github.com/exe-keppler/ML-Lab-Capston.git
cd ML-Lab-Capston
./setup.sh""", size=15)
    add_textbox(s, 0.6, 2.9, 12.2, 0.5,
                "Smoke test reciente (medido en VM con imágenes cacheadas):",
                size=16, bold=True, color=BLUE)
    add_code_block(s, 0.6, 3.5, 12.2, 1.6,
"""═══════════ Resumen final ═══════════
Containers corriendo: 11
Setup duración: 47s
Fresh deploy desde GitHub al smoke OK: SI""", size=15)
    add_textbox(s, 0.6, 5.4, 12.2, 1.4,
                "11 contenedores up, ML API healthy con model:v2 + available_models:[rf,xgb] + integrity:verified, Streamlit/Grafana/Jupyter/DVWA respondiendo, captura test productiva.",
                size=14, color=DARK_TEXT)
    add_footer(s, 19, TOTAL)


# ─── Slide 20: Sección 4 cover ───
def slide_seccion4():
    s = add_blank_slide()
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    bg.fill.solid(); bg.fill.fore_color.rgb = NAVY
    bg.line.fill.background()
    add_textbox(s, 0.8, 2.8, 11.7, 1.2,
                "Sección 4",
                size=36, color=RGBColor(0xC7, 0xD2, 0xFE))
    add_textbox(s, 0.8, 3.6, 11.7, 1.2,
                "Limitaciones honestas",
                size=56, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
    add_textbox(s, 0.8, 5.4, 11.7, 0.5,
                "F1-macro 0.99 ≠ modelo seguro. Por qué ML + reglas en paralelo.",
                size=18, color=RGBColor(0xC7, 0xD2, 0xFE))


# ─── Slide 21: El elefante en la habitación ───
def slide_elefante():
    s = add_blank_slide()
    add_title_bar(s, "El elefante en la habitación")
    add_textbox(s, 0.6, 1.2, 12.2, 0.6,
                "F1-macro 0.99 binary ≠ modelo seguro",
                size=24, bold=True, color=ACCENT, align=PP_ALIGN.CENTER)
    add_table(s, 0.6, 2.2, 12.2, 2.4,
              ["Detector", "Clean F1", "Bajo HopSkipJump"],
              [
                  ["RF v2 multiclass",   "0.66", "100% evadible"],
                  ["XGBoost v2 multi",   "0.65", "100% evadible"],
                  ["Suricata (firmas)",  "n/a",  "Resiste perturbaciones de features"],
              ], body_size=15)
    add_textbox(s, 0.6, 4.9, 12.2, 0.5,
                "Por qué Suricata resiste:",
                size=20, bold=True, color=BLUE)
    add_textbox(s, 0.6, 5.4, 12.2, 1.6,
                "El atacante puede mover los valores de Flow_Duration lo que quiera, pero el payload sigue siendo `' OR 1=1 --` → la regla de SQLi dispara igual. F1-macro 0.99 es el promedio sobre datos limpios; el atacante no juega al promedio.",
                size=14, color=DARK_TEXT)
    add_footer(s, 21, TOTAL)


# ─── Slide 22: Caveat ───
def slide_caveat():
    s = add_blank_slide()
    add_title_bar(s, "Caveat metodológico del adversarial")
    add_textbox(s, 0.6, 1.2, 12.2, 0.6,
                "HopSkipJump perturba en feature space (los 47 floats).",
                size=20, bold=True, color=BLUE)
    add_bullets(s, 0.6, 2.0, 12.2, 2, [
        "En la realidad, un atacante NO PUEDE elegir Bwd_Packet_Length_Mean arbitrariamente.",
        "Esos números los calcula CICFlowMeter del tráfico real.",
    ], size=15)
    add_textbox(s, 0.6, 4.1, 12.2, 0.6,
                "Para un ataque verdadero (problem-space attack):",
                size=20, bold=True, color=ACCENT)
    add_bullets(s, 0.6, 4.9, 12.2, 2, [
        "Modificar el tráfico generador (paquetes, timing, payload).",
        "Después esperar a que CICFlowMeter produzca features que evadan.",
        "Mucho más caro. Fuera del alcance de este lab.",
    ], size=15)
    add_textbox(s, 0.6, 6.5, 12.2, 0.6,
                "Resultado: fragilidad teórica, no exploit operacional.",
                size=14, color=GREY, align=PP_ALIGN.CENTER)
    add_footer(s, 22, TOTAL)


# ─── Slide 23: ML + reglas ───
def slide_complementarios():
    s = add_blank_slide()
    add_title_bar(s, "Por eso ML + reglas en paralelo")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "El SOC enterprise NO debería depender de un solo detector.",
                size=18, color=GREY, align=PP_ALIGN.CENTER)
    add_table(s, 0.6, 1.9, 12.2, 4.6,
              ["Caso", "Suricata", "ML", "Veredicto"],
              [
                  ["nmap -sS evidente",                    "✓ ET SCAN",  "✓ Reconnaissance", "Alta confianza"],
                  ["sqlmap",                                "✓ ET WEB SQL", "✓ Web Attack",   "Alta confianza"],
                  ["Brute Force novedosa",                  "✗",          "✓ Brute Force",   "ML cumple"],
                  ["Adversarial modificado",                "✓ payload",  "✗ evade",          "Reglas cumplen"],
                  ["Tráfico legítimo atípico",              "✓ no firma", "✗ FP",             "Suricata corrige"],
              ], body_size=13)
    add_textbox(s, 0.6, 6.6, 12.2, 0.5,
                "Esa es la conversación SOC enterprise que el lab ilustra en vivo.",
                size=14, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
    add_footer(s, 23, TOTAL)


# ─── Slide 24: Sección 5 cover ───
def slide_seccion5():
    s = add_blank_slide()
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    bg.fill.solid(); bg.fill.fore_color.rgb = NAVY
    bg.line.fill.background()
    add_textbox(s, 0.8, 2.8, 11.7, 1.2,
                "Sección 5",
                size=36, color=RGBColor(0xC7, 0xD2, 0xFE))
    add_textbox(s, 0.8, 3.6, 11.7, 1.2,
                "Para futuros estudiantes",
                size=56, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
    add_textbox(s, 0.8, 5.4, 11.7, 0.5,
                "Cómo extender el lab. Ideas para tomar la posta.",
                size=18, color=RGBColor(0xC7, 0xD2, 0xFE))


# ─── Slide 25: Cómo extender ───
def slide_extender():
    s = add_blank_slide()
    add_title_bar(s, "Cómo extender el lab")
    add_textbox(s, 0.6, 1.2, 12.2, 0.5,
                "Los 8 notebooks son la línea base. Cualquier extensión arranca clonando + ejecutando uno desde el principio.",
                size=14, color=GREY)
    add_table(s, 0.6, 1.9, 12.2, 4.5,
              ["Idea", "Donde toca", "Costo"],
              [
                  ["SMOTE sobre minorías antes del fit",       "nb05 + nb06",          "bajo"],
                  ["Stacking RF + XGBoost (ensemble vote)",     "nb05 + ml_api",        "medio"],
                  ["Modelo no supervisado (Isolation Forest)",  "nb05 + ml_api/anomaly", "medio"],
                  ["Problem-space adversarial",                 "nb07",                 "alto"],
                  ["Calibración threshold per-clase",            "ml_api",               "bajo"],
                  ["GNN sobre flow graphs",                      "nb09 nuevo",           "alto"],
              ], body_size=13)
    add_footer(s, 25, TOTAL)


# ─── Slide 26: Demo ───
def slide_demo():
    s = add_blank_slide()
    add_title_bar(s, "Demo en vivo (~10 min)")
    add_textbox(s, 0.6, 1.4, 12.2, 0.7,
                "Vamos al laboratorio en funcionamiento:",
                size=22, bold=True, color=BLUE, align=PP_ALIGN.CENTER)
    add_bullets(s, 1.5, 2.4, 10, 4.5, [
        "1. Levantar el lab con setup.sh (si no está ya levantado).",
        "2. Streamlit: recorrido por las 6 tabs.",
        "3. Lanzar una captura desde Tab Ataques.",
        "4. Ver predicción + SHAP en Tab Predicción.",
        "5. Cambiar a XGBoost y comparar.",
        "6. Abrir 3 dashboards SOC en Grafana.",
        "7. Mostrar cómo correlacionar ML ↔ Suricata por 5-tupla.",
    ], size=18)
    add_footer(s, 26, TOTAL)


# ─── Slide 27: Capturas ───
def slide_capturas():
    s = add_blank_slide()
    add_title_bar(s, "Capturas del lab")
    add_image_or_placeholder(s, 0.4, 1.2, 6.2, 3.5,
                              "01_streamlit_metricas.png",
                              "Streamlit · tab Métricas (matriz en vivo)")
    add_image_or_placeholder(s, 6.8, 1.2, 6.2, 3.5,
                              "02_streamlit_shap.png",
                              "Streamlit · tab Predicción con SHAP")
    add_image_or_placeholder(s, 0.4, 5.0, 6.2, 1.7,
                              "03_grafana_suricata.png",
                              "Grafana · SOC Suricata")
    add_image_or_placeholder(s, 6.8, 5.0, 6.2, 1.7,
                              "04_grafana_rf.png",
                              "Grafana · SOC Random Forest v2")
    add_footer(s, 27, TOTAL)


# ─── Slide 28: Recursos ───
def slide_recursos():
    s = add_blank_slide()
    add_title_bar(s, "Recursos para profundizar")
    add_table(s, 0.6, 1.4, 12.2, 4.5,
              ["Recurso", "Descripción"],
              [
                  ["github.com/exe-keppler/ML-Lab-Capston",     "Repo del lab"],
                  ["unb.ca/cic/datasets/ids-2017.html",          "Dataset CICIDS2017 (UNB)"],
                  ["github.com/Trusted-AI/ART",                  "IBM Adversarial Robustness Toolbox"],
                  ["github.com/shap/shap",                       "SHAP — Lundberg & Lee 2017"],
                  ["rules.emergingthreats.net/open/",            "Reglas Suricata ET-Open"],
                  ["docs.streamlit.io",                           "Streamlit"],
                  ["grafana.com/docs/loki",                       "Grafana Loki"],
              ], body_size=13)
    add_footer(s, 28, TOTAL)


# ─── Slide 29: Q&A ───
def slide_qa():
    s = add_blank_slide()
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    bg.fill.solid(); bg.fill.fore_color.rgb = NAVY
    bg.line.fill.background()
    add_textbox(s, 0.8, 2.5, 11.7, 1.5,
                "Q&A",
                font=FONT_TITLE, size=120, bold=True,
                color=RGBColor(0xFF, 0xFF, 0xFF), align=PP_ALIGN.CENTER)
    add_textbox(s, 0.8, 4.5, 11.7, 0.6,
                "11 contenedores · 8 notebooks · 5 dashboards · setup.sh 47s",
                size=20, color=RGBColor(0xC7, 0xD2, 0xFE),
                align=PP_ALIGN.CENTER)
    add_textbox(s, 0.8, 5.4, 11.7, 0.6,
                "github.com/exe-keppler/ML-Lab-Capston",
                font=FONT_CODE, size=18, color=RGBColor(0xFF, 0xFF, 0xFF),
                align=PP_ALIGN.CENTER)


# ─── Slide 30: Cierre ───
def slide_cierre():
    s = add_blank_slide()
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H)
    bg.fill.solid(); bg.fill.fore_color.rgb = NAVY
    bg.line.fill.background()
    add_textbox(s, 0.8, 3.0, 11.7, 1.2,
                "¡Gracias!",
                size=80, bold=True,
                color=RGBColor(0xFF, 0xFF, 0xFF), align=PP_ALIGN.CENTER)
    add_textbox(s, 0.8, 4.5, 11.7, 0.6,
                "Maestría en IA Aplicada · UDLA 2026",
                size=22, color=RGBColor(0xC7, 0xD2, 0xFE),
                align=PP_ALIGN.CENTER)


# ════════════════════════════════════════════════════════════════
# BUILD
# ════════════════════════════════════════════════════════════════
slide_portada()
slide_problema()
slide_stack()
slide_ml_vs_reglas()
slide_seccion2()
slide_dataset()
slide_eda()
slide_audit()
slide_baselines()
slide_modelo_final()
slide_adversarial()
slide_nb08()
slide_seccion3()
slide_ml_api()
slide_shap()
slide_sensor()
slide_grafana()
slide_streamlit()
slide_reproducible()
slide_seccion4()
slide_elefante()
slide_caveat()
slide_complementarios()
slide_seccion5()
slide_extender()
slide_demo()
slide_capturas()
slide_recursos()
slide_qa()
slide_cierre()

prs.save(OUT)
print(f"Escrito: {OUT}")
print(f"Total slides: {len(prs.slides)}")

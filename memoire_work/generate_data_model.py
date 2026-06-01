from __future__ import annotations

import html
import uuid
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from PIL import Image, ImageDraw, ImageFont


OUT_DIR = Path("memoire_work")
PNG_OUT = OUT_DIR / "modele_donnees_soc_dashboard.png"
PNG_ANNEXE_OUT = OUT_DIR / "modele_donnees_soc_dashboard_annexe.png"
DRAWIO_OUT = OUT_DIR / "modele_donnees_soc_dashboard.drawio"


TABLES = {
    "metrics": {
        "title": "metrics",
        "subtitle": "Mesures Proxmox hôte / VM",
        "fields": [
            "PK id",
            "timestamp",
            "node",
            "vmid",
            "scope: host | vm",
            "status",
            "cpu_percent",
            "ram_percent",
            "uptime_seconds",
        ],
    },
    "ssh_events": {
        "title": "ssh_events",
        "subtitle": "Logs SSH reçus via Syslog",
        "fields": [
            "PK id",
            "timestamp",
            "collected_at",
            "node",
            "vmid",
            "target_host",
            "source_ip",
            "username",
            "event_type",
            "line_hash UNIQUE",
        ],
    },
    "alerts": {
        "title": "alerts",
        "subtitle": "Alertes générées par règles",
        "fields": [
            "PK id",
            "alert_key",
            "first_seen / last_seen",
            "resolved_at",
            "node",
            "vmid",
            "event_type",
            "metric",
            "severity",
            "score",
            "status",
        ],
    },
    "incidents": {
        "title": "incidents",
        "subtitle": "Dossier de traitement SOC",
        "fields": [
            "PK id",
            "incident_key UNIQUE",
            "first_seen / last_seen",
            "resolved_at",
            "node",
            "vmid",
            "category",
            "severity",
            "score",
            "status",
            "source_ip / username",
        ],
    },
    "incident_alerts": {
        "title": "incident_alerts",
        "subtitle": "Lien incidents-alertes",
        "fields": [
            "PK/FK incident_id",
            "PK/FK alert_id",
            "linked_at",
        ],
    },
    "actions": {
        "title": "actions",
        "subtitle": "Audit réponse active",
        "fields": [
            "PK id",
            "timestamp",
            "node",
            "vmid",
            "action: isolate | restore",
            "result",
            "protected",
            "message",
        ],
    },
    "ml_scores": {
        "title": "ml_scores",
        "subtitle": "Scores Isolation Forest",
        "fields": [
            "PK id",
            "timestamp",
            "node",
            "vmid",
            "model_name / version",
            "anomaly_score",
            "raw_score",
            "is_anomaly",
            "severity",
            "feature_json",
        ],
    },
    "collector_runs": {
        "title": "collector_runs",
        "subtitle": "Santé collecteur Proxmox",
        "fields": ["PK id", "timestamp", "status", "nodes_seen", "vm_count", "alerts_seen"],
    },
    "syslog_runs": {
        "title": "syslog_runs",
        "subtitle": "Santé collecteur Syslog",
        "fields": ["PK id", "timestamp", "status", "events_seen", "events_inserted"],
    },
    "ml_model_runs": {
        "title": "ml_model_runs",
        "subtitle": "Entraînement ML",
        "fields": ["PK id", "timestamp", "model_version", "status", "training_rows", "accuracy", "recall", "precision"],
    },
}


POSITIONS = {
    "metrics": (90, 205, 430, 525),
    "ssh_events": (90, 650, 430, 1010),
    "alerts": (665, 285, 1035, 700),
    "ml_scores": (665, 800, 1035, 1170),
    "incident_alerts": (1255, 365, 1595, 555),
    "incidents": (1780, 240, 2175, 660),
    "actions": (1780, 820, 2175, 1145),
    "collector_runs": (155, 1320, 525, 1605),
    "syslog_runs": (820, 1320, 1190, 1605),
    "ml_model_runs": (1485, 1320, 1895, 1605),
}


EDGES = [
    ("metrics", "alerts", "seuils CPU/RAM"),
    ("ssh_events", "alerts", "règles SSH"),
    ("metrics", "ml_scores", "features CPU/RAM"),
    ("ssh_events", "ml_scores", "features SSH"),
    ("alerts", "incident_alerts", "N alertes"),
    ("incident_alerts", "incidents", "1 incident"),
    ("incidents", "actions", "timeline VMID"),
    ("alerts", "incidents", "création / mise à jour"),
    ("ml_scores", "alerts", "score anomalie"),
]


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        r"C:\Windows\Fonts\arialbd.ttf" if bold else r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\calibrib.ttf" if bold else r"C:\Windows\Fonts\calibri.ttf",
    ]
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return ImageFont.truetype(str(path), size=size)
    return ImageFont.load_default()


def draw_wrapped(draw: ImageDraw.ImageDraw, text: str, xy: tuple[int, int], max_width: int, fnt, fill, line_height: int) -> int:
    x, y = xy
    words = text.split()
    line = ""
    for word in words:
        candidate = f"{line} {word}".strip()
        if draw.textbbox((0, 0), candidate, font=fnt)[2] <= max_width:
            line = candidate
        else:
            draw.text((x, y), line, font=fnt, fill=fill)
            y += line_height
            line = word
    if line:
        draw.text((x, y), line, font=fnt, fill=fill)
        y += line_height
    return y


def draw_table(draw: ImageDraw.ImageDraw, name: str, box: tuple[int, int, int, int]) -> None:
    x1, y1, x2, y2 = box
    data = TABLES[name]
    header = "#0f766e"
    border = "#164e63"
    fill = "#ffffff"
    subfill = "#ecfeff"
    draw.rounded_rectangle(box, radius=16, fill=fill, outline=border, width=3)
    draw.rounded_rectangle((x1, y1, x2, y1 + 58), radius=16, fill=header, outline=header)
    draw.rectangle((x1, y1 + 35, x2, y1 + 58), fill=header)
    draw.text((x1 + 18, y1 + 14), data["title"], font=font(26, True), fill="white")
    draw.rectangle((x1, y1 + 58, x2, y1 + 91), fill=subfill, outline=border)
    draw.text((x1 + 18, y1 + 65), data["subtitle"], font=font(16), fill="#134e4a")
    y = y1 + 105
    for item in data["fields"]:
        bullet = "• "
        item_font = font(17, item.startswith("PK"))
        draw.text((x1 + 20, y), bullet, font=font(16), fill="#334155")
        draw.text((x1 + 42, y), item, font=item_font, fill="#111827")
        y += 24


def center(box: tuple[int, int, int, int]) -> tuple[int, int]:
    x1, y1, x2, y2 = box
    return ((x1 + x2) // 2, (y1 + y2) // 2)


def edge_points(src: str, dst: str) -> tuple[tuple[int, int], tuple[int, int]]:
    sx1, sy1, sx2, sy2 = POSITIONS[src]
    dx1, dy1, dx2, dy2 = POSITIONS[dst]
    sc = center(POSITIONS[src])
    dc = center(POSITIONS[dst])
    if sc[0] < dc[0]:
        start = (sx2, sc[1])
        end = (dx1, dc[1])
    else:
        start = (sx1, sc[1])
        end = (dx2, dc[1])
    return start, end


def draw_arrow(draw: ImageDraw.ImageDraw, src: str, dst: str, label: str, color: str = "#334155") -> None:
    start, end = edge_points(src, dst)
    sx, sy = start
    ex, ey = end
    midx = (sx + ex) // 2
    draw.line((sx, sy, midx, sy, midx, ey, ex, ey), fill=color, width=3)
    # arrow head
    draw.polygon([(ex, ey), (ex - 12 if sx < ex else ex + 12, ey - 8), (ex - 12 if sx < ex else ex + 12, ey + 8)], fill=color)
    label_box = draw.textbbox((0, 0), label, font=font(16, True))
    lw = label_box[2] - label_box[0] + 16
    lh = 26
    lx = midx - lw // 2
    ly = ey - 35 if abs(ey - sy) < 80 else (sy + ey) // 2 - lh // 2
    draw.rounded_rectangle((lx, ly, lx + lw, ly + lh), radius=8, fill="#f8fafc", outline="#cbd5e1")
    draw.text((lx + 8, ly + 4), label, font=font(16, True), fill=color)


def build_png() -> None:
    img = Image.new("RGB", (2260, 1710), "#f8fafc")
    draw = ImageDraw.Draw(img)
    draw.text((90, 45), "Modèle de données - Proxmox Sentinel", font=font(48, True), fill="#0f172a")
    subtitle = "Schéma logique SQLite utilisé pour collecter les métriques, logs SSH, alertes, incidents, actions et scores ML."
    draw.text((92, 105), subtitle, font=font(24), fill="#475569")
    for src, dst, label in EDGES:
        draw_arrow(draw, src, dst, label)
    for name, box in POSITIONS.items():
        draw_table(draw, name, box)
    legend = [
        "PK : clé primaire",
        "FK : clé étrangère",
        "node + vmid : association logique avec une VM Proxmox",
        "Les tables *_runs servent au suivi technique des collecteurs et du modèle ML.",
    ]
    y = 1640
    x = 90
    for item in legend:
        draw.text((x, y), item, font=font(18), fill="#334155")
        x += draw.textbbox((0, 0), item, font=font(18))[2] + 50
    img.save(PNG_OUT)


ANNEXE_POSITIONS = {
    "metrics": (80, 205, 420, 525),
    "ssh_events": (80, 660, 420, 1020),
    "alerts": (630, 340, 1000, 755),
    "ml_scores": (630, 840, 1000, 1235),
    "incident_alerts": (1190, 405, 1530, 595),
    "incidents": (1690, 300, 2085, 720),
    "actions": (1690, 835, 2085, 1175),
}


ANNEXE_EDGES = [
    ("metrics", "alerts", "seuils CPU/RAM"),
    ("ssh_events", "alerts", "règles SSH"),
    ("metrics", "ml_scores", "features CPU/RAM"),
    ("ssh_events", "ml_scores", "features SSH"),
    ("alerts", "incident_alerts", "N alertes"),
    ("incident_alerts", "incidents", "1 incident"),
    ("incidents", "actions", "timeline VMID"),
    ("ml_scores", "alerts", "score anomalie"),
]


def draw_arrow_custom(
    draw: ImageDraw.ImageDraw,
    positions: dict[str, tuple[int, int, int, int]],
    src: str,
    dst: str,
    label: str,
    color: str = "#334155",
) -> None:
    global POSITIONS
    old_positions = POSITIONS
    POSITIONS = positions
    try:
        start, end = edge_points(src, dst)
    finally:
        POSITIONS = old_positions
    sx, sy = start
    ex, ey = end
    midx = (sx + ex) // 2
    if label == "règles SSH":
        midx -= 20
    if label == "features CPU/RAM":
        midx -= 10
    draw.line((sx, sy, midx, sy, midx, ey, ex, ey), fill=color, width=3)
    draw.polygon([(ex, ey), (ex - 12 if sx < ex else ex + 12, ey - 8), (ex - 12 if sx < ex else ex + 12, ey + 8)], fill=color)
    label_box = draw.textbbox((0, 0), label, font=font(15, True))
    lw = label_box[2] - label_box[0] + 16
    lh = 25
    if label == "règles SSH":
        lx, ly = 455, 610
    elif label == "features CPU/RAM":
        lx, ly = 455, 715
    elif label == "features SSH":
        lx, ly = 455, 1005
    elif label == "score anomalie":
        lx, ly = midx - lw // 2, 790
    else:
        lx = midx - lw // 2
        ly = ey - 34 if abs(ey - sy) < 80 else (sy + ey) // 2 - lh // 2
    draw.rounded_rectangle((lx, ly, lx + lw, ly + lh), radius=8, fill="#f8fafc", outline="#cbd5e1")
    draw.text((lx + 8, ly + 4), label, font=font(15, True), fill=color)


def build_annexe_png() -> None:
    img = Image.new("RGB", (2160, 1340), "#f8fafc")
    draw = ImageDraw.Draw(img)
    draw.text((80, 42), "Modèle de données - Proxmox Sentinel", font=font(46, True), fill="#0f172a")
    subtitle = "Vue logique des principales tables SQLite utilisées par le SOC."
    draw.text((82, 102), subtitle, font=font(24), fill="#475569")
    for src, dst, label in ANNEXE_EDGES:
        draw_arrow_custom(draw, ANNEXE_POSITIONS, src, dst, label)
    for name, box in ANNEXE_POSITIONS.items():
        draw_table(draw, name, box)
    legend = "PK : clé primaire     FK : clé étrangère     node + vmid : association logique avec une VM Proxmox"
    draw.text((80, 1290), legend, font=font(19), fill="#334155")
    img.save(PNG_ANNEXE_OUT)


def mx_cell(root, id_, value="", style="", vertex="0", edge="0", parent="1", **attrs):
    cell = SubElement(root, "mxCell", id=id_, value=value, style=style, vertex=vertex, edge=edge, parent=parent)
    if attrs:
        geo = SubElement(cell, "mxGeometry", as_="geometry")
        for key, value in attrs.items():
            geo.set(key, str(value))
    return cell


def build_drawio() -> None:
    mxfile = Element("mxfile", host="app.diagrams.net", modified="2026-05-13T00:00:00.000Z", agent="Codex", version="24.7.17")
    diagram = SubElement(mxfile, "diagram", name="Modèle de données")
    graph = SubElement(diagram, "mxGraphModel", dx="2260", dy="1710", grid="1", gridSize="10", guides="1", tooltips="1", connect="1", arrows="1", fold="1", page="1", pageScale="1", pageWidth="2260", pageHeight="1710", math="0", shadow="0")
    root = SubElement(graph, "root")
    SubElement(root, "mxCell", id="0")
    SubElement(root, "mxCell", id="1", parent="0")

    ids = {}
    title_style = "text;html=1;strokeColor=none;fillColor=none;fontSize=28;fontStyle=1;align=left;verticalAlign=middle;"
    mx_cell(root, "title", "Modèle de données - Proxmox Sentinel", title_style, vertex="1", x="80", y="30", width="950", height="50")
    mx_cell(root, "subtitle", "Schéma logique SQLite : métriques, logs SSH, alertes, incidents, actions et scores ML.", "text;html=1;strokeColor=none;fillColor=none;fontSize=16;align=left;verticalAlign=middle;fontColor=#475569;", vertex="1", x="82", y="85", width="1050", height="35")

    for name, (x1, y1, x2, y2) in POSITIONS.items():
        ids[name] = f"table_{name}"
        data = TABLES[name]
        rows = [f"<b>{html.escape(data['title'])}</b><br><i>{html.escape(data['subtitle'])}</i><hr>"]
        rows.extend(html.escape(field) for field in data["fields"])
        value = "<br>".join(rows)
        style = "rounded=1;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#164e63;strokeWidth=2;fontSize=13;align=left;spacingLeft=12;verticalAlign=top;"
        mx_cell(root, ids[name], value, style, vertex="1", x=str(x1), y=str(y1), width=str(x2 - x1), height=str(y2 - y1))

    for idx, (src, dst, label) in enumerate(EDGES, start=1):
        style = "edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;endArrow=block;endFill=1;strokeColor=#334155;strokeWidth=2;fontSize=12;"
        cell = SubElement(root, "mxCell", id=f"edge_{idx}", value=html.escape(label), style=style, edge="1", parent="1", source=ids[src], target=ids[dst])
        SubElement(cell, "mxGeometry", relative="1", as_="geometry")

    xml = tostring(mxfile, encoding="unicode")
    # diagrams.net expects "as", not Python-friendly "as_".
    xml = xml.replace(" as_=", " as=")
    DRAWIO_OUT.write_text(xml, encoding="utf-8")


if __name__ == "__main__":
    OUT_DIR.mkdir(exist_ok=True)
    build_png()
    build_annexe_png()
    build_drawio()
    print(PNG_OUT)
    print(PNG_ANNEXE_OUT)
    print(DRAWIO_OUT)

import fs from "node:fs/promises";
import path from "node:path";
import { Canvas } from "../poster_work/node_modules/@oai/artifact-tool/node_modules/skia-canvas/lib/index.mjs";

const OUT_DIR = path.resolve("poster_work/output/poster_simulated_figures");

const C = {
  ink: "#111827",
  muted: "#4B5563",
  grid: "#E5E7EB",
  panel: "#F8FAFC",
  blue: "#2563EB",
  blueDark: "#1E3A8A",
  cyan: "#0891B2",
  orange: "#F97316",
  red: "#DC2626",
  green: "#059669",
  purple: "#7C3AED",
  yellow: "#F59E0B",
};

function canvas(width = 1600, height = 900) {
  const c = new Canvas(width, height);
  const ctx = c.getContext("2d");
  ctx.fillStyle = "#FFFFFF";
  ctx.fillRect(0, 0, width, height);
  ctx.textBaseline = "alphabetic";
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  return { c, ctx, width, height };
}

async function save(c, filename) {
  await fs.mkdir(OUT_DIR, { recursive: true });
  const buffer = await c.toBuffer("png");
  await fs.writeFile(path.join(OUT_DIR, filename), buffer);
}

function font(size, weight = 400) {
  return `${weight} ${size}px "Segoe UI", Arial, sans-serif`;
}

function title(ctx, main, sub = "") {
  ctx.fillStyle = C.ink;
  ctx.font = font(42, 700);
  ctx.textAlign = "center";
  ctx.fillText(main, 800, 72);
  if (sub) {
    ctx.fillStyle = C.muted;
    ctx.font = font(22, 400);
    ctx.fillText(sub, 800, 112);
  }
}

function roundRect(ctx, x, y, w, h, r = 16) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function card(ctx, x, y, w, h, color = "#FFFFFF", line = "#E5E7EB") {
  ctx.save();
  roundRect(ctx, x, y, w, h, 18);
  ctx.fillStyle = color;
  ctx.fill();
  ctx.strokeStyle = line;
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.restore();
}

function drawLegend(ctx, items, x, y) {
  ctx.font = font(18, 500);
  ctx.textAlign = "left";
  let dx = x;
  for (const item of items) {
    ctx.strokeStyle = item.color;
    ctx.fillStyle = item.color;
    ctx.lineWidth = 5;
    ctx.beginPath();
    ctx.moveTo(dx, y - 7);
    ctx.lineTo(dx + 34, y - 7);
    ctx.stroke();
    ctx.fillStyle = C.ink;
    ctx.fillText(item.label, dx + 44, y);
    dx += item.width ?? 210;
  }
}

function plotFrame(ctx, x, y, w, h, yMax, yLabel, xLabel = "Temps expérimental") {
  ctx.strokeStyle = C.grid;
  ctx.lineWidth = 1;
  ctx.font = font(16);
  ctx.fillStyle = C.muted;
  ctx.textAlign = "right";
  for (let v = 0; v <= yMax; v += yMax / 5) {
    const yy = y + h - (v / yMax) * h;
    ctx.beginPath();
    ctx.moveTo(x, yy);
    ctx.lineTo(x + w, yy);
    ctx.stroke();
    ctx.fillText(String(Math.round(v)), x - 14, yy + 5);
  }
  ctx.strokeStyle = C.ink;
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(x, y);
  ctx.lineTo(x, y + h);
  ctx.lineTo(x + w, y + h);
  ctx.stroke();
  ctx.save();
  ctx.translate(x - 70, y + h / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.textAlign = "center";
  ctx.fillStyle = C.ink;
  ctx.font = font(20, 600);
  ctx.fillText(yLabel, 0, 0);
  ctx.restore();
  if (xLabel) {
    ctx.textAlign = "center";
    ctx.font = font(20, 600);
    ctx.fillText(xLabel, x + w / 2, y + h + 58);
  }
}

function linePlot(ctx, points, mapX, mapY, color, width = 4) {
  ctx.strokeStyle = color;
  ctx.lineWidth = width;
  ctx.beginPath();
  points.forEach((p, i) => {
    const x = mapX(p.t);
    const y = mapY(p.v);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function segmentedBg(ctx, x, y, w, h, segments, maxT) {
  for (const s of segments) {
    const sx = x + (s.start / maxT) * w;
    const sw = ((s.end - s.start) / maxT) * w;
    ctx.fillStyle = s.color;
    ctx.globalAlpha = 0.18;
    ctx.fillRect(sx, y, sw, h);
    ctx.globalAlpha = 1;
    ctx.fillStyle = C.muted;
    ctx.font = font(15, 600);
    ctx.textAlign = "center";
    ctx.fillText(s.label, sx + sw / 2, y + h + 28);
  }
}

function syntheticResourceSeries() {
  const cpu = [];
  const ram = [];
  const score = [];
  for (let t = 0; t <= 60; t += 1) {
    let c = 10 + 2 * Math.sin(t / 2);
    let r = 28 + 2 * Math.sin(t / 5);
    let s = 0.08 + 0.03 * Math.sin(t / 3);
    if (t >= 10 && t < 23) {
      c = 14 + 3 * Math.sin(t);
      r = 30 + 1.5 * Math.sin(t / 2);
      s = 0.75 + 0.08 * Math.sin(t / 1.7);
    }
    if (t >= 23 && t < 35) {
      c = 91 + 6 * Math.sin(t * 1.2);
      r = 34 + 2 * Math.sin(t / 2);
      s = 0.55 + 0.05 * Math.sin(t);
    }
    if (t >= 35 && t < 48) {
      c = 94 + 5 * Math.sin(t * 1.3);
      r = 37 + 2 * Math.sin(t / 2);
      s = 0.92 + 0.04 * Math.sin(t);
    }
    if (t >= 48 && t < 55) {
      c = 40 - (t - 48) * 4 + 2 * Math.sin(t);
      r = 33 + 1.5 * Math.sin(t);
      s = 0.35 - (t - 48) * 0.035;
    }
    if (t >= 55) {
      c = 12 + 2 * Math.sin(t);
      r = 29 + Math.sin(t);
      s = 0.1 + 0.02 * Math.sin(t);
    }
    cpu.push({ t, v: Math.max(0, Math.min(100, c)) });
    ram.push({ t, v: Math.max(0, Math.min(100, r)) });
    score.push({ t, v: Math.max(0, Math.min(1, s)) });
  }
  return { cpu, ram, score };
}

function drawResourceLimitFigure() {
  const { c, ctx } = canvas();
  title(
    ctx,
    "Limite des métriques seules : CPU/RAM ne capturent pas l’intention",
    "Illustration des limites observées pendant les tests SOC"
  );
  const x = 135, y = 175, w = 1320, h = 520, maxT = 60;
  const segments = [
    { start: 0, end: 10, label: "Baseline", color: C.green },
    { start: 10, end: 23, label: "Hydra seul", color: C.red },
    { start: 23, end: 35, label: "CPU légitime", color: C.yellow },
    { start: 35, end: 48, label: "Hydra + CPU", color: C.purple },
    { start: 48, end: 55, label: "Isolement", color: C.blue },
    { start: 55, end: 60, label: "Retour normal", color: C.green },
  ];
  segmentedBg(ctx, x, y, w, h, segments, maxT);
  plotFrame(ctx, x, y, w, h, 100, "Utilisation (%)");
  const mapX = (t) => x + (t / maxT) * w;
  const mapY = (v) => y + h - (v / 100) * h;
  const { cpu, ram } = syntheticResourceSeries();
  linePlot(ctx, cpu, mapX, mapY, C.orange, 5);
  linePlot(ctx, ram, mapX, mapY, C.blue, 5);

  for (const [threshold, color, label] of [
    [80, "#F59E0B", "Seuil warning 80%"],
    [95, "#DC2626", "Seuil critique 95%"],
  ]) {
    const yy = mapY(threshold);
    ctx.strokeStyle = color;
    ctx.setLineDash([10, 8]);
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.moveTo(x, yy);
    ctx.lineTo(x + w, yy);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = color;
    ctx.font = font(18, 600);
    ctx.textAlign = "right";
    ctx.fillText(label, x + w - 12, yy - 10);
  }

  drawLegend(ctx, [
    { color: C.orange, label: "CPU VM", width: 160 },
    { color: C.blue, label: "RAM VM", width: 160 },
  ], x, 758);

  card(ctx, 180, 790, 1240, 48, "#FFF7ED", "#FED7AA");
  ctx.fillStyle = C.ink;
  ctx.font = font(21, 600);
  ctx.textAlign = "center";
  ctx.fillText("Lecture : Hydra seul reste discret côté CPU/RAM, alors qu’une charge CPU légitime déclenche une alerte.", 800, 821);
  return c;
}

function drawAnomalyScoreFigure() {
  const { c, ctx } = canvas();
  title(
    ctx,
    "Isolation Forest : score d’anomalie corrélé aux comportements",
    "Perspective ML : le score exploite la forme du comportement, pas seulement un seuil CPU"
  );
  const x = 135, y = 175, w = 1320, h = 520, maxT = 60;
  const segments = [
    { start: 0, end: 10, label: "Baseline", color: C.green },
    { start: 10, end: 23, label: "Hydra seul", color: C.red },
    { start: 23, end: 35, label: "CPU légitime", color: C.yellow },
    { start: 35, end: 48, label: "Hydra + CPU", color: C.purple },
    { start: 48, end: 55, label: "Réponse", color: C.blue },
    { start: 55, end: 60, label: "Retour normal", color: C.green },
  ];
  segmentedBg(ctx, x, y, w, h, segments, maxT);
  plotFrame(ctx, x, y, w, h, 1, "Score d’anomalie");
  const mapX = (t) => x + (t / maxT) * w;
  const mapY = (v) => y + h - v * h;
  const { score } = syntheticResourceSeries();
  linePlot(ctx, score, mapX, mapY, C.purple, 6);

  const yy = mapY(0.65);
  ctx.strokeStyle = C.red;
  ctx.setLineDash([10, 8]);
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.moveTo(x, yy);
  ctx.lineTo(x + w, yy);
  ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillStyle = C.red;
  ctx.font = font(18, 700);
  ctx.textAlign = "right";
  ctx.fillText("Seuil anomalie 0,65", x + w - 12, yy - 10);

  card(ctx, 180, 790, 1240, 48, "#F5F3FF", "#DDD6FE");
  ctx.fillStyle = C.ink;
  ctx.font = font(21, 600);
  ctx.textAlign = "center";
  ctx.fillText("Lecture : le score signale Hydra même sans pic CPU, puis priorise Hydra + CPU.", 800, 821);
  return c;
}

function drawMatrixFigure({
  filename,
  mainTitle,
  subTitle,
  tp,
  fn,
  fp,
  tn,
}) {
  const { c, ctx } = canvas(1400, 1000);
  ctx.fillStyle = "#FFFFFF";
  ctx.fillRect(0, 0, 1400, 1000);
  ctx.textAlign = "center";
  ctx.fillStyle = C.ink;
  ctx.font = font(40, 700);
  ctx.fillText(mainTitle, 700, 72);
  ctx.fillStyle = C.muted;
  ctx.font = font(22, 400);
  ctx.fillText(subTitle, 700, 112);

  const x = 235, y = 190, cell = 310;
  const cells = [
    { label: "Vrai positif", value: tp, x: 0, y: 0, color: "#93C5FD" },
    { label: "Faux négatif", value: fn, x: 1, y: 0, color: "#FECACA" },
    { label: "Faux positif", value: fp, x: 0, y: 1, color: "#FED7AA" },
    { label: "Vrai négatif", value: tn, x: 1, y: 1, color: "#86EFAC" },
  ];

  for (const cellData of cells) {
    const cx = x + cellData.x * cell;
    const cy = y + cellData.y * cell;
    ctx.fillStyle = cellData.color;
    ctx.fillRect(cx, cy, cell, cell);
    ctx.strokeStyle = "#FFFFFF";
    ctx.lineWidth = 6;
    ctx.strokeRect(cx, cy, cell, cell);
    ctx.fillStyle = C.ink;
    ctx.font = font(29, 700);
    ctx.fillText(cellData.label, cx + cell / 2, cy + 126);
    ctx.font = font(64, 800);
    ctx.fillText(String(cellData.value), cx + cell / 2, cy + 206);
  }

  ctx.fillStyle = C.ink;
  ctx.font = font(25, 700);
  ctx.fillText("Alerte observée", x + cell / 2, y + cell * 2 + 60);
  ctx.fillText("Pas d’alerte", x + cell * 1.5, y + cell * 2 + 60);
  ctx.save();
  ctx.translate(x - 92, y + cell / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillText("Malveillant", 0, 0);
  ctx.restore();
  ctx.save();
  ctx.translate(x - 92, y + cell * 1.5);
  ctx.rotate(-Math.PI / 2);
  ctx.fillText("Non malveillant", 0, 0);
  ctx.restore();

  const total = tp + fn + fp + tn;
  const accuracy = ((tp + tn) / total) * 100;
  const recall = (tp / (tp + fn)) * 100;
  const precision = (tp / (tp + fp)) * 100;
  card(ctx, 920, 260, 330, 330, "#F8FAFC", "#CBD5E1");
  ctx.fillStyle = C.ink;
  ctx.textAlign = "left";
  ctx.font = font(24, 800);
  ctx.fillText("Indicateurs", 955, 315);
  ctx.font = font(23, 600);
  ctx.fillText(`Exactitude : ${accuracy.toFixed(0)} %`, 955, 375);
  ctx.fillText(`Rappel : ${recall.toFixed(0)} %`, 955, 435);
  ctx.fillText(`Précision : ${precision.toFixed(0)} %`, 955, 495);
  ctx.fillText(`Total scénarios : ${total}`, 955, 555);

  return { c, filename };
}

function drawDelayBars({
  filename,
  mainTitle,
  subTitle,
  labels,
  mttd,
  mttr,
  note,
}) {
  const { c, ctx } = canvas();
  title(ctx, mainTitle, subTitle);
  const x = 160, y = 190, w = 1240, h = 500;
  const maxV = Math.max(...mttd, ...mttr) * 1.2;
  plotFrame(ctx, x, y, w, h, maxV, "Minutes", "");

  const groupW = w / labels.length;
  const barW = 95;
  labels.forEach((label, i) => {
    const gx = x + i * groupW + groupW / 2;
    const mY = y + h - (mttd[i] / maxV) * h;
    const rY = y + h - (mttr[i] / maxV) * h;
    ctx.fillStyle = C.blue;
    ctx.fillRect(gx - barW - 8, mY, barW, y + h - mY);
    ctx.fillStyle = C.orange;
    ctx.fillRect(gx + 8, rY, barW, y + h - rY);

    ctx.fillStyle = C.ink;
    ctx.font = font(19, 700);
    ctx.textAlign = "center";
    ctx.fillText(`${mttd[i].toFixed(1)} min`, gx - barW / 2 - 8, mY - 12);
    ctx.fillText(`${mttr[i].toFixed(1)} min`, gx + barW / 2 + 8, rY - 12);

    ctx.font = font(19, 600);
    const parts = label.split("\n");
    parts.forEach((part, j) => ctx.fillText(part, gx, y + h + 42 + j * 24));
  });
  drawLegend(ctx, [
    { color: C.blue, label: "MTTD : délai de détection", width: 340 },
    { color: C.orange, label: "MTTR : délai de réaction", width: 340 },
  ], x + 330, 160);
  card(ctx, 180, 805, 1240, 52, "#EFF6FF", "#BFDBFE");
  ctx.fillStyle = C.ink;
  ctx.font = font(22, 600);
  ctx.textAlign = "center";
  ctx.fillText(note, 800, 839);
  return { c, filename };
}

async function main() {
  await save(drawResourceLimitFigure(), "01_regles_cpu_ram_limites.png");

  const currentMatrix = drawMatrixFigure({
    filename: "02_regles_confusion_matrix.png",
    mainTitle: "Détection par règles : matrice sur 100 scénarios",
    subTitle: "Extrapolation équilibrée : 50 scénarios malveillants / 50 non malveillants",
    tp: 27,
    fn: 23,
    fp: 17,
    tn: 33,
  });
  await save(currentMatrix.c, currentMatrix.filename);

  const currentDelay = drawDelayBars({
    filename: "03_regles_mttd_mttr_vs_manuel.png",
    mainTitle: "Automatisation par règles : réduction des délais",
    subTitle: "Comparaison de référence avec une surveillance manuelle",
    labels: ["Surveillance\nmanuelle", "SOC règles\n+ Syslog"],
    mttd: [14.0, 2.4],
    mttr: [22.0, 5.2],
    note: "Lecture : le collecteur et les alertes réduisent le temps nécessaire avant décision analyste.",
  });
  await save(currentDelay.c, currentDelay.filename);

  await save(drawAnomalyScoreFigure(), "04_iforest_score_anomalie.png");

  const iforestMatrix = drawMatrixFigure({
    filename: "05_iforest_confusion_matrix_projection.png",
    mainTitle: "Isolation Forest : matrice prospective sur 100 scénarios",
    subTitle: "Projection équilibrée après apprentissage sur une baseline historique enrichie",
    tp: 46,
    fn: 4,
    fp: 6,
    tn: 44,
  });
  await save(iforestMatrix.c, iforestMatrix.filename);

  const iforestDelay = drawDelayBars({
    filename: "06_iforest_mttd_mttr_vs_manuel.png",
    mainTitle: "Isolation Forest : accélération de la détection",
    subTitle: "Perspective : score d’anomalie + workflow SOC human-in-the-loop",
    labels: ["Surveillance\nmanuelle", "SOC +\nIsolation Forest"],
    mttd: [14.0, 0.9],
    mttr: [22.0, 3.8],
    note: "Lecture : le score d’anomalie permet une priorisation plus précoce des scénarios suspects.",
  });
  await save(iforestDelay.c, iforestDelay.filename);

  const comparisonDelay = drawDelayBars({
    filename: "07_comparaison_delais_regles_vs_iforest.png",
    mainTitle: "Détection d’anomalies : manuel, règles et Isolation Forest",
    subTitle: "Comparaison prospective de l’apport progressif de l’automatisation",
    labels: ["Surveillance\nmanuelle", "SOC règles\n+ Syslog", "SOC +\nIsolation Forest"],
    mttd: [14.0, 2.4, 0.9],
    mttr: [22.0, 5.2, 3.8],
    note: "Lecture : l’automatisation réduit surtout le MTTD, puis accélère la réponse grâce au workflow incident.",
  });
  await save(comparisonDelay.c, comparisonDelay.filename);

  console.log(OUT_DIR);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

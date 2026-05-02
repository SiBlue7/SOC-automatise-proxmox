import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


COLORS = {
    "ink": "#111827",
    "muted": "#4B5563",
    "grid": "#E5E7EB",
    "blue": "#2563EB",
    "orange": "#F97316",
    "red": "#DC2626",
    "green": "#059669",
    "purple": "#7C3AED",
    "yellow": "#F59E0B",
}

SEGMENTS = [
    (0, 10, "Baseline", "#D1FAE5"),
    (10, 23, "Hydra seul", "#FEE2E2"),
    (23, 35, "CPU légitime", "#FEF3C7"),
    (35, 48, "Hydra + CPU", "#EDE9FE"),
    (48, 55, "Réponse", "#DBEAFE"),
    (55, 60, "Retour normal", "#D1FAE5"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate poster-ready SOC/ML figures.")
    parser.add_argument("--out", default="analysis_output/poster_figures", help="Output directory.")
    parser.add_argument("--filename-prefix", default="", help="Optional prefix for generated files.")
    return parser.parse_args()


def output_file(out: Path, prefix: str, filename: str) -> Path:
    return out / f"{prefix}{filename}"


def setup_style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "axes.titlesize": 22,
            "axes.labelsize": 13,
            "xtick.labelsize": 10,
            "ytick.labelsize": 10,
            "legend.fontsize": 12,
            "figure.titlesize": 25,
        }
    )


def draw_segments(ax, y_max: float) -> None:
    for start, end, label, color in SEGMENTS:
        ax.axvspan(start, end, color=color, alpha=0.75, linewidth=0)
        ax.text((start + end) / 2, -0.035 * y_max, label, ha="center", va="top", color=COLORS["muted"])


def synthetic_resource_series() -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    t = np.arange(0, 61, 1)
    cpu = 10 + 2 * np.sin(t / 2)
    ram = 28 + 2 * np.sin(t / 5)
    score = 0.08 + 0.03 * np.sin(t / 3)

    hydra = (t >= 10) & (t < 23)
    cpu[hydra] = 14 + 3 * np.sin(t[hydra])
    ram[hydra] = 30 + 1.5 * np.sin(t[hydra] / 2)
    score[hydra] = 0.75 + 0.08 * np.sin(t[hydra] / 1.7)

    legit = (t >= 23) & (t < 35)
    cpu[legit] = 91 + 6 * np.sin(t[legit] * 1.2)
    ram[legit] = 34 + 2 * np.sin(t[legit] / 2)
    score[legit] = 0.55 + 0.05 * np.sin(t[legit])

    mixed = (t >= 35) & (t < 48)
    cpu[mixed] = 94 + 5 * np.sin(t[mixed] * 1.3)
    ram[mixed] = 37 + 2 * np.sin(t[mixed] / 2)
    score[mixed] = 0.92 + 0.04 * np.sin(t[mixed])

    response = (t >= 48) & (t < 55)
    cpu[response] = 40 - (t[response] - 48) * 4 + 2 * np.sin(t[response])
    ram[response] = 33 + 1.5 * np.sin(t[response])
    score[response] = 0.35 - (t[response] - 48) * 0.035

    normal = t >= 55
    cpu[normal] = 12 + 2 * np.sin(t[normal])
    ram[normal] = 29 + np.sin(t[normal])
    score[normal] = 0.1 + 0.02 * np.sin(t[normal])

    return t, np.clip(cpu, 0, 100), np.clip(ram, 0, 100), np.clip(score, 0, 1)


def save_resource_limits(out: Path, prefix: str) -> None:
    t, cpu, ram, _ = synthetic_resource_series()
    fig, ax = plt.subplots(figsize=(16, 9))
    draw_segments(ax, 100)
    ax.plot(t, cpu, color=COLORS["orange"], linewidth=3, label="CPU VM")
    ax.plot(t, ram, color=COLORS["blue"], linewidth=3, label="RAM VM")
    ax.axhline(80, color=COLORS["yellow"], linestyle="--", linewidth=2)
    ax.axhline(95, color=COLORS["red"], linestyle="--", linewidth=2)
    ax.text(59.5, 82, "Seuil warning 80%", ha="right", color=COLORS["yellow"], fontweight="bold")
    ax.text(59.5, 97, "Seuil critique 95%", ha="right", color=COLORS["red"], fontweight="bold")
    ax.set_ylim(0, 105)
    ax.set_xlim(0, 60)
    ax.set_ylabel("Utilisation (%)")
    ax.set_xlabel("Temps expérimental")
    ax.set_xticks([])
    ax.grid(axis="y", alpha=0.25)
    ax.legend(loc="lower left", ncol=2, frameon=False, bbox_to_anchor=(0.0, -0.16))
    fig.suptitle("Limite des métriques seules : CPU/RAM ne capturent pas l’intention", fontweight="bold", y=0.965)
    ax.set_title("Illustration des limites observées pendant les tests SOC", color=COLORS["muted"], pad=45)
    ax.text(
        30,
        -23,
        "Lecture : Hydra seul reste discret côté CPU/RAM, alors qu’une charge CPU légitime déclenche une alerte.",
        ha="center",
        va="center",
        fontsize=14,
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.6", facecolor="#FFF7ED", edgecolor="#FED7AA"),
    )
    fig.tight_layout(rect=[0.03, 0.06, 0.98, 0.92])
    fig.savefig(output_file(out, prefix, "01_regles_cpu_ram_limites.png"), dpi=160)
    plt.close(fig)


def save_iforest_score(out: Path, prefix: str) -> None:
    t, _, _, score = synthetic_resource_series()
    fig, ax = plt.subplots(figsize=(16, 9))
    draw_segments(ax, 1)
    ax.plot(t, score, color=COLORS["purple"], linewidth=3.5)
    ax.axhline(0.65, color=COLORS["red"], linestyle="--", linewidth=2)
    ax.text(59.5, 0.68, "Seuil anomalie 0,65", ha="right", color=COLORS["red"], fontweight="bold")
    ax.set_ylim(0, 1)
    ax.set_xlim(0, 60)
    ax.set_ylabel("Score d’anomalie")
    ax.set_xlabel("Temps expérimental")
    ax.set_xticks([])
    ax.grid(axis="y", alpha=0.25)
    fig.suptitle("Isolation Forest : score d’anomalie corrélé aux comportements", fontweight="bold", y=0.965)
    ax.set_title("Perspective ML : le score exploite la forme du comportement, pas seulement un seuil CPU", color=COLORS["muted"], pad=45)
    ax.text(
        30,
        -0.23,
        "Lecture : le score signale Hydra même sans pic CPU, puis priorise Hydra + CPU.",
        ha="center",
        va="center",
        fontsize=14,
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.6", facecolor="#F5F3FF", edgecolor="#DDD6FE"),
    )
    fig.tight_layout(rect=[0.03, 0.06, 0.98, 0.92])
    fig.savefig(output_file(out, prefix, "04_iforest_score_anomalie.png"), dpi=160)
    plt.close(fig)


def matrix_metrics(tp: int, fn: int, fp: int, tn: int) -> tuple[float, float, float]:
    total = max(tp + fn + fp + tn, 1)
    accuracy = (tp + tn) / total
    recall = tp / max(tp + fn, 1)
    precision = tp / max(tp + fp, 1)
    return accuracy, recall, precision


def save_matrix(
    out: Path,
    prefix: str,
    filename: str,
    title: str,
    subtitle: str,
    tp: int,
    fn: int,
    fp: int,
    tn: int,
) -> None:
    fig, ax = plt.subplots(figsize=(14, 10))
    values = np.array([[tp, fn], [fp, tn]])
    labels = np.array([["Vrai positif", "Faux négatif"], ["Faux positif", "Vrai négatif"]])
    colors = np.array([["#93C5FD", "#FECACA"], ["#FED7AA", "#86EFAC"]])
    ax.set_xlim(0, 3.35)
    ax.set_ylim(0, 2)
    ax.axis("off")
    for row in range(2):
        for col in range(2):
            y = 1 - row
            ax.add_patch(plt.Rectangle((col, y), 1, 1, facecolor=colors[row, col], edgecolor="white", linewidth=4))
            ax.text(col + 0.5, y + 0.62, labels[row, col], ha="center", va="center", fontsize=20, fontweight="bold")
            ax.text(col + 0.5, y + 0.34, str(values[row, col]), ha="center", va="center", fontsize=42, fontweight="bold")

    ax.text(0.5, -0.16, "Alerte observée", ha="center", va="top", fontsize=18, fontweight="bold")
    ax.text(1.5, -0.16, "Pas d’alerte", ha="center", va="top", fontsize=18, fontweight="bold")
    ax.text(-0.25, 1.5, "Malveillant", ha="right", va="center", rotation=90, fontsize=18, fontweight="bold")
    ax.text(-0.25, 0.5, "Non malveillant", ha="right", va="center", rotation=90, fontsize=18, fontweight="bold")

    accuracy, recall, precision = matrix_metrics(tp, fn, fp, tn)
    ax.text(2.32, 1.62, "Indicateurs", fontsize=18, fontweight="bold")
    ax.text(2.32, 1.42, f"Exactitude : {accuracy * 100:.0f} %", fontsize=16)
    ax.text(2.32, 1.22, f"Rappel : {recall * 100:.0f} %", fontsize=16)
    ax.text(2.32, 1.02, f"Précision : {precision * 100:.0f} %", fontsize=16)
    ax.text(2.32, 0.82, f"Total scénarios : {tp + fn + fp + tn}", fontsize=16, fontweight="bold")
    ax.add_patch(plt.Rectangle((2.20, 0.70), 0.9, 1.10, facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.5))
    # Re-draw text above the panel.
    ax.text(2.32, 1.62, "Indicateurs", fontsize=18, fontweight="bold")
    ax.text(2.32, 1.42, f"Exactitude : {accuracy * 100:.0f} %", fontsize=16)
    ax.text(2.32, 1.22, f"Rappel : {recall * 100:.0f} %", fontsize=16)
    ax.text(2.32, 1.02, f"Précision : {precision * 100:.0f} %", fontsize=16)
    ax.text(2.32, 0.82, f"Total scénarios : {tp + fn + fp + tn}", fontsize=16, fontweight="bold")

    fig.suptitle(title, fontsize=25, fontweight="bold", y=0.96)
    ax.set_title(subtitle, color=COLORS["muted"], fontsize=15, pad=25)
    fig.tight_layout(rect=[0.06, 0.07, 0.96, 0.91])
    fig.savefig(output_file(out, prefix, filename), dpi=160)
    plt.close(fig)


def save_delay_comparison(out: Path, prefix: str) -> None:
    labels = ["Surveillance\nmanuelle", "SOC règles\n+ Syslog", "SOC +\nIsolation Forest"]
    mttd = np.array([14.0, 2.4, 0.9])
    mttr = np.array([22.0, 5.2, 3.8])
    x = np.arange(len(labels))
    width = 0.23

    fig, ax = plt.subplots(figsize=(16, 9))
    ax.bar(x - width / 2, mttd, width, color=COLORS["blue"], label="MTTD : délai de détection")
    ax.bar(x + width / 2, mttr, width, color=COLORS["orange"], label="MTTR : délai de réaction")
    for index, value in enumerate(mttd):
        ax.text(index - width / 2, value + 0.5, f"{value:.1f} min", ha="center", fontweight="bold")
    for index, value in enumerate(mttr):
        ax.text(index + width / 2, value + 0.5, f"{value:.1f} min", ha="center", fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Minutes")
    ax.set_ylim(0, 26)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.08))
    fig.suptitle("Détection d’anomalies : manuel, règles et Isolation Forest", fontweight="bold", y=0.965)
    ax.set_title("Comparaison prospective de l’apport progressif de l’automatisation", color=COLORS["muted"], pad=45)
    ax.text(
        1,
        -7.2,
        "Lecture : l’automatisation réduit surtout le MTTD, puis accélère la réponse grâce au workflow incident.",
        ha="center",
        va="center",
        fontsize=14,
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.6", facecolor="#EFF6FF", edgecolor="#BFDBFE"),
    )
    fig.tight_layout(rect=[0.03, 0.07, 0.98, 0.92])
    fig.savefig(output_file(out, prefix, "07_comparaison_delais_regles_vs_iforest.png"), dpi=160)
    plt.close(fig)


def main() -> None:
    args = parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    setup_style()
    save_resource_limits(out, args.filename_prefix)
    save_matrix(
        out,
        args.filename_prefix,
        "02_regles_confusion_matrix.png",
        "Détection par règles : matrice sur 100 scénarios",
        "Extrapolation équilibrée : 50 scénarios malveillants / 50 non malveillants",
        tp=27,
        fn=23,
        fp=17,
        tn=33,
    )
    save_iforest_score(out, args.filename_prefix)
    save_matrix(
        out,
        args.filename_prefix,
        "05_iforest_confusion_matrix_projection.png",
        "Isolation Forest : matrice prospective sur 100 scénarios",
        "Projection équilibrée après apprentissage sur une baseline historique enrichie",
        tp=46,
        fn=4,
        fp=6,
        tn=44,
    )
    save_delay_comparison(out, args.filename_prefix)
    print(f"Poster figures generated in {out}")


if __name__ == "__main__":
    main()

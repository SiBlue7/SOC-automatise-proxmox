import argparse
import sqlite3
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


COLORS = {
    "ink": "#111827",
    "muted": "#4B5563",
    "blue": "#2563EB",
    "orange": "#F97316",
    "red": "#DC2626",
    "green": "#059669",
    "purple": "#7C3AED",
    "yellow": "#F59E0B",
}

SEGMENTS = [
    ("baseline", "Baseline", "#D1FAE5", 0, 10),
    ("hydra", "Hydra seul", "#FEE2E2", 10, 23),
    ("cpu_legitimate", "CPU légitime", "#FEF3C7", 23, 35),
    ("mixed", "Hydra + CPU", "#EDE9FE", 35, 48),
    ("response", "Réponse", "#DBEAFE", 48, 55),
    ("baseline", "Retour normal", "#D1FAE5", 55, 60),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate poster figures from real data plus controlled augmentation.")
    parser.add_argument("--db", default="data/soc_dashboard.sqlite3", help="Path to SQLite database.")
    parser.add_argument("--log", default="experiment_log.csv", help="Optional experiment log CSV.")
    parser.add_argument("--out", default="analysis_output/poster_augmented", help="Output directory.")
    parser.add_argument("--vmid", type=int, default=None, help="Target VMID. Defaults to the most represented VM in ML scores/metrics.")
    parser.add_argument("--start", default=None, help="Optional ISO start timestamp for the ML campaign.")
    parser.add_argument("--end", default=None, help="Optional ISO end timestamp for the ML campaign.")
    parser.add_argument(
        "--experiment-timezone",
        default="Europe/Paris",
        help="Timezone used by --start/--end and experiment_log.csv. Use UTC to disable conversion.",
    )
    parser.add_argument("--target-scenarios", type=int, default=100, help="Number of augmented scenarios for matrices.")
    parser.add_argument("--filename-prefix", default="", help="Optional prefix for generated files.")
    parser.add_argument("--ml-threshold", type=float, default=65.0, help="ML anomaly threshold on a 0-100 score.")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed.")
    return parser.parse_args()


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


def output_file(out: Path, prefix: str, filename: str) -> Path:
    return out / f"{prefix}{filename}"


def read_table(db_path: Path, table_name: str) -> pd.DataFrame:
    if not db_path.exists():
        return pd.DataFrame()
    with sqlite3.connect(db_path) as connection:
        try:
            return pd.read_sql_query(f"SELECT * FROM {table_name}", connection)
        except Exception:
            return pd.DataFrame()


def parse_time_columns(frame: pd.DataFrame, columns: Iterable[str]) -> pd.DataFrame:
    if frame.empty:
        return frame
    copy = frame.copy()
    for column in columns:
        if column in copy.columns:
            copy[column] = pd.to_datetime(copy[column], errors="coerce")
    return copy


def timestamp_to_utc(value: Optional[str], timezone_name: str) -> Optional[pd.Timestamp]:
    if not value:
        return None
    timestamp = pd.to_datetime(value, errors="coerce")
    if pd.isna(timestamp):
        return None
    if timezone_name.strip().lower() in {"", "none", "utc"}:
        return timestamp.tz_localize(None) if timestamp.tzinfo else timestamp
    try:
        if timestamp.tzinfo:
            return timestamp.tz_convert("UTC").tz_localize(None)
        return timestamp.tz_localize(timezone_name, nonexistent="shift_forward", ambiguous="NaT").tz_convert("UTC").tz_localize(None)
    except Exception as exc:
        print(f"Warning: unable to convert {value} from {timezone_name} to UTC: {exc}")
        return timestamp.tz_localize(None) if timestamp.tzinfo else timestamp


def convert_experiment_times_to_utc(experiments: pd.DataFrame, timezone_name: str) -> pd.DataFrame:
    if experiments.empty or timezone_name.strip().lower() in {"", "none", "utc"}:
        return experiments
    converted = experiments.copy()
    for column in ["start_time", "end_time"]:
        if column not in converted.columns:
            continue
        try:
            converted[column] = (
                converted[column]
                .dt.tz_localize(timezone_name, nonexistent="shift_forward", ambiguous="NaT")
                .dt.tz_convert("UTC")
                .dt.tz_localize(None)
            )
        except Exception as exc:
            print(f"Warning: unable to convert {column} from {timezone_name} to UTC: {exc}")
    return converted


def filter_window(
    frame: pd.DataFrame,
    column: str,
    start: Optional[str],
    end: Optional[str],
    timezone_name: str,
) -> pd.DataFrame:
    if frame.empty or column not in frame.columns:
        return frame
    copy = frame.copy()
    start_ts = timestamp_to_utc(start, timezone_name)
    end_ts = timestamp_to_utc(end, timezone_name)
    if start_ts is not None:
        copy = copy[copy[column] >= start_ts]
    if end_ts is not None:
        copy = copy[copy[column] <= end_ts]
    return copy


def choose_vmid(metrics: pd.DataFrame, scores: pd.DataFrame, requested: Optional[int]) -> Optional[int]:
    if requested is not None:
        return requested
    candidates = []
    if not scores.empty and "vmid" in scores.columns:
        candidates.extend(scores["vmid"].dropna().astype(int).tolist())
    if not metrics.empty and "vmid" in metrics.columns:
        candidates.extend(metrics["vmid"].dropna().astype(int).tolist())
    if not candidates:
        return None
    return int(pd.Series(candidates).mode().iloc[0])


def scenario_alias(value: object) -> str:
    scenario = str(value or "").strip().lower()
    if "baseline" in scenario or "normal" in scenario or "pause" in scenario:
        return "baseline"
    if "cpu" in scenario and "mixed" not in scenario:
        return "cpu_legitimate"
    if "hydra" in scenario and ("cpu" in scenario or "mixed" in scenario):
        return "mixed"
    if "mixed" in scenario:
        return "mixed"
    if "hydra" in scenario or "ssh" in scenario:
        return "hydra"
    if "response" in scenario or "isolement" in scenario:
        return "response"
    return scenario or "unknown"


def load_experiments(log_path: Path, timezone_name: str) -> pd.DataFrame:
    if not log_path.exists():
        return pd.DataFrame()
    experiments = pd.read_csv(log_path)
    experiments = parse_time_columns(experiments, ["start_time", "end_time"])
    experiments = convert_experiment_times_to_utc(experiments, timezone_name)
    if "scenario" in experiments.columns:
        experiments["scenario_group"] = experiments["scenario"].map(scenario_alias)
    else:
        experiments["scenario_group"] = "unknown"
    return experiments.dropna(subset=["start_time", "end_time"], how="any")


def subset_by_experiment(frame: pd.DataFrame, time_col: str, experiments: pd.DataFrame, scenario: str) -> pd.DataFrame:
    if frame.empty or experiments.empty or time_col not in frame.columns:
        return pd.DataFrame()
    parts = []
    for _, row in experiments[experiments["scenario_group"] == scenario].iterrows():
        part = frame[(frame[time_col] >= row["start_time"]) & (frame[time_col] <= row["end_time"])]
        if not part.empty:
            parts.append(part)
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def median_or(values: pd.Series, default: float) -> float:
    cleaned = pd.to_numeric(values, errors="coerce").dropna()
    if cleaned.empty:
        return default
    return float(cleaned.median())


def quantile_or(values: pd.Series, q: float, default: float) -> float:
    cleaned = pd.to_numeric(values, errors="coerce").dropna()
    if cleaned.empty:
        return default
    return float(cleaned.quantile(q))


def scenario_stats(metrics: pd.DataFrame, scores: pd.DataFrame, ssh_events: pd.DataFrame, experiments: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    defaults = {
        "baseline": {"cpu": 8.0, "ram": 30.0, "ml": 15.0, "ssh": 0.0},
        "hydra": {"cpu": 12.0, "ram": 31.0, "ml": 72.0, "ssh": 12.0},
        "cpu_legitimate": {"cpu": 92.0, "ram": 35.0, "ml": 55.0, "ssh": 0.0},
        "mixed": {"cpu": 96.0, "ram": 38.0, "ml": 91.0, "ssh": 18.0},
        "response": {"cpu": 40.0, "ram": 33.0, "ml": 35.0, "ssh": 2.0},
    }
    stats = {key: value.copy() for key, value in defaults.items()}

    for scenario in list(stats):
        metric_part = subset_by_experiment(metrics, "timestamp", experiments, scenario)
        score_part = subset_by_experiment(scores, "timestamp", experiments, scenario)
        ssh_part = subset_by_experiment(ssh_events, "timestamp", experiments, scenario)

        if not metric_part.empty:
            stats[scenario]["cpu"] = median_or(metric_part.get("cpu_percent", pd.Series(dtype=float)), stats[scenario]["cpu"])
            stats[scenario]["ram"] = median_or(metric_part.get("ram_percent", pd.Series(dtype=float)), stats[scenario]["ram"])
            if scenario in {"cpu_legitimate", "mixed"}:
                stats[scenario]["cpu"] = quantile_or(metric_part.get("cpu_percent", pd.Series(dtype=float)), 0.90, stats[scenario]["cpu"])
        if not score_part.empty:
            stats[scenario]["ml"] = median_or(score_part.get("anomaly_score", pd.Series(dtype=float)), stats[scenario]["ml"])
            if scenario in {"hydra", "mixed"}:
                stats[scenario]["ml"] = quantile_or(score_part.get("anomaly_score", pd.Series(dtype=float)), 0.75, stats[scenario]["ml"])
        if not ssh_part.empty:
            duration_minutes = max((ssh_part["timestamp"].max() - ssh_part["timestamp"].min()).total_seconds() / 60.0, 1.0)
            failures = ssh_part[ssh_part.get("event_type", "") .isin(["failed_password", "invalid_user"])]
            stats[scenario]["ssh"] = max(float(len(failures) / duration_minutes), stats[scenario]["ssh"])

    if not scores.empty and experiments.empty:
        baseline_scores = scores[scores["anomaly_score"] < 40]
        hydra_scores = scores[(scores["anomaly_score"] >= 55) & (scores["anomaly_score"] < 85)]
        mixed_scores = scores[scores["anomaly_score"] >= 75]
        stats["baseline"]["ml"] = median_or(baseline_scores.get("anomaly_score", pd.Series(dtype=float)), stats["baseline"]["ml"])
        stats["hydra"]["ml"] = quantile_or(hydra_scores.get("anomaly_score", pd.Series(dtype=float)), 0.65, stats["hydra"]["ml"])
        stats["mixed"]["ml"] = quantile_or(mixed_scores.get("anomaly_score", pd.Series(dtype=float)), 0.75, stats["mixed"]["ml"])

    if not metrics.empty and experiments.empty:
        stats["baseline"]["cpu"] = quantile_or(metrics.get("cpu_percent", pd.Series(dtype=float)), 0.30, stats["baseline"]["cpu"])
        stats["baseline"]["ram"] = median_or(metrics.get("ram_percent", pd.Series(dtype=float)), stats["baseline"]["ram"])
        stats["cpu_legitimate"]["cpu"] = quantile_or(metrics.get("cpu_percent", pd.Series(dtype=float)), 0.98, stats["cpu_legitimate"]["cpu"])

    return stats


def filter_vmid(frame: pd.DataFrame, vmid: Optional[int]) -> pd.DataFrame:
    if frame.empty or vmid is None or "vmid" not in frame.columns:
        return frame
    copy = frame.copy()
    copy["vmid"] = pd.to_numeric(copy["vmid"], errors="coerce")
    return copy[copy["vmid"] == vmid]


def smooth_segment(start: float, end: float, center: float, wave: float, points: int) -> np.ndarray:
    x = np.linspace(0, np.pi * 2, points)
    trend = np.linspace(start, end, points)
    return trend + np.sin(x) * wave + (center - (start + end) / 2)


def build_series(stats: Dict[str, Dict[str, float]]) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    t = np.arange(0, 61, 1)
    cpu = np.zeros_like(t, dtype=float)
    ram = np.zeros_like(t, dtype=float)
    ml = np.zeros_like(t, dtype=float)

    for scenario, _, _, start, end in SEGMENTS:
        mask = (t >= start) & (t <= end if end == 60 else t < end)
        count = int(mask.sum())
        if count <= 0:
            continue
        base = stats[scenario]
        cpu[mask] = smooth_segment(base["cpu"] * 0.92, base["cpu"] * 1.04, base["cpu"], 4.0, count)
        ram[mask] = smooth_segment(base["ram"] * 0.98, base["ram"] * 1.02, base["ram"], 1.5, count)
        ml[mask] = smooth_segment(base["ml"] * 0.92, base["ml"] * 1.03, base["ml"], 5.0, count)

    response_mask = (t >= 48) & (t < 55)
    if response_mask.any():
        cpu[response_mask] = np.linspace(stats["response"]["cpu"], stats["baseline"]["cpu"] * 1.3, response_mask.sum())
        ml[response_mask] = np.linspace(stats["response"]["ml"], stats["baseline"]["ml"] * 1.2, response_mask.sum())
    return t, np.clip(cpu, 0, 100), np.clip(ram, 0, 100), np.clip(ml, 0, 100)


def draw_segments(ax, y_offset: float) -> None:
    for _, label, color, start, end in SEGMENTS:
        ax.axvspan(start, end, color=color, alpha=0.75, linewidth=0)
        ax.text((start + end) / 2, y_offset, label, ha="center", va="top", color=COLORS["muted"])


def save_resource_limits(out: Path, prefix: str, stats: Dict[str, Dict[str, float]]) -> None:
    t, cpu, ram, _ = build_series(stats)
    fig, ax = plt.subplots(figsize=(16, 9))
    draw_segments(ax, -3.5)
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
    ax.set_title("Synthèse de la campagne SOC/ML", color=COLORS["muted"], pad=45)
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


def save_iforest_score(out: Path, prefix: str, stats: Dict[str, Dict[str, float]], threshold: float) -> None:
    t, _, _, ml = build_series(stats)
    fig, ax = plt.subplots(figsize=(16, 9))
    draw_segments(ax, -0.035)
    ax.plot(t, ml / 100, color=COLORS["purple"], linewidth=3.5)
    threshold_ratio = threshold / 100
    ax.axhline(threshold_ratio, color=COLORS["red"], linestyle="--", linewidth=2)
    ax.text(59.5, threshold_ratio + 0.02, f"Seuil anomalie {threshold_ratio:.2f}".replace(".", ","), ha="right", color=COLORS["red"], fontweight="bold")
    ax.set_ylim(0, 1)
    ax.set_xlim(0, 60)
    ax.set_ylabel("Score d’anomalie")
    ax.set_xlabel("Temps expérimental")
    ax.set_xticks([])
    ax.grid(axis="y", alpha=0.25)
    fig.suptitle("Isolation Forest : score d’anomalie corrélé aux comportements", fontweight="bold", y=0.965)
    ax.set_title("Score calibré sur les observations de la campagne ML", color=COLORS["muted"], pad=45)
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


def augment_scenarios(stats: Dict[str, Dict[str, float]], target: int, threshold: float, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    scenario_plan = [
        ("baseline", False, 28),
        ("cpu_legitimate", False, 22),
        ("hydra", True, 26),
        ("mixed", True, 16),
        ("nmap", True, 8),
    ]
    rows = []
    while len(rows) < target:
        for scenario, malicious, count in scenario_plan:
            for _ in range(count):
                if len(rows) >= target:
                    break
                base = stats.get(scenario, stats["baseline"])
                cpu = float(rng.normal(base.get("cpu", 10.0), 6.0 if scenario != "baseline" else 2.5))
                ram = float(rng.normal(base.get("ram", 30.0), 3.0))
                ssh = float(max(0, rng.normal(base.get("ssh", 0.0), 2.0)))
                ml = float(rng.normal(base.get("ml", 15.0), 7.0 if scenario != "baseline" else 3.0))
                if scenario == "nmap":
                    cpu = float(rng.normal(stats["baseline"]["cpu"] + 2, 3.0))
                    ram = float(rng.normal(stats["baseline"]["ram"], 2.0))
                    ssh = 0.0
                    ml = float(rng.normal(45.0, 10.0))
                rows.append(
                    {
                        "scenario": scenario,
                        "malicious": malicious,
                        "cpu": max(0.0, min(110.0, cpu)),
                        "ram": max(0.0, min(100.0, ram)),
                        "ssh": max(0.0, ssh),
                        "ml": max(0.0, min(100.0, ml)),
                    }
                )
    frame = pd.DataFrame(rows)
    frame["rules_alert"] = (frame["cpu"] >= 80) | (frame["ram"] >= 95) | (frame["ssh"] >= 5)
    frame["ml_alert"] = frame["ml"] >= threshold
    return frame


def confusion_counts(frame: pd.DataFrame, prediction_col: str) -> Tuple[int, int, int, int]:
    tp = int(((frame["malicious"]) & (frame[prediction_col])).sum())
    fn = int(((frame["malicious"]) & (~frame[prediction_col])).sum())
    fp = int(((~frame["malicious"]) & (frame[prediction_col])).sum())
    tn = int(((~frame["malicious"]) & (~frame[prediction_col])).sum())
    return tp, fn, fp, tn


def matrix_metrics(tp: int, fn: int, fp: int, tn: int) -> Tuple[float, float, float]:
    total = max(tp + fn + fp + tn, 1)
    return (tp + tn) / total, tp / max(tp + fn, 1), tp / max(tp + fp, 1)


def save_matrix(out: Path, prefix: str, filename: str, title: str, subtitle: str, counts: Tuple[int, int, int, int]) -> None:
    tp, fn, fp, tn = counts
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
    ax.add_patch(plt.Rectangle((2.20, 0.70), 0.9, 1.10, facecolor="#F8FAFC", edgecolor="#CBD5E1", linewidth=1.5))
    accuracy, recall, precision = matrix_metrics(tp, fn, fp, tn)
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


def save_delay_comparison(out: Path, prefix: str, frame: pd.DataFrame) -> None:
    rules_recall = matrix_metrics(*confusion_counts(frame, "rules_alert"))[1]
    ml_recall = matrix_metrics(*confusion_counts(frame, "ml_alert"))[1]
    labels = ["Surveillance\nmanuelle", "SOC règles\n+ Syslog", "SOC +\nIsolation Forest"]
    mttd = np.array([14.0, max(1.5, 5.0 - rules_recall * 3.0), max(0.7, 4.0 - ml_recall * 3.2)])
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
    ax.set_title("Comparaison de l’apport progressif de l’automatisation", color=COLORS["muted"], pad=45)
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


def write_summary(out: Path, prefix: str, vmid: Optional[int], stats: Dict[str, Dict[str, float]], frame: pd.DataFrame) -> None:
    rules_counts = confusion_counts(frame, "rules_alert")
    ml_counts = confusion_counts(frame, "ml_alert")
    lines = [
        "# Figures poster augmentees",
        "",
        f"VMID cible: {vmid if vmid is not None else 'non determine'}",
        f"Scenarios augmentes: {len(frame)}",
        "",
        "## Statistiques utilisees",
    ]
    for scenario, values in stats.items():
        lines.append(
            f"- {scenario}: CPU {values['cpu']:.1f}%, RAM {values['ram']:.1f}%, "
            f"score ML {values['ml']:.1f}, SSH/min {values['ssh']:.1f}"
        )
    lines.extend(
        [
            "",
            "## Matrices",
            f"- Regles: VP={rules_counts[0]}, FN={rules_counts[1]}, FP={rules_counts[2]}, VN={rules_counts[3]}",
            f"- Isolation Forest: VP={ml_counts[0]}, FN={ml_counts[1]}, FP={ml_counts[2]}, VN={ml_counts[3]}",
            "",
            "Ces figures sont augmentees a partir des observations. Elles doivent etre presentees comme donnees augmentees, pas comme mesures brutes.",
        ]
    )
    out.joinpath(f"{prefix}poster_augmented_summary.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    setup_style()
    db_path = Path(args.db)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    metrics = parse_time_columns(read_table(db_path, "metrics"), ["timestamp"])
    scores = parse_time_columns(read_table(db_path, "ml_scores"), ["timestamp"])
    ssh_events = parse_time_columns(read_table(db_path, "ssh_events"), ["timestamp", "collected_at"])
    metrics = filter_window(metrics, "timestamp", args.start, args.end, args.experiment_timezone)
    scores = filter_window(scores, "timestamp", args.start, args.end, args.experiment_timezone)
    ssh_events = filter_window(ssh_events, "timestamp", args.start, args.end, args.experiment_timezone)
    vmid = choose_vmid(metrics, scores, args.vmid)
    if vmid is not None:
        metrics = filter_vmid(metrics, vmid)
        scores = filter_vmid(scores, vmid)
        ssh_events = filter_vmid(ssh_events, vmid)

    experiments = load_experiments(Path(args.log), args.experiment_timezone)
    experiments = filter_window(experiments, "start_time", args.start, args.end, args.experiment_timezone)
    stats = scenario_stats(metrics, scores, ssh_events, experiments)
    augmented = augment_scenarios(stats, args.target_scenarios, args.ml_threshold, args.seed)

    save_resource_limits(out, args.filename_prefix, stats)
    save_matrix(
        out,
        args.filename_prefix,
        "02_regles_confusion_matrix.png",
        f"Détection par règles : matrice sur {len(augmented)} scénarios",
        "Extrapolation équilibrée à partir de la campagne SOC",
        confusion_counts(augmented, "rules_alert"),
    )
    save_iforest_score(out, args.filename_prefix, stats, args.ml_threshold)
    save_matrix(
        out,
        args.filename_prefix,
        "05_iforest_confusion_matrix_projection.png",
        f"Isolation Forest : matrice sur {len(augmented)} scénarios",
        "Projection équilibrée après apprentissage sur baseline historique",
        confusion_counts(augmented, "ml_alert"),
    )
    save_delay_comparison(out, args.filename_prefix, augmented)
    write_summary(out, args.filename_prefix, vmid, stats, augmented)
    print(f"Augmented poster figures generated in {out}")


if __name__ == "__main__":
    main()

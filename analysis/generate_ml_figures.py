import argparse
import sqlite3
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Isolation Forest analysis figures.")
    parser.add_argument("--db", default="data/soc_dashboard.sqlite3", help="Path to SQLite database.")
    parser.add_argument("--out", default="analysis_output", help="Output directory.")
    parser.add_argument("--filename-prefix", default="", help="Optional prefix for generated files.")
    return parser.parse_args()


def read_table(db_path: Path, table_name: str) -> pd.DataFrame:
    if not db_path.exists():
        return pd.DataFrame()
    with sqlite3.connect(db_path) as connection:
        try:
            return pd.read_sql_query(f"SELECT * FROM {table_name}", connection)
        except Exception:
            return pd.DataFrame()


def output_file(out: Path, prefix: str, filename: str) -> Path:
    return out / f"{prefix}{filename}"


def plot_ml_score_timeline(scores: pd.DataFrame, out: Path, prefix: str) -> None:
    if scores.empty:
        return
    frame = scores.copy()
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    frame = frame.dropna(subset=["timestamp"]).sort_values("timestamp")
    if frame.empty:
        return

    fig, ax = plt.subplots(figsize=(14, 6))
    for vmid, group in frame.groupby("vmid"):
        ax.plot(group["timestamp"], group["anomaly_score"], marker="o", linewidth=1.8, label=f"VM {vmid}")
    ax.axhline(70, color="#d97706", linestyle="--", label="Seuil warning 70")
    ax.axhline(85, color="#b91c1c", linestyle="--", label="Seuil critique 85")
    ax.set_title("Evolution du score Isolation Forest par VM")
    ax.set_xlabel("Temps")
    ax.set_ylabel("Score d'anomalie")
    ax.set_ylim(0, 105)
    ax.grid(alpha=0.25)
    ax.legend(loc="upper left")
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(output_file(out, prefix, "08_ml_score_timeline.png"), dpi=160)
    plt.close(fig)


def plot_ml_evaluation(runs: pd.DataFrame, out: Path, prefix: str) -> None:
    if runs.empty:
        return
    latest = runs.sort_values(["timestamp", "id"]).iloc[-1]
    metrics = {
        "Exactitude": float(latest.get("accuracy") or 0.0) * 100,
        "Rappel": float(latest.get("recall") or 0.0) * 100,
        "Precision": float(latest.get("precision") or 0.0) * 100,
    }
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(metrics.keys(), metrics.values(), color=["#2563eb", "#059669", "#f97316"])
    ax.set_ylim(0, 100)
    ax.set_ylabel("%")
    ax.set_title("Evaluation du modele Isolation Forest")
    for index, value in enumerate(metrics.values()):
        ax.text(index, value + 2, f"{value:.0f}%", ha="center", fontweight="bold")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(output_file(out, prefix, "09_ml_model_evaluation.png"), dpi=160)
    plt.close(fig)


def plot_ml_anomalies_by_vm(scores: pd.DataFrame, out: Path, prefix: str) -> None:
    if scores.empty:
        return
    anomalies = scores[scores["is_anomaly"].astype(int) == 1]
    if anomalies.empty:
        return
    counts = anomalies.groupby("vmid").size().sort_values(ascending=False)
    fig, ax = plt.subplots(figsize=(9, 5))
    counts.plot(kind="bar", ax=ax, color="#7c3aed")
    ax.set_title("Anomalies ML detectees par VM")
    ax.set_xlabel("VMID")
    ax.set_ylabel("Nombre de scores anormaux")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(output_file(out, prefix, "10_ml_anomalies_by_vm.png"), dpi=160)
    plt.close(fig)


def main() -> None:
    args = parse_args()
    db_path = Path(args.db)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    scores = read_table(db_path, "ml_scores")
    runs = read_table(db_path, "ml_model_runs")
    plot_ml_score_timeline(scores, out, args.filename_prefix)
    plot_ml_evaluation(runs, out, args.filename_prefix)
    plot_ml_anomalies_by_vm(scores, out, args.filename_prefix)


if __name__ == "__main__":
    main()

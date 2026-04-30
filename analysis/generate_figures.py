import argparse
import sqlite3
from pathlib import Path
from typing import Dict, Optional, Tuple

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd


SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "medium": "#d97706",
    "low": "#2563eb",
    "unknown": "#6b7280",
}

SCENARIO_COLORS = {
    "baseline": "#d1fae5",
    "cpu_legitimate": "#fef3c7",
    "nmap": "#dbeafe",
    "hydra": "#fee2e2",
    "mixed": "#ede9fe",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate SOC dashboard analysis figures.")
    parser.add_argument("--db", default="data/soc_dashboard.sqlite3", help="Path to SQLite database.")
    parser.add_argument("--log", default="experiment_log.csv", help="Path to experiment log CSV.")
    parser.add_argument("--out", default="analysis_output", help="Output directory for figures and summary.")
    parser.add_argument("--vmid", type=int, default=None, help="Target VMID. Defaults to experiment log VMID or most sampled VM.")
    return parser.parse_args()


def ensure_output_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_table(db_path: Path, table_name: str) -> pd.DataFrame:
    if not db_path.exists():
        return pd.DataFrame()
    with sqlite3.connect(db_path) as connection:
        try:
            return pd.read_sql_query(f"SELECT * FROM {table_name}", connection)
        except Exception:
            return pd.DataFrame()


def load_data(db_path: Path, log_path: Path) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    metrics = read_table(db_path, "metrics")
    alerts = read_table(db_path, "alerts")
    actions = read_table(db_path, "actions")

    if log_path.exists():
        experiments = pd.read_csv(log_path)
    else:
        experiments = pd.DataFrame(
            columns=[
                "start_time",
                "end_time",
                "scenario",
                "label",
                "vmid",
                "target_ip",
                "is_malicious",
                "expected_alert",
                "observed_alert",
                "notes",
            ]
        )

    for frame, columns in [
        (metrics, ["timestamp"]),
        (alerts, ["first_seen", "last_seen", "active_since", "resolved_at"]),
        (actions, ["timestamp"]),
        (experiments, ["start_time", "end_time"]),
    ]:
        for column in columns:
            if column in frame.columns:
                frame[column] = pd.to_datetime(frame[column], errors="coerce")

    for column in ["is_malicious", "expected_alert", "observed_alert"]:
        if column in experiments.columns:
            experiments[column] = experiments[column].map(parse_bool)

    if "vmid" in experiments.columns:
        experiments["vmid"] = pd.to_numeric(experiments["vmid"], errors="coerce")
    if "vmid" in metrics.columns:
        metrics["vmid"] = pd.to_numeric(metrics["vmid"], errors="coerce")
    if "vmid" in alerts.columns:
        alerts["vmid"] = pd.to_numeric(alerts["vmid"], errors="coerce")
    if "vmid" in actions.columns:
        actions["vmid"] = pd.to_numeric(actions["vmid"], errors="coerce")

    return metrics, alerts, actions, experiments


def parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if pd.isna(value):
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "oui"}


def choose_vmid(metrics: pd.DataFrame, experiments: pd.DataFrame, requested_vmid: Optional[int]) -> Optional[int]:
    if requested_vmid is not None:
        return requested_vmid
    if not experiments.empty and "vmid" in experiments.columns:
        vmids = experiments["vmid"].dropna()
        if not vmids.empty:
            return int(vmids.iloc[0])
    if not metrics.empty and "vmid" in metrics.columns:
        vm_metrics = metrics[metrics["scope"] == "vm"]
        if not vm_metrics.empty:
            counts = vm_metrics["vmid"].value_counts()
            return int(counts.index[0])
    return None


def save_placeholder(output_path: Path, title: str, message: str) -> None:
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.axis("off")
    ax.text(0.5, 0.62, title, ha="center", va="center", fontsize=18, fontweight="bold")
    ax.text(0.5, 0.42, message, ha="center", va="center", fontsize=12, wrap=True)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def add_experiment_spans(ax, experiments: pd.DataFrame) -> None:
    if experiments.empty:
        return
    used_labels = set()
    for _, row in experiments.iterrows():
        start = row.get("start_time")
        end = row.get("end_time")
        if pd.isna(start) or pd.isna(end):
            continue
        scenario = str(row.get("scenario", "scenario"))
        color = SCENARIO_COLORS.get(scenario, "#e5e7eb")
        label = scenario if scenario not in used_labels else None
        ax.axvspan(start, end, color=color, alpha=0.35, label=label)
        used_labels.add(scenario)


def filter_alerts_for_vmid(alerts: pd.DataFrame, vmid: Optional[int]) -> pd.DataFrame:
    if alerts.empty or vmid is None or "vmid" not in alerts.columns:
        return alerts.copy()
    return alerts[(alerts["vmid"] == vmid) | alerts["vmid"].isna()].copy()


def figure_cpu_timeline(metrics: pd.DataFrame, alerts: pd.DataFrame, experiments: pd.DataFrame, vmid: Optional[int], out: Path) -> None:
    output_path = out / "01_cpu_timeline.png"
    if metrics.empty or vmid is None:
        save_placeholder(output_path, "Timeline CPU", "Aucune metrique VM disponible.")
        return

    vm_metrics = metrics[(metrics["scope"] == "vm") & (metrics["vmid"] == vmid)].copy()
    if vm_metrics.empty:
        save_placeholder(output_path, "Timeline CPU", f"Aucune metrique CPU pour la VMID {vmid}.")
        return

    vm_metrics = vm_metrics.sort_values("timestamp")
    target_alerts = filter_alerts_for_vmid(alerts, vmid)

    fig, ax = plt.subplots(figsize=(14, 6))
    add_experiment_spans(ax, experiments)
    ax.plot(vm_metrics["timestamp"], vm_metrics["cpu_percent"], color="#111827", linewidth=1.5, label=f"VM {vmid} CPU")
    ax.axhline(80, color="#d97706", linestyle="--", linewidth=1, label="Seuil warning 80%")
    ax.axhline(95, color="#b91c1c", linestyle="--", linewidth=1, label="Seuil critique 95%")

    if not target_alerts.empty:
        for _, alert in target_alerts.iterrows():
            first_seen = alert.get("first_seen")
            if pd.notna(first_seen):
                ax.axvline(first_seen, color=SEVERITY_COLORS.get(str(alert.get("severity")), "#6b7280"), alpha=0.55, linewidth=1)

    ax.set_title("Evolution CPU de la VM cible avec fenetres experimentales")
    ax.set_ylabel("CPU (%)")
    ax.set_xlabel("Temps")
    ax.set_ylim(bottom=0)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M"))
    ax.legend(loc="upper left", ncols=2)
    ax.grid(alpha=0.25)
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def figure_alerts_timeline(alerts: pd.DataFrame, out: Path) -> None:
    output_path = out / "02_alerts_timeline.png"
    if alerts.empty:
        save_placeholder(output_path, "Timeline des alertes", "Aucune alerte presente dans SQLite.")
        return

    data = alerts.sort_values("first_seen").copy()
    colors = [SEVERITY_COLORS.get(str(severity), "#6b7280") for severity in data["severity"]]

    fig, ax = plt.subplots(figsize=(14, 5))
    ax.scatter(data["first_seen"], data["score"], c=colors, s=90, edgecolor="#111827", linewidth=0.6)
    for _, row in data.iterrows():
        label = f"{row.get('event_type', '')} ({row.get('severity', '')})"
        ax.annotate(label, (row["first_seen"], row["score"]), textcoords="offset points", xytext=(4, 6), fontsize=8)
    ax.set_title("Timeline des alertes detectees")
    ax.set_ylabel("Score d'anomalie")
    ax.set_xlabel("Temps")
    ax.set_ylim(0, 105)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M"))
    ax.grid(alpha=0.25)
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def count_alerts_for_experiment(alerts: pd.DataFrame, experiment: pd.Series) -> int:
    if alerts.empty:
        return 0
    start = experiment.get("start_time")
    end = experiment.get("end_time")
    if pd.isna(start) or pd.isna(end):
        return 0
    subset = alerts.copy()
    if pd.notna(experiment.get("vmid")) and "vmid" in subset.columns:
        vmid = int(experiment["vmid"])
        subset = subset[(subset["vmid"] == vmid) | subset["vmid"].isna()]
    overlap = (subset["first_seen"] <= end) & (subset["last_seen"].fillna(subset["first_seen"]) >= start)
    return int(overlap.sum())


def enrich_experiments(experiments: pd.DataFrame, alerts: pd.DataFrame) -> pd.DataFrame:
    if experiments.empty:
        return experiments.copy()
    enriched = experiments.copy()
    enriched["alert_count"] = enriched.apply(lambda row: count_alerts_for_experiment(alerts, row), axis=1)
    if "observed_alert" not in enriched.columns:
        enriched["observed_alert"] = enriched["alert_count"] > 0
    else:
        missing_observed = enriched["observed_alert"].isna()
        enriched.loc[missing_observed, "observed_alert"] = enriched.loc[missing_observed, "alert_count"] > 0
    return enriched


def figure_alerts_by_scenario(experiments: pd.DataFrame, alerts: pd.DataFrame, out: Path) -> None:
    output_path = out / "03_alerts_by_scenario.png"
    enriched = enrich_experiments(experiments, alerts)
    if enriched.empty:
        if alerts.empty:
            save_placeholder(output_path, "Alertes par scenario", "Aucun journal d'experiences et aucune alerte.")
            return
        counts = alerts["event_type"].value_counts().sort_index()
        title = "Alertes par type detecte"
        x_label = "Type d'alerte"
    else:
        counts = enriched.groupby("scenario")["alert_count"].sum().sort_index()
        title = "Nombre d'alertes par scenario experimental"
        x_label = "Scenario"

    fig, ax = plt.subplots(figsize=(10, 5))
    counts.plot(kind="bar", ax=ax, color="#2563eb")
    ax.set_title(title)
    ax.set_xlabel(x_label)
    ax.set_ylabel("Nombre d'alertes")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def confusion_counts(experiments: pd.DataFrame, alerts: pd.DataFrame) -> Dict[str, int]:
    enriched = enrich_experiments(experiments, alerts)
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    if enriched.empty:
        return counts
    for _, row in enriched.iterrows():
        malicious = parse_bool(row.get("is_malicious"))
        observed = parse_bool(row.get("observed_alert"))
        if malicious and observed:
            counts["TP"] += 1
        elif malicious and not observed:
            counts["FN"] += 1
        elif not malicious and observed:
            counts["FP"] += 1
        else:
            counts["TN"] += 1
    return counts


def figure_confusion_matrix(experiments: pd.DataFrame, alerts: pd.DataFrame, out: Path) -> None:
    output_path = out / "04_confusion_matrix.png"
    if experiments.empty:
        save_placeholder(output_path, "Matrice de classification", "Renseigner experiment_log.csv pour classer TP/FP/TN/FN.")
        return

    counts = confusion_counts(experiments, alerts)
    matrix = [[counts["TP"], counts["FN"]], [counts["FP"], counts["TN"]]]
    labels = [["Vrai positif", "Faux negatif"], ["Faux positif", "Vrai negatif"]]

    fig, ax = plt.subplots(figsize=(7, 6))
    image = ax.imshow(matrix, cmap="Blues")
    ax.set_xticks([0, 1], labels=["Alerte observee", "Pas d'alerte"])
    ax.set_yticks([0, 1], labels=["Malveillant", "Non malveillant"])
    for row_index in range(2):
        for col_index in range(2):
            ax.text(col_index, row_index, f"{labels[row_index][col_index]}\n{matrix[row_index][col_index]}", ha="center", va="center", fontsize=12)
    ax.set_title("Matrice experimentale detection / verite terrain")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def compute_mttd_mttr(alerts: pd.DataFrame, actions: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return pd.DataFrame(columns=["id", "mttd_seconds", "mttr_seconds"])

    rows = []
    for _, alert in alerts.iterrows():
        first_seen = alert.get("first_seen")
        active_since = alert.get("active_since")
        mttd = None
        if pd.notna(first_seen) and pd.notna(active_since):
            mttd = max((first_seen - active_since).total_seconds(), 0)

        mttr = None
        if not actions.empty and pd.notna(alert.get("vmid")) and pd.notna(first_seen):
            related = actions[
                (actions["node"] == alert.get("node"))
                & (actions["vmid"] == alert.get("vmid"))
                & (actions["result"] == "success")
                & (actions["timestamp"] >= first_seen)
            ].sort_values("timestamp")
            if not related.empty:
                mttr = max((related.iloc[0]["timestamp"] - first_seen).total_seconds(), 0)

        rows.append({"id": alert.get("id"), "mttd_seconds": mttd, "mttr_seconds": mttr})
    return pd.DataFrame(rows)


def figure_mttd_mttr(alerts: pd.DataFrame, actions: pd.DataFrame, out: Path) -> None:
    output_path = out / "05_mttd_mttr.png"
    data = compute_mttd_mttr(alerts, actions)
    if data.empty or data[["mttd_seconds", "mttr_seconds"]].dropna(how="all").empty:
        save_placeholder(output_path, "MTTD / MTTR", "Aucun delai calculable sans alertes ou actions associees.")
        return

    plot_data = data.set_index("id")[["mttd_seconds", "mttr_seconds"]]
    fig, ax = plt.subplots(figsize=(10, 5))
    plot_data.plot(kind="bar", ax=ax, color=["#2563eb", "#16a34a"])
    ax.set_title("Delais de detection et de reponse")
    ax.set_xlabel("ID alerte")
    ax.set_ylabel("Secondes")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def figure_cpu_distribution(metrics: pd.DataFrame, experiments: pd.DataFrame, vmid: Optional[int], out: Path) -> None:
    output_path = out / "06_cpu_normal_vs_attack.png"
    if metrics.empty or experiments.empty or vmid is None:
        save_placeholder(output_path, "Distribution CPU par scenario", "Metriques et experiment_log.csv requis.")
        return

    vm_metrics = metrics[(metrics["scope"] == "vm") & (metrics["vmid"] == vmid)].copy()
    if vm_metrics.empty:
        save_placeholder(output_path, "Distribution CPU par scenario", f"Aucune metrique CPU pour la VMID {vmid}.")
        return

    series_by_scenario = []
    labels = []
    for scenario, group in experiments.groupby("scenario"):
        values = []
        for _, experiment in group.iterrows():
            start = experiment.get("start_time")
            end = experiment.get("end_time")
            if pd.isna(start) or pd.isna(end):
                continue
            subset = vm_metrics[(vm_metrics["timestamp"] >= start) & (vm_metrics["timestamp"] <= end)]
            values.extend(subset["cpu_percent"].dropna().tolist())
        if values:
            series_by_scenario.append(values)
            labels.append(str(scenario))

    if not series_by_scenario:
        save_placeholder(output_path, "Distribution CPU par scenario", "Aucune metrique ne chevauche les fenetres experimentales.")
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.boxplot(series_by_scenario, labels=labels, showmeans=True)
    ax.set_title("Distribution CPU par scenario")
    ax.set_ylabel("CPU (%)")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def write_summary(
    out: Path,
    metrics: pd.DataFrame,
    alerts: pd.DataFrame,
    actions: pd.DataFrame,
    experiments: pd.DataFrame,
    vmid: Optional[int],
) -> None:
    enriched = enrich_experiments(experiments, alerts)
    counts = confusion_counts(experiments, alerts)
    delays = compute_mttd_mttr(alerts, actions)

    metrics_count = len(metrics)
    alert_count = len(alerts)
    action_count = len(actions)
    experiment_count = len(experiments)
    first_metric = metrics["timestamp"].min() if not metrics.empty and "timestamp" in metrics.columns else None
    last_metric = metrics["timestamp"].max() if not metrics.empty and "timestamp" in metrics.columns else None
    avg_mttd = delays["mttd_seconds"].dropna().mean() if not delays.empty else None
    avg_mttr = delays["mttr_seconds"].dropna().mean() if not delays.empty else None

    lines = [
        "# Resultats experimentaux SOC Dashboard",
        "",
        "## Synthese quantitative",
        "",
        f"- VMID cible analysee : {vmid if vmid is not None else 'non determinee'}",
        f"- Nombre de points de metriques : {metrics_count}",
        f"- Nombre d'alertes : {alert_count}",
        f"- Nombre d'actions de reponse active : {action_count}",
        f"- Nombre de scenarios documentes : {experiment_count}",
        f"- Premiere metrique : {first_metric if first_metric is not None else 'n/a'}",
        f"- Derniere metrique : {last_metric if last_metric is not None else 'n/a'}",
        f"- MTTD moyen : {avg_mttd:.2f} s" if pd.notna(avg_mttd) else "- MTTD moyen : n/a",
        f"- MTTR moyen : {avg_mttr:.2f} s" if pd.notna(avg_mttr) else "- MTTR moyen : n/a",
        "",
        "## Classification experimentale",
        "",
        f"- Vrais positifs : {counts['TP']}",
        f"- Faux positifs : {counts['FP']}",
        f"- Vrais negatifs : {counts['TN']}",
        f"- Faux negatifs : {counts['FN']}",
        "",
        "## Alertes par severite",
        "",
    ]

    if alerts.empty:
        lines.append("- Aucune alerte enregistree.")
    else:
        for severity, count in alerts["severity"].value_counts().sort_index().items():
            lines.append(f"- {severity} : {count}")

    lines.extend(["", "## Scenarios documentes", ""])
    if enriched.empty:
        lines.append("- Aucun scenario renseigne dans experiment_log.csv.")
    else:
        for _, row in enriched.iterrows():
            lines.append(
                f"- {row.get('scenario')} / {row.get('label')} : "
                f"alertes={row.get('alert_count', 0)}, "
                f"malveillant={row.get('is_malicious')}, "
                f"alerte_observee={row.get('observed_alert')}"
            )

    lines.extend(
        [
            "",
            "## Interpretation prete pour le memoire",
            "",
            "- La baseline permet d'evaluer le bruit normal et les vrais negatifs.",
            "- Les charges CPU legitimes evaluent les faux positifs d'une detection par seuils.",
            "- Les scans Nmap et brute-force SSH sans alerte illustrent les faux negatifs possibles d'une approche metriques-only.",
            "- Les actions d'isolement/restauration documentent la valeur de la reponse active human-in-the-loop.",
            "- La prochaine evolution logique est la correlation avec les logs SSH/syslog.",
            "",
        ]
    )

    (out / "summary_results.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    db_path = Path(args.db)
    log_path = Path(args.log)
    output_dir = Path(args.out)
    ensure_output_dir(output_dir)

    metrics, alerts, actions, experiments = load_data(db_path, log_path)
    vmid = choose_vmid(metrics, experiments, args.vmid)

    figure_cpu_timeline(metrics, alerts, experiments, vmid, output_dir)
    figure_alerts_timeline(alerts, output_dir)
    figure_alerts_by_scenario(experiments, alerts, output_dir)
    figure_confusion_matrix(experiments, alerts, output_dir)
    figure_mttd_mttr(alerts, actions, output_dir)
    figure_cpu_distribution(metrics, experiments, vmid, output_dir)
    write_summary(output_dir, metrics, alerts, actions, experiments, vmid)

    print(f"Figures generated in {output_dir.resolve()}")
    print(f"Summary generated at {(output_dir / 'summary_results.md').resolve()}")


if __name__ == "__main__":
    main()

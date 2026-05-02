import os
import random
import statistics
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

from config import AppConfig
from storage import fetch_vm_metric_profile, iso_timestamp


MODEL_NAME = "isolation_forest"
MODEL_VERSION = "iforest-v1"
FEATURE_COLUMNS = [
    "cpu_percent",
    "ram_percent",
    "cpu_delta_percent",
    "ssh_failed_count",
    "ssh_source_count",
    "ssh_success_after_failure_count",
]


@dataclass(frozen=True)
class MlPrediction:
    timestamp: str
    node: str
    vmid: int
    model_name: str
    model_version: str
    anomaly_score: float
    raw_score: float
    is_anomaly: bool
    severity: str
    features: Dict[str, float]
    message: str


def optional_ml_imports():
    try:
        import joblib
        from sklearn.ensemble import IsolationForest
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
    except Exception as exc:
        raise RuntimeError(
            "Dependances ML indisponibles. Lance docker compose up -d --build "
            "apres l'ajout de scikit-learn et joblib."
        ) from exc
    return joblib, IsolationForest, Pipeline, StandardScaler


def vm_ram_percent(vm_status: Dict[str, object]) -> float:
    maxmem = int(vm_status.get("maxmem", 0))
    if maxmem <= 0:
        return 0.0
    return (int(vm_status.get("mem", 0)) / maxmem) * 100


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def percentile(values: Sequence[float], ratio: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    index = int(round((len(sorted_values) - 1) * ratio))
    return sorted_values[max(0, min(index, len(sorted_values) - 1))]


def profile_from_metrics(rows: List[Dict[str, object]]) -> Dict[str, float]:
    cpu_values = [float(row["cpu_percent"]) for row in rows if row.get("cpu_percent") is not None]
    ram_values = [float(row["ram_percent"]) for row in rows if row.get("ram_percent") is not None]
    if not cpu_values:
        cpu_values = [8.0, 10.0, 12.0, 15.0]
    if not ram_values:
        ram_values = [25.0, 28.0, 32.0, 35.0]

    return {
        "cpu_mean": statistics.mean(cpu_values),
        "cpu_std": max(statistics.pstdev(cpu_values), 2.0),
        "cpu_p80": percentile(cpu_values, 0.80),
        "ram_mean": statistics.mean(ram_values),
        "ram_std": max(statistics.pstdev(ram_values), 2.0),
        "ram_p80": percentile(ram_values, 0.80),
    }


def make_feature_row(
    cpu_percent: float,
    ram_percent: float,
    cpu_delta_percent: float,
    ssh_failed_count: float,
    ssh_source_count: float,
    ssh_success_after_failure_count: float,
) -> Dict[str, float]:
    return {
        "cpu_percent": round(clamp(cpu_percent, 0.0, 120.0), 3),
        "ram_percent": round(clamp(ram_percent, 0.0, 100.0), 3),
        "cpu_delta_percent": round(clamp(abs(cpu_delta_percent), 0.0, 120.0), 3),
        "ssh_failed_count": round(max(0.0, ssh_failed_count), 3),
        "ssh_source_count": round(max(0.0, ssh_source_count), 3),
        "ssh_success_after_failure_count": round(max(0.0, ssh_success_after_failure_count), 3),
    }


def generate_training_samples(settings: AppConfig) -> Tuple[List[Dict[str, float]], Dict[str, float]]:
    rows = fetch_vm_metric_profile(settings.db_path)
    profile = profile_from_metrics(rows)
    rng = random.Random(42)
    samples: List[Dict[str, float]] = []

    for row in rows[: min(len(rows), 300)]:
        samples.append(
            make_feature_row(
                float(row.get("cpu_percent") or profile["cpu_mean"]),
                float(row.get("ram_percent") or profile["ram_mean"]),
                rng.uniform(0.0, 6.0),
                rng.choice([0, 0, 0, 1]),
                rng.choice([0, 0, 1]),
                0,
            )
        )

    for _ in range(settings.ml_train_synthetic_samples):
        mode = rng.random()
        if mode < 0.82:
            cpu = rng.gauss(profile["cpu_mean"], profile["cpu_std"])
            ram = rng.gauss(profile["ram_mean"], profile["ram_std"])
            delta = abs(rng.gauss(2.5, 2.0))
            ssh_failed = rng.choice([0, 0, 0, 1, 2])
            sources = 1 if ssh_failed else 0
        elif mode < 0.94:
            # Maintenance legitime: CPU haut mais peu ou pas de signal SSH.
            cpu = rng.uniform(max(profile["cpu_p80"], 45.0), 92.0)
            ram = rng.gauss(profile["ram_mean"] + 4.0, profile["ram_std"])
            delta = rng.uniform(8.0, 22.0)
            ssh_failed = rng.choice([0, 0, 1])
            sources = 1 if ssh_failed else 0
        else:
            # Bruit de connexion raisonnable, non assimile a une attaque.
            cpu = rng.gauss(profile["cpu_mean"] + 4.0, profile["cpu_std"])
            ram = rng.gauss(profile["ram_mean"], profile["ram_std"])
            delta = rng.uniform(2.0, 10.0)
            ssh_failed = rng.randint(2, max(2, settings.ssh_auth_failure_warn - 1))
            sources = rng.choice([1, 1, 2])
        samples.append(make_feature_row(cpu, ram, delta, ssh_failed, sources, 0))

    return samples, profile


def feature_matrix(samples: Sequence[Dict[str, float]]) -> List[List[float]]:
    return [[float(sample[column]) for column in FEATURE_COLUMNS] for sample in samples]


def normalize_score(raw_score: float, low: float, threshold: float, high: float) -> float:
    if threshold <= low:
        threshold = low + 0.001
    if high <= threshold:
        high = threshold + 0.001
    if raw_score <= threshold:
        return clamp(((raw_score - low) / (threshold - low)) * 70.0, 0.0, 70.0)
    return clamp(70.0 + ((raw_score - threshold) / (high - threshold)) * 30.0, 70.0, 100.0)


def synthetic_eval_samples(settings: AppConfig, profile: Dict[str, float]) -> List[Dict[str, object]]:
    rng = random.Random(84)
    rows: List[Dict[str, object]] = []
    total = settings.ml_evaluation_synthetic_samples
    malicious_target = total // 2
    benign_target = total - malicious_target

    for _ in range(malicious_target):
        mode = rng.choice(["hydra", "hydra_cpu", "distributed", "success_after_failures"])
        if mode == "hydra":
            features = make_feature_row(
                rng.gauss(profile["cpu_mean"] + 3.0, profile["cpu_std"]),
                rng.gauss(profile["ram_mean"], profile["ram_std"]),
                rng.uniform(1.0, 8.0),
                rng.randint(settings.ssh_auth_failure_warn, settings.ssh_auth_failure_critical + 8),
                1,
                0,
            )
        elif mode == "hydra_cpu":
            features = make_feature_row(
                rng.uniform(82.0, 100.0),
                rng.gauss(profile["ram_mean"] + 6.0, profile["ram_std"]),
                rng.uniform(12.0, 36.0),
                rng.randint(settings.ssh_auth_failure_warn, settings.ssh_auth_failure_critical + 15),
                rng.choice([1, 2]),
                0,
            )
        elif mode == "distributed":
            features = make_feature_row(
                rng.gauss(profile["cpu_mean"] + 5.0, profile["cpu_std"]),
                rng.gauss(profile["ram_mean"], profile["ram_std"]),
                rng.uniform(2.0, 14.0),
                rng.randint(settings.ssh_auth_failure_warn, settings.ssh_auth_failure_critical + 12),
                rng.randint(settings.ssh_distributed_source_warn, settings.ssh_distributed_source_warn + 5),
                0,
            )
        else:
            features = make_feature_row(
                rng.gauss(profile["cpu_mean"] + 4.0, profile["cpu_std"]),
                rng.gauss(profile["ram_mean"], profile["ram_std"]),
                rng.uniform(2.0, 10.0),
                rng.randint(settings.ssh_success_after_failure_warn, settings.ssh_auth_failure_warn + 5),
                1,
                1,
            )
        rows.append({"malicious": True, "features": features})

    for _ in range(benign_target):
        mode = rng.choice(["baseline", "maintenance", "admin_typo"])
        if mode == "baseline":
            features = make_feature_row(
                rng.gauss(profile["cpu_mean"], profile["cpu_std"]),
                rng.gauss(profile["ram_mean"], profile["ram_std"]),
                rng.uniform(0.0, 6.0),
                rng.choice([0, 0, 0, 1]),
                rng.choice([0, 0, 1]),
                0,
            )
        elif mode == "maintenance":
            features = make_feature_row(
                rng.uniform(max(profile["cpu_p80"], 50.0), 94.0),
                rng.gauss(profile["ram_mean"] + 5.0, profile["ram_std"]),
                rng.uniform(8.0, 25.0),
                rng.choice([0, 0, 1]),
                rng.choice([0, 1]),
                0,
            )
        else:
            features = make_feature_row(
                rng.gauss(profile["cpu_mean"] + 2.0, profile["cpu_std"]),
                rng.gauss(profile["ram_mean"], profile["ram_std"]),
                rng.uniform(1.0, 8.0),
                rng.randint(1, max(1, settings.ssh_auth_failure_warn - 1)),
                1,
                0,
            )
        rows.append({"malicious": False, "features": features})

    return rows


def evaluate_bundle(settings: AppConfig, bundle: Dict[str, object], profile: Dict[str, float]) -> Dict[str, float]:
    evaluation_rows = synthetic_eval_samples(settings, profile)
    tp = fp = tn = fn = 0
    for row in evaluation_rows:
        score = predict_features(settings, bundle, row["features"])
        predicted = bool(score.is_anomaly)
        malicious = bool(row["malicious"])
        if malicious and predicted:
            tp += 1
        elif malicious and not predicted:
            fn += 1
        elif not malicious and predicted:
            fp += 1
        else:
            tn += 1
    total = max(tp + fp + tn + fn, 1)
    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "accuracy": (tp + tn) / total,
        "recall": tp / max(tp + fn, 1),
        "precision": tp / max(tp + fp, 1),
        "evaluation_rows": total,
    }


def train_model(settings: AppConfig) -> Dict[str, object]:
    _, IsolationForest, Pipeline, StandardScaler = optional_ml_imports()
    samples, profile = generate_training_samples(settings)
    matrix = feature_matrix(samples)
    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=180,
                    contamination=settings.ml_contamination,
                    random_state=42,
                ),
            ),
        ]
    )
    pipeline.fit(matrix)
    raw_scores = [-float(value) for value in pipeline.decision_function(matrix)]
    low = percentile(raw_scores, 0.05)
    threshold = percentile(raw_scores, 1.0 - settings.ml_contamination)
    high = percentile(raw_scores, 0.995)
    if high <= threshold:
        high = max(raw_scores) + 0.001

    bundle = {
        "model": pipeline,
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "feature_columns": FEATURE_COLUMNS,
        "trained_at": iso_timestamp(datetime.now()),
        "training_rows": len(samples),
        "score_low": low,
        "score_threshold": threshold,
        "score_high": high,
        "profile": profile,
    }
    bundle["evaluation"] = evaluate_bundle(settings, bundle, profile)
    return bundle


def save_model(settings: AppConfig, bundle: Dict[str, object]) -> None:
    joblib, _, _, _ = optional_ml_imports()
    model_dir = os.path.dirname(settings.ml_model_path)
    if model_dir:
        os.makedirs(model_dir, exist_ok=True)
    joblib.dump(bundle, settings.ml_model_path)


def load_model(settings: AppConfig) -> Optional[Dict[str, object]]:
    if not settings.ml_enabled or not os.path.exists(settings.ml_model_path):
        return None
    joblib, _, _, _ = optional_ml_imports()
    return joblib.load(settings.ml_model_path)


def train_and_save_model(settings: AppConfig) -> Dict[str, object]:
    bundle = train_model(settings)
    save_model(settings, bundle)
    return bundle


def ensure_model(settings: AppConfig) -> Optional[Dict[str, object]]:
    if not settings.ml_enabled:
        return None
    bundle = load_model(settings)
    if bundle is not None:
        return bundle
    if not settings.ml_auto_train:
        return None
    return train_and_save_model(settings)


def build_live_features(
    vm_status: Dict[str, object],
    previous_metric: Optional[Dict[str, object]],
    ssh_failed_count: int,
    ssh_source_count: int,
    ssh_success_after_failure_count: int,
) -> Dict[str, float]:
    cpu_percent = float(vm_status.get("cpu", 0.0)) * 100
    previous_cpu = float(previous_metric.get("cpu_percent", cpu_percent)) if previous_metric else cpu_percent
    return make_feature_row(
        cpu_percent=cpu_percent,
        ram_percent=vm_ram_percent(vm_status),
        cpu_delta_percent=cpu_percent - previous_cpu,
        ssh_failed_count=float(ssh_failed_count),
        ssh_source_count=float(ssh_source_count),
        ssh_success_after_failure_count=float(ssh_success_after_failure_count),
    )


def predict_features(settings: AppConfig, bundle: Dict[str, object], features: Dict[str, float]) -> MlPrediction:
    matrix = feature_matrix([features])
    model = bundle["model"]
    raw_score = -float(model.decision_function(matrix)[0])
    anomaly_score = normalize_score(
        raw_score,
        float(bundle.get("score_low", -0.1)),
        float(bundle.get("score_threshold", 0.0)),
        float(bundle.get("score_high", 0.1)),
    )
    is_anomaly = anomaly_score >= settings.ml_score_warn
    if anomaly_score >= settings.ml_score_critical:
        severity = "critical"
    elif is_anomaly:
        severity = "medium"
    else:
        severity = "low"

    message = (
        f"Score Isolation Forest {anomaly_score:.1f}/100 "
        f"(cpu={features['cpu_percent']:.1f}%, ram={features['ram_percent']:.1f}%, "
        f"ssh={features['ssh_failed_count']:.0f})."
    )
    return MlPrediction(
        timestamp=iso_timestamp(datetime.now()),
        node="",
        vmid=0,
        model_name=str(bundle.get("model_name", MODEL_NAME)),
        model_version=str(bundle.get("model_version", MODEL_VERSION)),
        anomaly_score=round(anomaly_score, 2),
        raw_score=round(raw_score, 6),
        is_anomaly=is_anomaly,
        severity=severity,
        features=features,
        message=message,
    )


def score_live_vm(
    settings: AppConfig,
    bundle: Dict[str, object],
    node: str,
    vmid: int,
    vm_status: Dict[str, object],
    previous_metric: Optional[Dict[str, object]],
    ssh_failed_count: int,
    ssh_source_count: int,
    ssh_success_after_failure_count: int,
    timestamp: datetime,
) -> MlPrediction:
    features = build_live_features(
        vm_status,
        previous_metric,
        ssh_failed_count,
        ssh_source_count,
        ssh_success_after_failure_count,
    )
    prediction = predict_features(settings, bundle, features)
    return MlPrediction(
        timestamp=iso_timestamp(timestamp),
        node=node,
        vmid=vmid,
        model_name=prediction.model_name,
        model_version=prediction.model_version,
        anomaly_score=prediction.anomaly_score,
        raw_score=prediction.raw_score,
        is_anomaly=prediction.is_anomaly,
        severity=prediction.severity,
        features=prediction.features,
        message=prediction.message,
    )


def prediction_to_row(prediction: MlPrediction) -> Dict[str, object]:
    return {
        "timestamp": prediction.timestamp,
        "node": prediction.node,
        "vmid": prediction.vmid,
        "model_name": prediction.model_name,
        "model_version": prediction.model_version,
        "anomaly_score": prediction.anomaly_score,
        "raw_score": prediction.raw_score,
        "is_anomaly": prediction.is_anomaly,
        "severity": prediction.severity,
        "features": prediction.features,
        "message": prediction.message,
    }

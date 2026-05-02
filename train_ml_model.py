from config import read_settings
from ml_model import MODEL_NAME, MODEL_VERSION, train_and_save_model
from storage import init_db, record_ml_model_run


def main() -> None:
    settings = read_settings()
    init_db(settings.db_path)
    try:
        bundle = train_and_save_model(settings)
        evaluation = bundle.get("evaluation", {})
        message = (
            "Modele Isolation Forest entraine sur donnees augmentees. "
            f"Fichier: {settings.ml_model_path}"
        )
        record_ml_model_run(
            settings.db_path,
            model_name=str(bundle.get("model_name", MODEL_NAME)),
            model_version=str(bundle.get("model_version", MODEL_VERSION)),
            status="success",
            training_rows=int(bundle.get("training_rows", 0)),
            evaluation_rows=int(evaluation.get("evaluation_rows", 0)),
            accuracy=float(evaluation.get("accuracy", 0.0)),
            recall=float(evaluation.get("recall", 0.0)),
            precision=float(evaluation.get("precision", 0.0)),
            message=message,
        )
        print(message)
        print(
            "Evaluation synthetique | "
            f"accuracy={float(evaluation.get('accuracy', 0.0)):.2f} "
            f"recall={float(evaluation.get('recall', 0.0)):.2f} "
            f"precision={float(evaluation.get('precision', 0.0)):.2f}"
        )
    except Exception as exc:
        record_ml_model_run(
            settings.db_path,
            model_name=MODEL_NAME,
            model_version=MODEL_VERSION,
            status="error",
            message=str(exc),
        )
        raise


if __name__ == "__main__":
    main()

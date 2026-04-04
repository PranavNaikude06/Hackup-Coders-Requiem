import os
import mlflow
import mlflow.sklearn
from sklearn.model_selection import train_test_split

from src.data_loader import load_config, load_data, preprocess
from src.trainer import get_scaler, train_xgboost, train_mlp, evaluate_model, save_artifacts


def run_pipeline(config_path: str = "config.yaml"):
    config = load_config(config_path)
    print("=" * 60)
    print("   Phishing Website Detection — Training Pipeline")
    print("=" * 60)

    df = load_data(config)
    X, y = preprocess(df, config["data"]["target_column"])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config["data"]["test_size"],
        random_state=config["data"]["random_state"], stratify=y,
    )
    print(f"[INFO] Train: {X_train.shape[0]} | Test: {X_test.shape[0]}")

    scaler = get_scaler(config)
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    mlflow.set_experiment("phishing-detection")

    with mlflow.start_run(run_name="XGBoost"):
        xgb = train_xgboost(X_train_s, y_train, config)
        metrics = evaluate_model(xgb, X_test_s, y_test, "XGBoost")
        mlflow.log_params(config["xgboost"])
        mlflow.log_metrics(metrics)
        mlflow.sklearn.log_model(xgb, "xgb_model")

    with mlflow.start_run(run_name="ANN_MLP"):
        ann = train_mlp(X_train_s, y_train, config)
        metrics2 = evaluate_model(ann, X_test_s, y_test, "ANN (MLP)")
        mlflow.log_params({k: str(v) for k, v in config["mlp"].items()})
        mlflow.log_metrics(metrics2)
        mlflow.sklearn.log_model(ann, "ann_model")

    save_artifacts(scaler, xgb, ann, config)
    print("\n" + "=" * 60)
    print("   Pipeline completed successfully!")
    print("=" * 60)

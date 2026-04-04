import os
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report
)
from xgboost import XGBClassifier


def get_scaler(config: dict) -> StandardScaler:
    return StandardScaler()


def train_xgboost(X_train, y_train, config: dict) -> XGBClassifier:
    c = config["xgboost"]
    model = XGBClassifier(
        n_estimators=c["n_estimators"], max_depth=c["max_depth"],
        learning_rate=c["learning_rate"], subsample=c["subsample"],
        colsample_bytree=c["colsample_bytree"], gamma=c["gamma"],
        min_child_weight=c["min_child_weight"], reg_alpha=c["reg_alpha"],
        reg_lambda=c["reg_lambda"], scale_pos_weight=c["scale_pos_weight"],
        n_jobs=c["n_jobs"], eval_metric=c["eval_metric"],
        random_state=config["data"]["random_state"],
    )
    model.fit(X_train, y_train)
    
    print("[INFO] XGBoost trained.")
    return model


def train_mlp(X_train, y_train, config: dict) -> MLPClassifier:
    c = config["mlp"]
    model = MLPClassifier(
        hidden_layer_sizes=tuple(c["hidden_layers"]),
        activation=c["activation"], solver=c["solver"],
        learning_rate_init=c["learning_rate_init"], alpha=c["alpha"],
        batch_size=c["batch_size"], max_iter=c["max_iter"],
        early_stopping=c["early_stopping"],
        validation_fraction=c["validation_fraction"],
        random_state=config["data"]["random_state"],
    )
    model.fit(X_train, y_train)
    print("[INFO] ANN (MLP) trained.")
    return model


def evaluate_model(model, X_test, y_test, name: str) -> dict:
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None
    metrics = {
        "accuracy":  accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall":    recall_score(y_test, y_pred, zero_division=0),
        "f1":        f1_score(y_test, y_pred, zero_division=0),
    }
    if y_prob is not None:
        metrics["roc_auc"] = roc_auc_score(y_test, y_prob)
    print(f"\n[RESULTS] {name}")
    print(classification_report(y_test, y_pred, target_names=["Legitimate","Phishing"]))
    return metrics


def save_artifacts(scaler, xgb, ann, config: dict):
    d = config["artifacts"]["directory"]
    os.makedirs(d, exist_ok=True)
    joblib.dump(scaler, os.path.join(d, config["artifacts"]["scaler_filename"]))
    joblib.dump(xgb,    os.path.join(d, config["artifacts"]["xgb_model_filename"]))
    joblib.dump(ann,    os.path.join(d, config["artifacts"]["ann_model_filename"]))
    print(f"[INFO] Artifacts saved to '{d}/'")

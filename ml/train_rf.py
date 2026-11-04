"""
ml/train_rf.py
--------------
Train a Random Forest classifier on the NSL-KDD dataset for binary
network anomaly detection (normal vs. attack).

Usage:
    python ml/train_rf.py
"""

import json
import os
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder, StandardScaler

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN_PATH = os.path.join(PROJECT_ROOT, "data", "raw", "KDDTrain+.txt")
TEST_PATH = os.path.join(PROJECT_ROOT, "data", "raw", "KDDTest+.txt")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
PIPELINE_PATH = os.path.join(MODEL_DIR, "rf_pipeline.pkl")
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, "feature_names.json")
METRICS_PATH = os.path.join(MODEL_DIR, "rf_metrics.json")

os.makedirs(MODEL_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Column schema
# ---------------------------------------------------------------------------
COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

FEATURE_COLUMNS = [c for c in COLUMNS if c not in ("label", "difficulty")]

NUMERICAL_FEATURES = [f for f in FEATURE_COLUMNS if f not in CATEGORICAL_FEATURES]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_dataset(path):
    """Load NSL-KDD text file and return (X, y) with binary labels."""
    print("  Loading: " + path)
    df = pd.read_csv(path, header=None, names=COLUMNS)
    df = df.drop(columns=["difficulty"])

    # Strip trailing dots and binarise: normal=0, attack=1
    df["label"] = df["label"].str.rstrip(".")
    y = (df["label"] != "normal").astype(int)
    X = df[FEATURE_COLUMNS].copy()
    return X, y


def build_pipeline():
    """Build the sklearn Pipeline with ColumnTransformer preprocessing."""
    cat_transformer = OrdinalEncoder(
        handle_unknown="use_encoded_value",
        unknown_value=-1,
    )
    num_transformer = StandardScaler()

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", cat_transformer, CATEGORICAL_FEATURES),
            ("num", num_transformer, NUMERICAL_FEATURES),
        ],
        remainder="drop",
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=100,
                    random_state=42,
                    n_jobs=-1,
                    class_weight="balanced",
                ),
            ),
        ]
    )
    return pipeline


# ---------------------------------------------------------------------------
# Main training routine
# ---------------------------------------------------------------------------

def main():
    sep = "=" * 60
    print(sep)
    print("NSL-KDD Random Forest Training Pipeline")
    print(sep)

    # ------------------------------------------------------------------
    # 1. Load data
    # ------------------------------------------------------------------
    print("\n[1/5] Loading datasets ...")
    X_train, y_train = load_dataset(TRAIN_PATH)
    X_test, y_test = load_dataset(TEST_PATH)
    print("  Train size : {:,} samples".format(len(X_train)))
    print("  Test  size : {:,} samples".format(len(X_test)))
    print("  Train label distribution: normal={:,}, attack={:,}".format(
        int((y_train == 0).sum()), int((y_train == 1).sum())))
    print("  Test  label distribution: normal={:,}, attack={:,}".format(
        int((y_test == 0).sum()), int((y_test == 1).sum())))

    # ------------------------------------------------------------------
    # 2. Build pipeline
    # ------------------------------------------------------------------
    print("\n[2/5] Building sklearn pipeline ...")
    pipeline = build_pipeline()
    print("  Pipeline: OrdinalEncoder + StandardScaler -> RandomForest(100 trees)")

    # ------------------------------------------------------------------
    # 3. Train
    # ------------------------------------------------------------------
    print("\n[3/5] Training RandomForestClassifier ...")
    t0 = time.time()
    pipeline.fit(X_train, y_train)
    elapsed = time.time() - t0
    print("  Training complete in {:.1f}s".format(elapsed))

    # ------------------------------------------------------------------
    # 4. Evaluate
    # ------------------------------------------------------------------
    print("\n[4/5] Evaluating on test set ...")
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0  # False Positive Rate

    print("")
    print("  EVALUATION METRICS")
    print("  " + "-" * 42)
    print("  Accuracy           : {:.4f}".format(acc))
    print("  Precision          : {:.4f}".format(prec))
    print("  Recall             : {:.4f}".format(rec))
    print("  F1-Score           : {:.4f}".format(f1))
    print("  False Positive Rate: {:.4f}".format(fpr))
    print("  " + "-" * 42)
    print("  Confusion Matrix:")
    print("    TN={:6d}  FP={:6d}".format(int(tn), int(fp)))
    print("    FN={:6d}  TP={:6d}".format(int(fn), int(tp)))
    print("  " + "-" * 42)

    metrics = {
        "accuracy": round(acc, 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "f1_score": round(f1, 6),
        "false_positive_rate": round(fpr, 6),
        "confusion_matrix": {
            "TN": int(tn),
            "FP": int(fp),
            "FN": int(fn),
            "TP": int(tp),
        },
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "training_time_seconds": round(elapsed, 2),
        "model": "RandomForestClassifier",
        "n_estimators": 100,
        "random_state": 42,
    }

    # ------------------------------------------------------------------
    # 5. Save artifacts
    # ------------------------------------------------------------------
    print("\n[5/5] Saving artifacts ...")

    joblib.dump(pipeline, PIPELINE_PATH)
    print("  Pipeline saved  -> " + PIPELINE_PATH)

    with open(FEATURE_NAMES_PATH, "w") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)
    print("  Feature names   -> " + FEATURE_NAMES_PATH)

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    print("  Metrics saved   -> " + METRICS_PATH)

    print("")
    print(sep)
    print("Training pipeline complete.")
    print(sep)

    return metrics


if __name__ == "__main__":
    main()

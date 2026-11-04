"""
ml/predict.py
-------------
Inference module for the NSL-KDD network anomaly detection project.

Exposes:
    predict_single(feature_dict)  -> dict
    predict_batch(list_of_dicts)  -> list[dict]
    get_model_info()              -> dict
    predict_if(feature_dict)      -> dict   (Isolation Forest anomaly score)

NOTE on Isolation Forest scores:
    The Isolation Forest is an *unsupervised* anomaly detector trained on raw
    traffic features.  Its output is an anomaly score in [-1, 1] range
    (sklearn decision_function), NOT an attack probability.  A score < 0
    typically indicates an anomaly.  Do NOT compare this score directly to the
    Random Forest attack probability.
"""

from __future__ import annotations

import json
import os
from typing import Any

import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_MODULE_DIR)
_MODEL_DIR = os.path.join(_PROJECT_ROOT, "models")
_TRAINED_DIR = os.path.join(_MODEL_DIR, "trained")

_PIPELINE_PATH = os.path.join(_MODEL_DIR, "rf_pipeline.pkl")
_FEATURE_NAMES_PATH = os.path.join(_MODEL_DIR, "feature_names.json")
_IF_PATH = os.path.join(_TRAINED_DIR, "isolation_forest.joblib")

# ---------------------------------------------------------------------------
# Categorical / numeric split (must match train_rf.py)
# ---------------------------------------------------------------------------
_CATEGORICAL_FEATURES = {"protocol_type", "service", "flag"}

_DEFAULT_NUMERIC = 0
_DEFAULT_CATEGORICAL = "unknown"

# ---------------------------------------------------------------------------
# Singleton loaders
# ---------------------------------------------------------------------------
_rf_pipeline = None
_feature_names: list[str] = []
_if_model = None
_if_loaded: bool = False  # tracks whether we attempted IF load


def _load_rf() -> None:
    """Load RF pipeline and feature names exactly once."""
    global _rf_pipeline, _feature_names

    if _rf_pipeline is not None:
        return

    if not os.path.exists(_PIPELINE_PATH):
        raise FileNotFoundError(
            f"RF pipeline not found at {_PIPELINE_PATH}. "
            "Run ml/train_rf.py first."
        )
    _rf_pipeline = joblib.load(_PIPELINE_PATH)

    if os.path.exists(_FEATURE_NAMES_PATH):
        with open(_FEATURE_NAMES_PATH) as f:
            _feature_names = json.load(f)
    else:
        raise FileNotFoundError(
            f"feature_names.json not found at {_FEATURE_NAMES_PATH}."
        )


_ENCODER_PATH = os.path.join(_PROJECT_ROOT, "data", "processed", "label_encoders.joblib")
_SCALER_PATH = os.path.join(_PROJECT_ROOT, "data", "processed", "scaler.joblib")
_label_encoders = None
_scaler = None


def _load_if() -> None:
    """Load Isolation Forest model and its preprocessors (silently skipped if absent)."""
    global _if_model, _if_loaded, _label_encoders, _scaler

    if _if_loaded:
        return
    _if_loaded = True

    if os.path.exists(_IF_PATH):
        try:
            _if_model = joblib.load(_IF_PATH)
        except Exception as exc:  # pragma: no cover
            print(f"[predict.py] Warning: could not load Isolation Forest: {exc}")
            _if_model = None

    if os.path.exists(_ENCODER_PATH):
        try:
            _label_encoders = joblib.load(_ENCODER_PATH)
        except Exception:
            _label_encoders = None

    if os.path.exists(_SCALER_PATH):
        try:
            _scaler = joblib.load(_SCALER_PATH)
        except Exception:
            _scaler = None


# Eagerly load on import so import errors surface immediately.
_load_rf()
_load_if()


def reload_models() -> dict[str, Any]:
    """Force reload of RF and IF models and return their load statuses."""
    global _rf_pipeline, _feature_names, _if_model, _if_loaded, _label_encoders, _scaler
    _rf_pipeline = None
    _feature_names = []
    _if_model = None
    _if_loaded = False
    _label_encoders = None
    _scaler = None
    _load_rf()
    _load_if()
    return get_model_info()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_dataframe(feature_dict: dict[str, Any]) -> pd.DataFrame:
    """
    Convert a raw feature dict into a single-row DataFrame matching the
    exact feature order expected by the RF pipeline.

    Missing numeric features are filled with 0.
    Missing categorical features are filled with 'unknown' (handled by
    OrdinalEncoder's unknown_value=-1).
    """
    row: dict[str, Any] = {}
    for feat in _feature_names:
        if feat in feature_dict:
            row[feat] = feature_dict[feat]
        elif feat in _CATEGORICAL_FEATURES:
            row[feat] = _DEFAULT_CATEGORICAL
        else:
            row[feat] = _DEFAULT_NUMERIC

    return pd.DataFrame([row], columns=_feature_names)


def _make_result(pred: int, proba_attack: float) -> dict:
    return {
        "prediction": int(pred),
        "label": "Attack" if pred == 1 else "Normal",
        "probability": round(float(proba_attack), 6),
        "confidence": round(float(proba_attack), 6),
        "model_version": "rf_v1.0",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def predict_single(feature_dict: dict[str, Any]) -> dict:
    """
    Predict whether a single network connection is normal or an attack.

    Parameters
    ----------
    feature_dict : dict
        Mapping of feature names to values.  Missing features are filled with
        safe defaults (0 for numeric, 'unknown' for categorical).

    Returns
    -------
    dict with keys:
        prediction   (int)   0 = Normal, 1 = Attack
        label        (str)   'Normal' or 'Attack'
        probability  (float) RF probability of the Attack class [0, 1]
        confidence   (float) same as probability
        model_version (str)
    """
    df = _build_dataframe(feature_dict)
    pred = int(_rf_pipeline.predict(df)[0])
    proba_attack = float(_rf_pipeline.predict_proba(df)[0][1])
    return _make_result(pred, proba_attack)


def predict_batch(list_of_dicts: list[dict[str, Any]]) -> list[dict]:
    """
    Predict for a batch of connections.

    Parameters
    ----------
    list_of_dicts : list[dict]
        Each dict is a feature mapping as in predict_single.

    Returns
    -------
    list[dict] — one result dict per input row, same schema as predict_single.
    """
    if not list_of_dicts:
        return []

    rows = [_build_dataframe(d) for d in list_of_dicts]
    df_batch = pd.concat(rows, ignore_index=True)

    preds = _rf_pipeline.predict(df_batch)
    probas = _rf_pipeline.predict_proba(df_batch)[:, 1]

    return [_make_result(int(p), float(pr)) for p, pr in zip(preds, probas)]


def get_model_info() -> dict:
    """
    Return metadata about the loaded models.

    Returns
    -------
    dict with model details.
    """
    rf_params = _rf_pipeline.named_steps["classifier"].get_params()
    info: dict[str, Any] = {
        "model_type": "RandomForestClassifier",
        "model_version": "rf_v1.0",
        "n_estimators": rf_params.get("n_estimators"),
        "random_state": rf_params.get("random_state"),
        "class_weight": rf_params.get("class_weight"),
        "n_features": len(_feature_names),
        "feature_names": _feature_names,
        "categorical_features": list(_CATEGORICAL_FEATURES),
        "pipeline_path": _PIPELINE_PATH,
        "isolation_forest_loaded": _if_model is not None,
    }

    # Append IF metadata if available
    if _if_model is not None:
        if_params = _if_model.get_params() if hasattr(_if_model, "get_params") else {}
        info["isolation_forest"] = {
            "path": _IF_PATH,
            "n_estimators": if_params.get("n_estimators"),
            "contamination": if_params.get("contamination"),
            "note": (
                "Isolation Forest outputs anomaly scores (NOT attack probabilities). "
                "Score < 0 indicates anomaly."
            ),
        }

    return info


def predict_if(feature_dict: dict[str, Any]) -> dict:
    """
    Run Isolation Forest anomaly detection on a single connection.

    .. important::
        The Isolation Forest is an **unsupervised** model.  Its
        ``anomaly_score`` is the raw ``decision_function`` value (higher =
        more normal, lower / negative = more anomalous).  This is NOT an
        attack probability and should NOT be compared directly to the
        Random Forest ``probability`` field.

    Parameters
    ----------
    feature_dict : dict
        Feature mapping. Preprocessed using saved LabelEncoders and
        StandardScaler to match training distribution.

    Returns
    -------
    dict with keys:
        anomaly_score (float)   Raw decision_function score.  < 0 → anomaly.
        is_anomaly    (bool)    True if score < 0.
        note          (str)     Reminder that this is NOT attack probability.
    """
    if _if_model is None:
        raise RuntimeError(
            f"Isolation Forest model not found at {_IF_PATH}. "
            "Ensure isolation_forest.joblib is present in models/trained/."
        )

    df = _build_dataframe(feature_dict).copy()

    # Preprocess categorical features using fitted encoders if available
    if _label_encoders is not None:
        for col in ["protocol_type", "service", "flag"]:
            if col in df.columns and col in _label_encoders:
                le = _label_encoders[col]
                df[col] = df[col].map(
                    lambda s: int(le.transform([s])[0]) if s in le.classes_ else 0
                )

    # Scale numeric features if fitted scaler is available
    if _scaler is not None:
        try:
            x_input = pd.DataFrame(_scaler.transform(df), columns=_feature_names)
        except Exception:
            x_input = df
    else:
        x_input = df

    score = float(_if_model.decision_function(x_input)[0])
    is_anomaly = bool(score < 0)

    return {
        "anomaly_score": round(score, 6),
        "is_anomaly": is_anomaly,
        "note": (
            "Isolation Forest anomaly score. "
            "Score < 0 indicates anomaly. "
            "This is NOT an attack probability."
        ),
    }

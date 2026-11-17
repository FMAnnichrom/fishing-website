"""
Offline training pipeline for the Scikit-learn Phishing URL Detection Model.
Separates training, validation, and test datasets by domain group to prevent data leakage.
"""

import json
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from feature_extraction.extractor import FEATURE_NAMES, extract_structural_vector


def evaluate_predictions(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
        "sample_count": int(len(y_true)),
    }


def main():
    base_dir = Path(__file__).resolve().parent.parent
    dataset_path = base_dir / "datasets" / "urls_dataset.csv"
    models_dir = base_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(dataset_path).dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    df["domain_group"] = df["url"].apply(
        lambda u: (urlparse(u).hostname or u).lower().split(".")[-2:]
        and ".".join((urlparse(u).hostname or u).lower().split(".")[-2:])
    )

    # 70% train / 15% val / 15% test grouped by domain to prevent leakage
    gss_outer = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=42)
    train_idx, temp_idx = next(gss_outer.split(df, df["label"], groups=df["domain_group"]))

    temp_df = df.iloc[temp_idx].reset_index(drop=True)
    gss_inner = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=42)
    val_rel_idx, test_rel_idx = next(
        gss_inner.split(temp_df, temp_df["label"], groups=temp_df["domain_group"])
    )

    train_df = df.iloc[train_idx].reset_index(drop=True)
    val_df = temp_df.iloc[val_rel_idx].reset_index(drop=True)
    test_df = temp_df.iloc[test_rel_idx].reset_index(drop=True)

    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 4), min_df=3, max_features=500)
    scaler = StandardScaler()

    def build_features(frame: pd.DataFrame, fit: bool = False):
        surfaces = frame["url"].str.replace(r"^https?://", "", regex=True)
        tfidf = vectorizer.fit_transform(surfaces) if fit else vectorizer.transform(surfaces)
        struct = np.array([extract_structural_vector(u) for u in frame["url"]])
        struct_scaled = scaler.fit_transform(struct) if fit else scaler.transform(struct)
        return np.hstack([struct_scaled, tfidf.toarray()])

    X_train = build_features(train_df, fit=True)
    X_val = build_features(val_df, fit=False)
    X_test = build_features(test_df, fit=False)

    clf = RandomForestClassifier(n_estimators=200, max_depth=16, random_state=42, n_jobs=-1)
    clf.fit(X_train, train_df["label"].values)

    val_metrics = evaluate_predictions(val_df["label"].values, clf.predict(X_val))
    test_metrics = evaluate_predictions(test_df["label"].values, clf.predict(X_test))

    bundle = {
        "model": clf,
        "vectorizer": vectorizer,
        "scaler": scaler,
        "feature_names": FEATURE_NAMES,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
    }

    joblib.dump(bundle, models_dir / "sklearn_phishing_model.joblib")
    with open(models_dir / "sklearn_evaluation.json", "w", encoding="utf-8") as f:
        json.dump({"validation": val_metrics, "test": test_metrics}, f, indent=2)

    print("Saved Scikit-learn model to", models_dir / "sklearn_phishing_model.joblib")
    print("Test Metrics:", json.dumps(test_metrics, indent=2))


if __name__ == "__main__":
    main()

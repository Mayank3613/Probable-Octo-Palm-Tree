
import os
import json
import joblib
import pandas as pd
import numpy as np

from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (
    train_test_split,
    cross_val_score
)

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)

from features import extract_features


# ==========================================================
# Synthetic Dataset Generator
# ==========================================================

def generate_synthetic_data(num_samples=5000):
    """
    Generates synthetic training data.

    Replace with:
    - PhishTank
    - OpenPhish
    - URLHaus
    - Real telemetry

    when available.
    """

    print(f"Generating {num_samples} samples...")

    data = []

    # ======================================================
    # Safe URLs
    # ======================================================

    safe_domains = [
        "google.com",
        "github.com",
        "microsoft.com",
        "apple.com",
        "wikipedia.org",
        "amazon.com",
        "netflix.com",
        "stackoverflow.com",
        "openai.com",
        "linkedin.com",
        "discord.com",
        "reddit.com"
    ]

    safe_paths = [
        "/",
        "/about",
        "/pricing",
        "/products",
        "/blog",
        "/contact",
        "/docs",
        "/login",
        "/user/profile",
        "/settings",
        "/search?q=test"
    ]

    for _ in range(num_samples // 2):

        domain = np.random.choice(safe_domains)
        path = np.random.choice(safe_paths)

        url = f"https://{domain}{path}"

        row = extract_features(url)
        row["label"] = 0

        data.append(row)

    # ======================================================
    # Malicious URLs
    # ======================================================

    malicious_domains = [
        "paypal-update-account.top",
        "secure-login-verification.xyz",
        "banking-security-check.icu",
        "wallet-confirmation.top",
        "verify-account-login.xyz",
        "185.243.112.55",
        "192.168.100.200",
        "xn--pple-43d.com",
        "microsoft-security-update.top",
        "amazon-auth-reset.icu"
    ]

    malicious_paths = [
        "/login",
        "/verify/account",
        "/secure/update",
        "/account/reset",
        "/wallet/recovery",
        "/billing/update",
        "/payload.exe",
        "/bin.sh",
        "/auth/confirm",
        "/login/verify/account"
    ]

    for _ in range(num_samples // 2):

        domain = np.random.choice(malicious_domains)
        path = np.random.choice(malicious_paths)

        url = (
            f"http://{domain}"
            f"{path}"
            f"?id={np.random.randint(1000,99999)}"
        )

        row = extract_features(url)
        row["label"] = 1

        data.append(row)

    # ======================================================
    # Extra Training Noise
    # ======================================================

    extra_samples = [

        (
            "https://github.com/Mayank3613/"
            "Probable-Octo-Palm-Tree/"
            "blob/main/backend-api/"
            "app/services/url_analyzer.py",
            0
        ),

        (
            "http://example.xyz/"
            "secure/login/verify/"
            "account/update/reset",
            1
        ),

        (
            "https://google.com/search?q=openai",
            0
        ),

        (
            "http://paypal-login-update.top/"
            "verify/account",
            1
        ),

        (
            "http://185.243.112.55/"
            "secure/update/login",
            1
        )
    ]

    for url, label in extra_samples:

        row = extract_features(url)
        row["label"] = label

        data.append(row)

    df = pd.DataFrame(data)

    print(f"Dataset Shape: {df.shape}")

    return df


# ==========================================================
# Model Training
# ==========================================================

def train_model():

    print("=" * 60)
    print(" OCTOPALMTREE AI ENGINE TRAINING ")
    print("=" * 60)

    df = generate_synthetic_data(5000)

    y = df["label"]
    X = df.drop("label", axis=1)

    feature_names = list(X.columns)

    print(f"\nTotal Features: {len(feature_names)}")

    # ======================================================
    # Train/Test Split
    # ======================================================

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )
    print(f"Training Samples: {len(X_train)}")
    print(f"Testing Samples : {len(X_test)}")

    # ======================================================
    # Random Forest
    # ======================================================

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        min_samples_leaf=2,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining model...")
    clf.fit(X_train, y_train)

    # ======================================================
    # Predictions
    # ======================================================

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    # ======================================================
    # Metrics
    # ======================================================

    accuracy = accuracy_score(y_test, y_pred)

    precision = precision_score(
        y_test,
        y_pred
    )

    recall = recall_score(
        y_test,
        y_pred
    )

    f1 = f1_score(
        y_test,
        y_pred
    )

    roc_auc = roc_auc_score(
        y_test,
        y_proba
    )

    # ======================================================
    # Cross Validation
    # ======================================================

    cv_scores = cross_val_score(
        clf,
        X,
        y,
        cv=5,
        scoring="accuracy"
    )

    # ======================================================
    # Reporting
    # ======================================================

    print("\n" + "=" * 60)
    print(" MODEL PERFORMANCE ")
    print("=" * 60)
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print(f"ROC-AUC  : {roc_auc:.4f}")
    print(
        f"Cross Validation Accuracy: "
        f"{cv_scores.mean():.4f} "
        f"(±{cv_scores.std():.4f})"
    )
    print("\nClassification Report:\n")
    print(
        classification_report(
            y_test,
            y_pred
        )
    )
    print("\nConfusion Matrix:\n")
    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    # ======================================================
    # Feature Importance
    # ======================================================

    print("\nTop 20 Features:\n")
    importance_df = pd.DataFrame({
        "feature": feature_names,
        "importance": clf.feature_importances_
    })
    importance_df = (
        importance_df
        .sort_values(
            "importance",
            ascending=False
        )
    )
    print(
        importance_df.head(20)
    )

    # ======================================================
    # Save Artifacts
    # ======================================================

    base_dir = os.path.dirname(
        os.path.abspath(__file__)
    )
    model_path = os.path.join(
        base_dir,
        "model.joblib"
    )
    feature_path = os.path.join(
        base_dir,
        "feature_names.joblib"
    )
    importance_path = os.path.join(
        base_dir,
        "feature_importance.csv"
    )
    metadata_path = os.path.join(
        base_dir,
        "model_metadata.json"
    )
    joblib.dump(clf, model_path)
    joblib.dump(
        feature_names,
        feature_path
    )
    importance_df.to_csv(
        importance_path,
        index=False
    )
    metadata = {
        "model_name":
            "OctoPalmTree URL Threat Detector",
        "algorithm":
            "RandomForestClassifier",
        "version":
            "2.0.0",
        "trained_at":
            datetime.utcnow().isoformat(),
        "feature_count":
            len(feature_names),
        "dataset_size":
            len(df),
        "accuracy":
            round(float(accuracy), 4),
        "precision":
            round(float(precision), 4),
        "recall":
            round(float(recall), 4),
        "f1_score":
            round(float(f1), 4),
        "roc_auc":
            round(float(roc_auc), 4),
        "cv_accuracy":
            round(float(cv_scores.mean()), 4)
    }
    with open(
        metadata_path,
        "w"
    ) as f:
        json.dump(
            metadata,
            f,
            indent=4
        )
    print("\n" + "=" * 60)
    print(" MODEL SAVED SUCCESSFULLY ")
    print("=" * 60)
    print(f"Model File      : {model_path}")
    print(f"Feature File    : {feature_path}")
    print(f"Importance File : {importance_path}")
    print(f"Metadata File   : {metadata_path}")


# ==========================================================
# Entry Point
# ==========================================================

if __name__ == "__main__":
    train_model()

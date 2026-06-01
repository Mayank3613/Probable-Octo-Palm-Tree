import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from features import extract_features

def generate_synthetic_data(num_samples=2000):
    print(f"Generating {num_samples} synthetic URL samples...")
    data = []
    
    # Generate Safe URLs (Label 0)
    safe_domains = ["google.com", "github.com", "microsoft.com", "apple.com", "wikipedia.org", "netflix.com", "amazon.com", "discord.com"]
    safe_paths = ["/", "/about", "/contact", "/home", "/user/profile", "/login", "/search?q=test"]
    for _ in range(num_samples // 2):
        domain = np.random.choice(safe_domains)
        path = np.random.choice(safe_paths)
        url = f"https://{domain}{path}"
        features = extract_features(url)
        features["label"] = 0
        data.append(features)
        
    # Generate Malicious URLs (Label 1)
    malicious_domains = ["login-verify-secure.xyz", "paypal-update-account.top", "netflix-billing.icu", "185.243.112.55", "xn--pple-43d.com"]
    malicious_paths = ["/login/verify/account", "/secure/update", "/bin.sh", "/payload.exe", "/"]
    for _ in range(num_samples // 2):
        domain = np.random.choice(malicious_domains)
        path = np.random.choice(malicious_paths)
        # Add random noise to make them unique
        url = f"http://{domain}{path}?id={np.random.randint(1000, 9999)}"
        features = extract_features(url)
        features["label"] = 1
        data.append(features)
        
    # Extra noise for robust training
    for _ in range(100):
        # Long safe URL
        url = "https://github.com/Mayank3613/Probable-Octo-Palm-Tree/blob/main/backend-api/app/services/url_analyzer.py"
        features = extract_features(url)
        features["label"] = 0
        data.append(features)
        
        # Deep path phishing
        url = "http://example.xyz/secure/login/verify/account/update/confirm/reset"
        features = extract_features(url)
        features["label"] = 1
        data.append(features)
        
    df = pd.DataFrame(data)
    return df

def train_model():
    df = generate_synthetic_data(2000)
    
    # Prepare X and y
    y = df["label"]
    X = df.drop("label", axis=1)
    
    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X, y)
    
    accuracy = clf.score(X, y)
    print(f"Training Accuracy: {accuracy:.4f}")
    
    # Save the model
    model_path = os.path.join(os.path.dirname(__file__), "model.joblib")
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")
    
    # Save feature names to ensure we extract them in the same order later
    joblib.dump(list(X.columns), os.path.join(os.path.dirname(__file__), "feature_names.joblib"))

if __name__ == "__main__":
    train_model()

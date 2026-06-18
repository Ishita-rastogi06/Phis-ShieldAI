import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
from feature_extractor import extract_features

# ── Load dataset ──────────────────────────────────────────────
df = pd.read_csv("phishing_dataset.csv")

print("Columns found:", df.columns.tolist())
print("Shape:", df.shape)

# Auto-detect URL and label columns
url_col = None
label_col = None

for col in df.columns:
    if col.lower() in ["url", "urls", "link", "domain"]:
        url_col = col
        break

for col in df.columns:
    if col.lower() in ["type", "label", "class", "status", "result"]:
        label_col = col
        break

if url_col is None or label_col is None:
    raise ValueError(f"Could not find URL/label columns. Columns: {df.columns.tolist()}")

print(f"\nUsing URL column   : '{url_col}'")
print(f"Using label column : '{label_col}'")

# ── Map labels to binary ──────────────────────────────────────
print(f"\nUnique label values:\n{df[label_col].value_counts()}")

label_map = {
    # phishing / malicious
    "phishing": 1, "phish": 1, "malware": 1, "defacement": 1,
    "malicious": 1, "spam": 1, "fraud": 1, "scam": 1,
    "1": 1, 1: 1, "bad": 1,
    # benign / legitimate
    "benign": 0, "legitimate": 0, "safe": 0, "good": 0,
    "0": 0, 0: 0, "ham": 0,
}

df["label"] = df[label_col].map(label_map)
df = df.dropna(subset=["label", url_col])
df["label"] = df["label"].astype(int)

print(f"\nRows after label mapping: {len(df)}")
print(f"Label distribution:\n{df['label'].value_counts()}")

# ── Drop bad URLs before feature extraction ───────────────────
df[url_col] = df[url_col].astype(str).str.strip()

# Remove rows likely to crash urlparse
bad_mask = (
    df[url_col].str.contains(r'\[.*:.*\]', regex=True) |  # raw IPv6
    df[url_col].str.len() < 4 |
    df[url_col].isna()
)
dropped = bad_mask.sum()
df = df[~bad_mask].copy()
print(f"\nDropped {dropped} malformed/IPv6 URLs. Remaining: {len(df)}")

# ── Extract features ─────────────────────────────────────────
print(f"\nTraining on {len(df)} samples with 20 features each...")

def safe_extract(url):
    try:
        return extract_features(url)
    except Exception:
        return [0] * 20

X_raw = df[url_col].apply(safe_extract)

# Drop rows where extraction returned all zeros (bad URLs slipped through)
X = np.array(X_raw.tolist())
y = df["label"].values

valid_mask = X.sum(axis=1) > 0
X = X[valid_mask]
y = y[valid_mask]
print(f"Valid samples after feature extraction: {len(X)}")

# ── Train / test split ────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Train model ───────────────────────────────────────────────
print("\nTraining Random Forest...")
model = RandomForestClassifier(
    n_estimators=100,
    n_jobs=-1,
    random_state=42
)
model.fit(X_train, y_train)

# ── Evaluate ──────────────────────────────────────────────────
y_pred = model.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

# ── Save model ────────────────────────────────────────────────
joblib.dump(model, "phishing_model.pkl")
print("\nModel saved to phishing_model.pkl")
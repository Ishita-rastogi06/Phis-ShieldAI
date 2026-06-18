import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

# Replace with your actual CSV filename if different
df = pd.read_csv("phishing_email_dataset.csv")
print(df["label"].value_counts())

print("Dataset Loaded Successfully")
print("\nColumns:")
print(df.columns.tolist())

print("\nData Types:")
print(df.dtypes)

# Convert everything to string before combining
df["subject"] = df["subject"].fillna("").astype(str)
df["body"] = df["body"].fillna("").astype(str)
df["urls"] = df["urls"].fillna("").astype(str)

# Create combined email text
df["email_text"] = (
    df["subject"] + " " +
    df["body"] + " " +
    df["urls"]
)

# Remove rows with missing labels
df = df.dropna(subset=["label"])

# Features and Labels
X = df["email_text"]
y = df["label"]

# Convert text to numerical vectors
vectorizer = TfidfVectorizer(
    max_features=5000,
    stop_words="english"
)

X_vectorized = vectorizer.fit_transform(X)

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.2,
    random_state=42
)

# Train Model
model = LogisticRegression(
    max_iter=1000
)

model.fit(X_train, y_train)

# Predictions
predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\nEmail Model Accuracy:", round(accuracy, 4))

# Save Files
joblib.dump(
    model,
    "email_model.pkl"
)

joblib.dump(
    vectorizer,
    "email_vectorizer.pkl"
)

print("\nemail_model.pkl saved successfully")
print("email_vectorizer.pkl saved successfully")
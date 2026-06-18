import pandas as pd

df = pd.read_csv("phishing_email_dataset.csv")

print("\nLABEL COUNTS:")
print(df["label"].value_counts())

print("\nFIRST 20 ROWS:")
print(df[["subject", "label"]].head(20))
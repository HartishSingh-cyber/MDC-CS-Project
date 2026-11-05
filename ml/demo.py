
import pandas as pd
import joblib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_FILE = BASE_DIR / "ids_model.pkl"
DATA_FILE = BASE_DIR / "MachineLearningCVE" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

print("Loading AI-IDS model...")
model = joblib.load(MODEL_FILE)

print("Loading sample network records...")
df = pd.read_csv(DATA_FILE, low_memory=False)
df.columns = df.columns.str.strip()
df = df.replace([float("inf"), float("-inf")], float("nan"))
df = df.dropna()

labels = df["Label"].str.strip()
df = df[labels.isin(["BENIGN", "DDoS"])].copy()

# Choose a few examples from both classes
samples = pd.concat([
    df[labels.loc[df.index] == "BENIGN"].head(3),
    df[labels.loc[df.index] == "DDoS"].head(3)
])

X = samples.drop(columns=["Label"]).astype("float32")
predictions = model.predict(X)

print("\n===== AI-IDS DETECTION DEMO =====")
for i, prediction in enumerate(predictions):
    result = "DDoS ATTACK" if prediction == 1 else "BENIGN TRAFFIC"
    actual = samples.iloc[i]["Label"]
    print(f"Record {i + 1}: Predicted={result} | Dataset label={actual}")

print("\nDemo completed.")
print("Note: These are saved dataset records, not live network traffic.")


import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = BASE_DIR / "MachineLearningCVE" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
MODEL_FILE = BASE_DIR / "ids_model.pkl"

print("Loading dataset...", flush=True)
df = pd.read_csv(DATA_FILE, low_memory=False)
df.columns = df.columns.str.strip()
print("Dataset loaded:", df.shape, flush=True)

df = df.replace([float("inf"), float("-inf")], float("nan"))
df = df.dropna()

y = df["Label"].str.strip().map({"BENIGN": 0, "DDoS": 1})
valid = y.notna()
df = df.loc[valid].copy()
y = y.loc[valid].astype(int)
X = df.drop(columns=["Label"])

# Keep a manageable, balanced sample for the first prototype
sample_size = min(60000, len(df))
sample = pd.concat([
    df[y == 0].sample(n=min(sample_size // 2, (y == 0).sum()), random_state=42),
    df[y == 1].sample(n=min(sample_size // 2, (y == 1).sum()), random_state=42)
]).sample(frac=1, random_state=42)

y_sample = sample["Label"].str.strip().map({"BENIGN": 0, "DDoS": 1}).astype(int)
X_sample = sample.drop(columns=["Label"]).astype("float32")

print("Training sample:", X_sample.shape, flush=True)

X_train, X_test, y_train, y_test = train_test_split(
    X_sample, y_sample, test_size=0.2, random_state=42, stratify=y_sample
)

model = RandomForestClassifier(
    n_estimators=60, random_state=42, n_jobs=-1
)

print("Training model...", flush=True)
model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
print("\nClassification report:")
print(classification_report(
    y_test, predictions, labels=[0, 1],
    target_names=["BENIGN", "DDoS"], zero_division=0
))
print("Confusion matrix:\n", confusion_matrix(y_test, predictions))

joblib.dump(model, MODEL_FILE)
print(f"\nModel saved to: {MODEL_FILE}", flush=True)

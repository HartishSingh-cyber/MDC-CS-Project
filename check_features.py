import pandas as pd
from pathlib import Path

base = Path(__file__).resolve().parent
csv_file = base / "MachineLearningCVE" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(csv_file, nrows=5, low_memory=False)
df.columns = df.columns.str.strip()
features = [c for c in df.columns if c != "Label"]

print("Number of features:", len(features))
print("\nFeature names in training order:")
for i, name in enumerate(features, start=1):
    print(f"{i}. {name}")

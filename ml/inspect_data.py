import pandas as pd
import os

# Location of our dataset
dataset_folder = "../MachineLearningCVE"

# Find CSV files
files = [f for f in os.listdir(dataset_folder) if f.endswith(".csv")]

print("CSV files found:")
for file in files:
    print("-", file)

# Read the first CSV
file_path = os.path.join(dataset_folder, files[0])

print("\nLoading:", files[0])

df = pd.read_csv(file_path)

print("\nDataset shape:")
print(df.shape)

print("\nFirst 5 rows:")
print(df.head())

print("\nColumn names:")
print(df.columns.tolist())

print("\nAttack types:")
print(df[" Label"].value_counts())
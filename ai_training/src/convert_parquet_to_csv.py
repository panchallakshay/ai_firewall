"""
Convert CIC-DDoS2019 Parquet files to CSV and combine for training
"""

import pandas as pd
import os
from pathlib import Path

# Paths
KAGGLE_PATH = "/Users/lakshaly/.cache/kagglehub/datasets/dhoogla/cicddos2019/versions/3"
DATA_DIR = "/Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_training/data"

print("=" * 60)
print("CIC-DDoS2019 Parquet to CSV Converter")
print("=" * 60)
print()

# Get all training parquet files
training_files = [f for f in os.listdir(KAGGLE_PATH) if f.endswith('-training.parquet')]

print(f"Found {len(training_files)} training files")
print()

# Combine all training files
combined_df = None
total_rows = 0

for file in sorted(training_files):
    file_path = os.path.join(KAGGLE_PATH, file)
    attack_type = file.replace('-training.parquet', '')
    
    print(f"Processing {file}...")
    df = pd.read_parquet(file_path)
    
    # Add attack type label if not present
    if 'Label' not in df.columns:
        df['Label'] = attack_type
    
    print(f"  Rows: {len(df):,}")
    print(f"  Columns: {len(df.columns)}")
    
    total_rows += len(df)
    
    if combined_df is None:
        combined_df = df
    else:
        combined_df = pd.concat([combined_df, df], ignore_index=True)

print()
print(f"✓ Combined {len(training_files)} files")
print(f"✓ Total rows: {total_rows:,}")
print(f"✓ Total columns: {len(combined_df.columns)}")
print()

# Save to CSV
output_path = os.path.join(DATA_DIR, 'cic_ddos2019_flows.csv')
print(f"Saving to: {output_path}")
combined_df.to_csv(output_path, index=False)

file_size = os.path.getsize(output_path) / (1024 * 1024)  # MB
print(f"✓ Saved! File size: {file_size:.1f} MB")
print()

# Show label distribution
print("Label distribution:")
print(combined_df['Label'].value_counts())
print()

print("=" * 60)
print("Dataset Ready for Training!")
print("=" * 60)
print()
print("Next steps:")
print("  1. Train Flow model:")
print("     python src/train_flow_model.py")
print()
print("  2. Or start with DNS model first:")
print("     python src/train_dns_model.py")
print()

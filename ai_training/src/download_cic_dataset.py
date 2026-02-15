"""
Download CIC-DDoS2019 dataset from Kaggle using kagglehub
"""

import kagglehub
import os
import shutil

print("=" * 60)
print("CIC-DDoS2019 Dataset Downloader")
print("=" * 60)
print()

# Download latest version
print("Downloading CIC-DDoS2019 dataset from Kaggle...")
print("This may take a while (dataset is ~1-20GB)...")
print()

try:
    path = kagglehub.dataset_download("dhoogla/cicddos2019")
    
    print("✓ Download complete!")
    print(f"Path to dataset files: {path}")
    print()
    
    # List downloaded files
    print("Downloaded files:")
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB
            print(f"  - {file} ({file_size:.1f} MB)")
    
    print()
    print("=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print()
    print("1. The dataset has been downloaded to:")
    print(f"   {path}")
    print()
    print("2. To use it for training, copy/link the CSV files to:")
    print("   /Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_training/data/")
    print()
    print("3. Recommended: Start with a sample file (e.g., DrDoS_DNS.csv)")
    print("   for faster training and testing")
    print()
    
except Exception as e:
    print(f"✗ Error downloading dataset: {e}")
    print()
    print("Troubleshooting:")
    print("1. Ensure you have Kaggle credentials configured")
    print("2. Run: kaggle datasets download -d dhoogla/cicddos2019")
    print("3. Or download manually from:")
    print("   https://www.kaggle.com/datasets/dhoogla/cicddos2019")

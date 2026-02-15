# AI Firewall - Training Pipeline

Machine learning pipeline for training DNS and Flow threat detection models.

## Overview

This pipeline trains two AI models:
- **DNS Model**: Domain-based threat detection (malware, phishing, DGA)
- **Flow Model**: Connection behavior anomaly detection (DDoS, floods, scanning)

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Download Datasets

```bash
cd src
python download_datasets.py
```

This will download:
- Tranco top 100k domains (benign)
- URLhaus malware domains
- Sample blocklists

**Manual Download Required:**
- **CIC-DDoS2019**: Download from [UNB CIC Datasets](https://www.unb.ca/cic/datasets/ddos-2019.html)
- Save CSV to `data/cic_ddos2019_flows.csv`

### 3. Train DNS Model

```bash
python src/train_dns_model.py
```

Output:
- `out/dns_model.h5` (Keras model)
- `out/dns_metadata.json` (feature specs)

### 4. Train Flow Model

```bash
python src/train_flow_model.py
```

Output:
- `out/flow_model.h5` (Keras model)
- `out/flow_metadata.json` (feature specs)

### 5. Export to TFLite

```bash
python src/export_tflite.py
```

Output:
- `out/dns_model.tflite` (~50KB)
- `out/flow_model.tflite` (~100KB)
- `out/metadata.json` (combined metadata)

## Features

### DNS Model (11 features)

1. Domain length
2. Number of dots (subdomain depth)
3. Shannon entropy (randomness)
4. Punycode flag (IDN attacks)
5. Digit ratio
6. Vowel ratio
7. TLD risk score
8. Max consecutive consonants (DGA indicator)
9. DNS queries per minute (burst detection)
10. Unique domains per minute (scanning)
11. Tranco rank bucket (popularity)

### Flow Model (15 features)

1. Destination IP risk score
2. Destination port
3. Protocol (TCP/UDP)
4. Packets per second
5. Bytes per second
6. Upload/download ratio
7. Connection duration
8. New connections per minute
9. Unique destination IPs per minute
10. Failure rate
11. App permission count
12. Is system app
13. App install age
14. Background restriction state
15. Destination diversity entropy

## Model Architecture

Both models use MLP (Multi-Layer Perceptron):

**DNS Model:**
- Input: 11 features
- Hidden: [64, 32, 16]
- Output: 3 classes (ALLOW, WARN, BLOCK)

**Flow Model:**
- Input: 15 features
- Hidden: [128, 64, 32]
- Output: 3 classes (ALLOW, WARN, BLOCK)

## Dataset Sources

- **Benign Domains**: [Tranco](https://tranco-list.eu/)
- **Malware Domains**: [URLhaus](https://urlhaus.abuse.ch/)
- **Phishing Domains**: [PhishTank](https://www.phishtank.net/)
- **Flow Data**: [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html)

## File Structure

```
ai_training/
├── data/                      # Raw datasets
│   ├── benign_domains.txt
│   ├── malicious_domains.txt
│   ├── cic_ddos2019_flows.csv
│   ├── domain_blocklist.txt
│   ├── ip_blocklist.txt
│   └── port_blocklist.txt
├── src/                       # Training scripts
│   ├── features_dns.py
│   ├── features_flow.py
│   ├── train_dns_model.py
│   ├── train_flow_model.py
│   ├── export_tflite.py
│   └── download_datasets.py
├── out/                       # Model outputs
│   ├── dns_model.tflite
│   ├── flow_model.tflite
│   └── metadata.json
└── requirements.txt
```

## Next Steps

After training:

1. Copy TFLite models to Android app:
   ```bash
   cp out/*.tflite ../ai_firewall_app/android/app/src/main/assets/models/
   cp out/metadata.json ../ai_firewall_app/android/app/src/main/assets/models/
   ```

2. Copy blocklists to Android app:
   ```bash
   cp data/*_blocklist.txt ../ai_firewall_app/android/app/src/main/assets/rules/
   ```

3. Proceed with Android app development

## Performance

Expected metrics (with proper datasets):

**DNS Model:**
- Accuracy: >95%
- Precision (malicious): >90%
- Recall (malicious): >85%

**Flow Model:**
- Accuracy: >90%
- Precision (attack): >85%
- Recall (attack): >80%

## Troubleshooting

**Issue**: `FileNotFoundError` for datasets
- **Solution**: Run `download_datasets.py` first

**Issue**: Low accuracy
- **Solution**: Ensure datasets are balanced, increase training epochs

**Issue**: TFLite conversion fails
- **Solution**: Check TensorFlow version (2.15.0 recommended)

## License

Training code is independent implementation (no GPL code copied).
Datasets have their own licenses - check source websites.

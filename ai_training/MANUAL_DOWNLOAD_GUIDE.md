# Manual Dataset Download Guide

This guide provides step-by-step instructions for downloading datasets that require manual intervention.

---

## ✅ Already Downloaded

- **Tranco Top Domains** (100,000 benign domains) ✓
- **URLhaus Malware Domains** (2,961 malicious domains) ✓
- **Sample Blocklists** (domain, IP, port) ✓

---

## 📥 Manual Downloads Required

### 1. PhishTank Phishing Domains

PhishTank provides verified phishing URLs that we'll use to train the DNS model.

#### Option A: Direct CSV Download (Recommended)

1. **Visit**: [http://data.phishtank.com/data/online-valid.csv](http://data.phishtank.com/data/online-valid.csv)
   
2. **Download** the CSV file (your browser may block it due to Cloudflare protection)
   
3. **Save as**: `phishtank_verified.csv` in the `data/` directory

4. **Extract domains** using this Python script:

```bash
cd /Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_training/data

python3 << 'EOF'
import csv
from urllib.parse import urlparse

domains = set()
with open('phishtank_verified.csv', 'r', encoding='utf-8', errors='ignore') as f:
    reader = csv.reader(f)
    next(reader)  # Skip header
    for row in reader:
        if len(row) >= 2:
            url = row[1].strip('"')
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domains.add(parsed.netloc)
            except:
                pass

# Append to malicious_domains.txt
with open('malicious_domains.txt', 'a') as f:
    for domain in sorted(domains):
        f.write(domain + '\n')

print(f'✓ Added {len(domains)} phishing domains')
EOF
```

#### Option B: API Access (For Automation)

1. **Register** at [https://www.phishtank.net/register.php](https://www.phishtank.net/register.php)
   
2. **Get API key** from [https://www.phishtank.net/api_info.php](https://www.phishtank.net/api_info.php)
   
3. **Download** using API:
```bash
curl -o phishtank_api.json "http://data.phishtank.com/data/YOUR_API_KEY/online-valid.json"
```

4. **Extract domains** from JSON

---

### 2. CIC-DDoS2019 Flow Dataset

This dataset contains labeled network flows for DDoS attack detection.

#### Download Instructions

1. **Visit**: [https://www.unb.ca/cic/datasets/ddos-2019.html](https://www.unb.ca/cic/datasets/ddos-2019.html)

2. **Scroll** to the "Download" section

3. **Choose** one of these options:

   **Option A: Full Dataset (~20GB)**
   - Download all CSV files
   - Includes multiple attack types
   - Best for production training
   
   **Option B: Sample Dataset (Recommended for Testing)**
   - Download individual attack CSVs:
     - `DrDoS_DNS.csv` (~500MB)
     - `Syn.csv` (~300MB)
     - `TFTP.csv` (~200MB)
   - Faster download and training
   - Good for initial testing

4. **Extract** the downloaded files

5. **Combine** CSVs (if using multiple files):

```bash
cd /Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_training/data

# Combine all CSV files (keep header from first file only)
head -1 DrDoS_DNS.csv > cic_ddos2019_flows.csv
tail -n +2 -q DrDoS_DNS.csv Syn.csv TFTP.csv >> cic_ddos2019_flows.csv

echo "✓ Combined CSV files into cic_ddos2019_flows.csv"
```

#### Alternative: Use Kaggle

The CIC-DDoS2019 dataset is also available on Kaggle:

1. **Visit**: [https://www.kaggle.com/datasets/dhoogla/cicddos2019](https://www.kaggle.com/datasets/dhoogla/cicddos2019)
   
2. **Download** using Kaggle CLI:
```bash
pip install kaggle
kaggle datasets download -d dhoogla/cicddos2019
unzip cicddos2019.zip -d data/
```

---

## 🔍 Verify Downloads

After downloading, verify your datasets:

```bash
cd /Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_training/data

echo "=== Dataset Summary ==="
echo "Benign domains: $(wc -l < benign_domains.txt)"
echo "Malicious domains: $(wc -l < malicious_domains.txt)"
echo ""

if [ -f "cic_ddos2019_flows.csv" ]; then
    echo "✓ CIC-DDoS2019: $(wc -l < cic_ddos2019_flows.csv) flows"
else
    echo "⚠ CIC-DDoS2019: NOT FOUND"
fi

echo ""
echo "Blocklists:"
echo "  - domain_blocklist.txt: $(wc -l < domain_blocklist.txt) entries"
echo "  - ip_blocklist.txt: $(wc -l < ip_blocklist.txt) entries"
echo "  - port_blocklist.txt: $(wc -l < port_blocklist.txt) entries"
```

---

## 🎯 Expected Dataset Sizes

| Dataset | File | Size | Rows |
|---------|------|------|------|
| Benign Domains | `benign_domains.txt` | ~2MB | 100,000 |
| Malicious Domains | `malicious_domains.txt` | ~500KB | 10,000+ |
| CIC-DDoS2019 (sample) | `cic_ddos2019_flows.csv` | ~1GB | 1M+ |
| CIC-DDoS2019 (full) | `cic_ddos2019_flows.csv` | ~20GB | 50M+ |

---

## 🚀 Next Steps

Once all datasets are downloaded:

1. **Train DNS Model**:
```bash
cd /Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_training
python src/train_dns_model.py
```

2. **Train Flow Model**:
```bash
python src/train_flow_model.py
```

3. **Export to TFLite**:
```bash
python src/export_tflite.py
```

---

## 💡 Tips

- **Start with sample datasets** for faster iteration
- **PhishTank updates daily** — download fresh data periodically
- **URLhaus is already downloaded** — no manual action needed
- **CIC-DDoS2019 is large** — ensure you have enough disk space
- **Use SSD storage** for faster training

---

## 🆘 Troubleshooting

### PhishTank Download Blocked

**Problem**: Cloudflare blocks automated downloads

**Solution**: 
1. Open the URL in your browser
2. Save the page as CSV
3. Move to `data/` directory

### CIC-DDoS2019 Download Slow

**Problem**: Large file size (~20GB)

**Solution**:
1. Use a download manager (e.g., `wget`, `aria2c`)
2. Download individual attack CSVs instead of full dataset
3. Use Kaggle mirror (often faster)

### Insufficient Disk Space

**Problem**: Not enough space for full dataset

**Solution**:
1. Use sample datasets (DrDoS_DNS.csv only)
2. Clean up temporary files
3. Use external storage

---

## 📧 Support

If you encounter issues:

1. Check the [CIC Datasets FAQ](https://www.unb.ca/cic/datasets/index.html)
2. Visit [PhishTank Developer Info](https://www.phishtank.net/developer_info.php)
3. Review the [URLhaus API Docs](https://urlhaus.abuse.ch/api/)

---

**Current Status**:
- ✅ Benign domains: 100,000
- ✅ Malicious domains: 2,961 (URLhaus)
- ⚠️ PhishTank: Manual download required
- ⚠️ CIC-DDoS2019: Manual download required

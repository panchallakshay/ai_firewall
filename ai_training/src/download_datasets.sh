#!/bin/bash

# AI Firewall Dataset Downloader
# Downloads datasets for training DNS and Flow models

set -e

DATA_DIR="$(cd "$(dirname "$0")/../data" && pwd)"
echo "Data directory: $DATA_DIR"
mkdir -p "$DATA_DIR"

echo "=========================================="
echo "AI Firewall Dataset Downloader"
echo "=========================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# 1. Download Tranco Top Domains (Benign)
echo ""
echo "[1/4] Downloading Tranco Top Domains (Benign)..."
if [ -f "$DATA_DIR/benign_domains.txt" ]; then
    print_warning "benign_domains.txt already exists, skipping"
else
    echo "Downloading Tranco top 1M domains..."
    curl -L -o "$DATA_DIR/tranco_top1m.csv.zip" "https://tranco-list.eu/top-1m.csv.zip"
    
    echo "Extracting domains..."
    unzip -o "$DATA_DIR/tranco_top1m.csv.zip" -d "$DATA_DIR"
    
    # Extract just the domains (second column)
    cut -d',' -f2 "$DATA_DIR/top-1m.csv" | head -100000 > "$DATA_DIR/benign_domains.txt"
    
    # Cleanup
    rm "$DATA_DIR/tranco_top1m.csv.zip"
    rm "$DATA_DIR/top-1m.csv"
    
    print_status "Downloaded $(wc -l < "$DATA_DIR/benign_domains.txt") benign domains"
fi

# 2. Download URLhaus Malware Domains
echo ""
echo "[2/4] Downloading URLhaus Malware Domains..."
if [ -f "$DATA_DIR/malicious_domains.txt" ]; then
    print_warning "malicious_domains.txt already exists, appending new data"
else
    touch "$DATA_DIR/malicious_domains.txt"
fi

echo "Downloading URLhaus recent malware URLs..."
curl -L -o "$DATA_DIR/urlhaus_recent.csv" "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Extract domains from URLs (column 3)
echo "Extracting domains from URLs..."
awk -F',' 'NR>9 && $3 != "" {
    # Remove quotes and extract domain
    gsub(/"/, "", $3)
    # Parse URL to get domain
    if (match($3, /^https?:\/\/([^\/]+)/, arr)) {
        print arr[1]
    }
}' "$DATA_DIR/urlhaus_recent.csv" | sort -u >> "$DATA_DIR/malicious_domains.txt"

rm "$DATA_DIR/urlhaus_recent.csv"

# Remove duplicates
sort -u "$DATA_DIR/malicious_domains.txt" -o "$DATA_DIR/malicious_domains.txt"

print_status "Total malicious domains: $(wc -l < "$DATA_DIR/malicious_domains.txt")"

# 3. PhishTank Phishing Domains
echo ""
echo "[3/4] PhishTank Phishing Domains..."
print_warning "PhishTank requires manual download or API key"
echo ""
echo "Please follow these steps:"
echo "  1. Visit: https://www.phishtank.net/developer_info.php"
echo "  2. Download 'verified_online.csv' (no API key needed for CSV)"
echo "  3. Or register for API access for JSON format"
echo "  4. Extract domains and append to: $DATA_DIR/malicious_domains.txt"
echo ""
echo "Alternative: Use the online CSV endpoint (may require browser):"
echo "  http://data.phishtank.com/data/online-valid.csv"
echo ""

# Try to download PhishTank CSV (may fail due to Cloudflare)
echo "Attempting automatic download..."
if curl -L -f -o "$DATA_DIR/phishtank_temp.csv" "http://data.phishtank.com/data/online-valid.csv" 2>/dev/null; then
    # Extract domains (column 2)
    awk -F',' 'NR>1 && $2 != "" {
        gsub(/"/, "", $2)
        if (match($2, /^https?:\/\/([^\/]+)/, arr)) {
            print arr[1]
        }
    }' "$DATA_DIR/phishtank_temp.csv" | sort -u >> "$DATA_DIR/malicious_domains.txt"
    
    rm "$DATA_DIR/phishtank_temp.csv"
    sort -u "$DATA_DIR/malicious_domains.txt" -o "$DATA_DIR/malicious_domains.txt"
    
    print_status "PhishTank domains added"
else
    print_warning "Automatic download failed (Cloudflare protection)"
    print_warning "Please download manually from the link above"
fi

# 4. CIC-DDoS2019 Dataset
echo ""
echo "[4/4] CIC-DDoS2019 Flow Dataset..."
print_warning "CIC-DDoS2019 requires manual download"
echo ""
echo "Please follow these steps:"
echo "  1. Visit: https://www.unb.ca/cic/datasets/ddos-2019.html"
echo "  2. Scroll to 'Download' section"
echo "  3. Download the CSV files (multiple files, ~20GB total)"
echo "  4. Extract and combine into: $DATA_DIR/cic_ddos2019_flows.csv"
echo ""
echo "Recommended: Download a sample first for testing:"
echo "  - Use 'DrDoS_DNS.csv' or 'Syn.csv' (smaller files)"
echo "  - Combine multiple attack types for better training"
echo ""

# Create sample blocklists
echo ""
echo "Creating sample blocklists..."

# Domain blocklist
cat > "$DATA_DIR/domain_blocklist.txt" << 'EOF'
# Domain Blocklist
# Format: exact domain or wildcard (*.example.com)
malware-test.com
phishing-example.net
*.suspicious-ads.tk
*.tracker.ml
*.adserver.xyz
badsite.ru
evil-domain.cn
EOF
print_status "Created domain_blocklist.txt"

# IP blocklist
cat > "$DATA_DIR/ip_blocklist.txt" << 'EOF'
# IP Blocklist
# Format: IP address or CIDR notation
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
EOF
print_status "Created ip_blocklist.txt"

# Port blocklist
cat > "$DATA_DIR/port_blocklist.txt" << 'EOF'
# Port Blocklist
# Format: port number (one per line)
23
135
139
445
1433
3389
5900
6667
EOF
print_status "Created port_blocklist.txt"

# Summary
echo ""
echo "=========================================="
echo "Download Summary"
echo "=========================================="
echo ""

if [ -f "$DATA_DIR/benign_domains.txt" ]; then
    print_status "Benign domains: $(wc -l < "$DATA_DIR/benign_domains.txt") domains"
else
    print_error "Benign domains: NOT FOUND"
fi

if [ -f "$DATA_DIR/malicious_domains.txt" ]; then
    print_status "Malicious domains: $(wc -l < "$DATA_DIR/malicious_domains.txt") domains"
else
    print_error "Malicious domains: NOT FOUND"
fi

if [ -f "$DATA_DIR/cic_ddos2019_flows.csv" ]; then
    print_status "CIC-DDoS2019: READY"
else
    print_warning "CIC-DDoS2019: MANUAL DOWNLOAD REQUIRED"
fi

echo ""
echo "Blocklists created:"
print_status "domain_blocklist.txt"
print_status "ip_blocklist.txt"
print_status "port_blocklist.txt"

echo ""
echo "=========================================="
echo "Next Steps"
echo "=========================================="
echo ""
echo "1. Complete manual downloads (PhishTank, CIC-DDoS2019)"
echo "2. Train DNS model:"
echo "   python src/train_dns_model.py"
echo ""
echo "3. Train Flow model:"
echo "   python src/train_flow_model.py"
echo ""
echo "4. Export to TFLite:"
echo "   python src/export_tflite.py"
echo ""

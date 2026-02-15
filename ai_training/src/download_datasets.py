"""
Download and prepare datasets for AI Firewall training
"""

import requests
import os
from urllib.parse import urlparse


def download_file(url: str, output_path: str):
    """Download file from URL"""
    print(f"Downloading {url}...")
    
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        # Create directory if needed
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Download with progress
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    progress = (downloaded / total_size) * 100
                    print(f"  Progress: {progress:.1f}%", end='\r')
        
        print(f"\n✓ Downloaded to {output_path}")
        return True
        
    except Exception as e:
        print(f"✗ Error downloading: {e}")
        return False


def download_tranco_domains(output_path: str, top_n: int = 100000):
    """
    Download Tranco top domains list
    
    Args:
        output_path: Path to save benign domains
        top_n: Number of top domains to download
    """
    print("\n[1/4] Downloading Tranco top domains (benign)...")
    
    # Tranco provides daily lists
    url = "https://tranco-list.eu/top-1m.csv.zip"
    zip_path = output_path.replace('.txt', '.zip')
    
    if download_file(url, zip_path):
        # Extract and process
        import zipfile
        
        print("Extracting domains...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            csv_name = zip_ref.namelist()[0]
            zip_ref.extract(csv_name, os.path.dirname(output_path))
            
            # Read CSV and extract domains
            csv_path = os.path.join(os.path.dirname(output_path), csv_name)
            domains = []
            
            with open(csv_path, 'r') as f:
                for i, line in enumerate(f):
                    if i >= top_n:
                        break
                    parts = line.strip().split(',')
                    if len(parts) == 2:
                        domains.append(parts[1])
            
            # Save domains
            with open(output_path, 'w') as f:
                f.write('\n'.join(domains))
            
            print(f"✓ Saved {len(domains)} benign domains to {output_path}")
            
            # Cleanup
            os.remove(zip_path)
            os.remove(csv_path)


def download_urlhaus_domains(output_path: str):
    """
    Download URLhaus malware domains
    
    Args:
        output_path: Path to save malicious domains
    """
    print("\n[2/4] Downloading URLhaus malware domains...")
    
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    csv_path = output_path.replace('.txt', '_urlhaus.csv')
    
    if download_file(url, csv_path):
        # Parse CSV and extract domains
        domains = set()
        
        with open(csv_path, 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                
                parts = line.strip().split(',')
                if len(parts) >= 3:
                    url_str = parts[2].strip('"')
                    try:
                        parsed = urlparse(url_str)
                        if parsed.netloc:
                            domains.add(parsed.netloc)
                    except:
                        pass
        
        print(f"Extracted {len(domains)} unique domains from URLhaus")
        
        # Append to output file
        with open(output_path, 'a') as f:
            f.write('\n'.join(sorted(domains)) + '\n')
        
        os.remove(csv_path)


def download_phishtank_domains(output_path: str):
    """
    Download PhishTank phishing domains
    
    Note: PhishTank requires API key for automated downloads
    This is a placeholder - manual download recommended
    """
    print("\n[3/4] PhishTank domains...")
    print("  PhishTank requires manual download or API key")
    print("  Please visit: https://www.phishtank.net/developer_info.php")
    print("  Download verified phishing URLs and extract domains")
    print(f"  Save to: {output_path}")


def create_sample_blocklists(data_dir: str):
    """
    Create sample blocklists for rules engine
    """
    print("\n[4/4] Creating sample blocklists...")
    
    # Domain blocklist (sample)
    domain_blocklist = [
        "malware-test.com",
        "phishing-example.net",
        "*.suspicious-ads.tk",
        "*.tracker.ml",
    ]
    
    domain_path = os.path.join(data_dir, 'domain_blocklist.txt')
    with open(domain_path, 'w') as f:
        f.write('\n'.join(domain_blocklist))
    print(f"✓ Created {domain_path}")
    
    # IP blocklist (sample - known malicious ranges)
    ip_blocklist = [
        "192.0.2.0/24",  # TEST-NET-1 (example)
        "198.51.100.0/24",  # TEST-NET-2 (example)
    ]
    
    ip_path = os.path.join(data_dir, 'ip_blocklist.txt')
    with open(ip_path, 'w') as f:
        f.write('\n'.join(ip_blocklist))
    print(f"✓ Created {ip_path}")
    
    # Port blocklist (dangerous ports)
    port_blocklist = [
        "23",    # Telnet
        "135",   # MS RPC
        "139",   # NetBIOS
        "445",   # SMB
        "1433",  # MS SQL
        "3389",  # RDP
        "5900",  # VNC
        "6667",  # IRC
    ]
    
    port_path = os.path.join(data_dir, 'port_blocklist.txt')
    with open(port_path, 'w') as f:
        f.write('\n'.join(port_blocklist))
    print(f"✓ Created {port_path}")


def main():
    """Main download pipeline"""
    
    DATA_DIR = '../data'
    os.makedirs(DATA_DIR, exist_ok=True)
    
    benign_path = os.path.join(DATA_DIR, 'benign_domains.txt')
    malicious_path = os.path.join(DATA_DIR, 'malicious_domains.txt')
    
    print("="*60)
    print("AI Firewall Dataset Downloader")
    print("="*60)
    
    # Download benign domains
    if not os.path.exists(benign_path):
        download_tranco_domains(benign_path, top_n=100000)
    else:
        print(f"\n[1/4] Benign domains already exist: {benign_path}")
    
    # Download malicious domains
    if not os.path.exists(malicious_path):
        # Create empty file
        open(malicious_path, 'w').close()
        
        download_urlhaus_domains(malicious_path)
        download_phishtank_domains(malicious_path)
    else:
        print(f"\n[2/4] Malicious domains already exist: {malicious_path}")
    
    # Create blocklists
    create_sample_blocklists(DATA_DIR)
    
    print("\n" + "="*60)
    print("Dataset download complete!")
    print("="*60)
    print("\nNote: For CIC-DDoS2019 dataset:")
    print("  1. Visit: https://www.unb.ca/cic/datasets/ddos-2019.html")
    print("  2. Download the CSV files")
    print(f"  3. Save to: {os.path.join(DATA_DIR, 'cic_ddos2019_flows.csv')}")
    print("\nNext steps:")
    print("  python src/train_dns_model.py")
    print("  python src/train_flow_model.py")
    print("  python src/export_tflite.py")


if __name__ == "__main__":
    main()

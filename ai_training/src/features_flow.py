"""
Flow Feature Extraction for Connection Behavior Analysis
Extracts 15 features from network flows for anomaly detection
"""

import ipaddress
from typing import Dict, List, Tuple
import math
from collections import Counter


class FlowFeatureExtractor:
    """Extract features from network flows for anomaly detection"""
    
    # Known malicious IP ranges (example - should be loaded from blocklist)
    MALICIOUS_IP_RANGES = [
        '192.0.2.0/24',  # TEST-NET-1 (example)
    ]
    
    # High-risk ports
    HIGH_RISK_PORTS = {
        23,    # Telnet
        135,   # MS RPC
        139,   # NetBIOS
        445,   # SMB
        1433,  # MS SQL
        3389,  # RDP
        5900,  # VNC
        6667,  # IRC
    }
    
    def __init__(self, ip_blocklist: List[str] = None):
        """
        Initialize feature extractor
        
        Args:
            ip_blocklist: List of malicious IP ranges in CIDR notation
        """
        self.ip_blocklist = ip_blocklist or self.MALICIOUS_IP_RANGES
        self._compile_ip_networks()
    
    def _compile_ip_networks(self):
        """Compile IP ranges into network objects for fast matching"""
        self.malicious_networks = []
        for cidr in self.ip_blocklist:
            try:
                self.malicious_networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                print(f"Warning: Invalid CIDR notation: {cidr}")
    
    def extract_features(self, flow_stats: Dict, app_info: Dict = None) -> Tuple[list, list]:
        """
        Extract all flow features
        
        Args:
            flow_stats: Flow statistics dict containing:
                - dst_ip: Destination IP address
                - dst_port: Destination port
                - protocol: 'TCP' or 'UDP'
                - packets_per_sec: Packets per second
                - bytes_per_sec: Bytes per second
                - upload_bytes: Total upload bytes
                - download_bytes: Total download bytes
                - duration_sec: Connection duration in seconds
                - new_connections_per_min: New connections in last minute
                - unique_dst_ips_per_min: Unique destination IPs in last minute
                - failure_count: Number of failed connections (RST/timeout)
                - total_connections: Total connection attempts
                - unique_dst_ips: Set of unique destination IPs
            
            app_info: Optional app information dict:
                - permission_count: Number of permissions granted
                - is_system_app: Boolean
                - install_age_days: Days since installation
                - background_restricted: Boolean
        
        Returns:
            Tuple of (feature_vector, feature_names)
        """
        app_info = app_info or {}
        
        features = []
        feature_names = []
        
        # 1. Destination IP risk score
        features.append(self._ip_risk_score(flow_stats.get('dst_ip', '')))
        feature_names.append('dst_ip_risk')
        
        # 2. Destination port
        features.append(float(flow_stats.get('dst_port', 0)))
        feature_names.append('dst_port')
        
        # 3. Protocol (TCP=0, UDP=1)
        protocol = flow_stats.get('protocol', 'TCP')
        features.append(0.0 if protocol == 'TCP' else 1.0)
        feature_names.append('protocol')
        
        # 4. Packets per second
        features.append(flow_stats.get('packets_per_sec', 0.0))
        feature_names.append('packets_per_sec')
        
        # 5. Bytes per second
        features.append(flow_stats.get('bytes_per_sec', 0.0))
        feature_names.append('bytes_per_sec')
        
        # 6. Upload/download ratio
        features.append(self._upload_download_ratio(
            flow_stats.get('upload_bytes', 0),
            flow_stats.get('download_bytes', 0)
        ))
        feature_names.append('upload_download_ratio')
        
        # 7. Connection duration
        features.append(flow_stats.get('duration_sec', 0.0))
        feature_names.append('duration_sec')
        
        # 8. New connections per minute
        features.append(flow_stats.get('new_connections_per_min', 0.0))
        feature_names.append('new_connections_per_min')
        
        # 9. Unique destination IPs per minute
        features.append(flow_stats.get('unique_dst_ips_per_min', 0.0))
        feature_names.append('unique_dst_ips_per_min')
        
        # 10. Failure rate
        features.append(self._failure_rate(
            flow_stats.get('failure_count', 0),
            flow_stats.get('total_connections', 1)
        ))
        feature_names.append('failure_rate')
        
        # 11. App permission count
        features.append(float(app_info.get('permission_count', 0)))
        feature_names.append('app_permission_count')
        
        # 12. Is system app
        features.append(1.0 if app_info.get('is_system_app', False) else 0.0)
        feature_names.append('is_system_app')
        
        # 13. App install age (days)
        features.append(float(app_info.get('install_age_days', 0)))
        feature_names.append('install_age_days')
        
        # 14. Background restriction state
        features.append(1.0 if app_info.get('background_restricted', False) else 0.0)
        feature_names.append('background_restricted')
        
        # 15. Destination diversity entropy
        features.append(self._destination_diversity(
            flow_stats.get('unique_dst_ips', set())
        ))
        feature_names.append('dst_diversity_entropy')
        
        return features, feature_names
    
    def _ip_risk_score(self, ip: str) -> float:
        """
        Score IP address based on blocklist and characteristics
        
        Returns:
            0.0 = Safe (private/local)
            0.5 = Unknown public IP
            1.0 = Known malicious IP
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if private/local
            if ip_obj.is_private or ip_obj.is_loopback:
                return 0.0
            
            # Check against blocklist
            for network in self.malicious_networks:
                if ip_obj in network:
                    return 1.0
            
            # Unknown public IP
            return 0.5
            
        except ValueError:
            return 0.5  # Invalid IP
    
    def _upload_download_ratio(self, upload: int, download: int) -> float:
        """
        Calculate upload/download ratio
        
        High ratio may indicate data exfiltration
        Normalized to [0, 1] range
        """
        if download == 0:
            return 1.0 if upload > 0 else 0.0
        
        ratio = upload / (upload + download)
        return ratio
    
    def _failure_rate(self, failures: int, total: int) -> float:
        """Calculate connection failure rate"""
        if total == 0:
            return 0.0
        return failures / total
    
    def _destination_diversity(self, dst_ips: set) -> float:
        """
        Calculate entropy of destination IP distribution
        
        High entropy = scanning behavior (many different IPs)
        Low entropy = normal behavior (few repeated IPs)
        """
        if not dst_ips or len(dst_ips) <= 1:
            return 0.0
        
        # For simplicity, use normalized count as proxy for entropy
        # In production, could track frequency distribution
        diversity_score = min(len(dst_ips) / 100.0, 1.0)  # Normalize to [0, 1]
        return diversity_score


# Example usage
if __name__ == "__main__":
    extractor = FlowFeatureExtractor()
    
    # Test benign flow (normal web browsing)
    benign_flow = {
        'dst_ip': '142.250.185.46',  # Google IP
        'dst_port': 443,
        'protocol': 'TCP',
        'packets_per_sec': 15.0,
        'bytes_per_sec': 25000.0,
        'upload_bytes': 5000,
        'download_bytes': 50000,
        'duration_sec': 10.0,
        'new_connections_per_min': 3.0,
        'unique_dst_ips_per_min': 2.0,
        'failure_count': 0,
        'total_connections': 5,
        'unique_dst_ips': {'142.250.185.46', '172.217.14.206'}
    }
    
    benign_app = {
        'permission_count': 5,
        'is_system_app': False,
        'install_age_days': 120,
        'background_restricted': False
    }
    
    features, names = extractor.extract_features(benign_flow, benign_app)
    print("Benign flow (web browsing):")
    for name, value in zip(names, features):
        print(f"  {name}: {value}")
    
    print()
    
    # Test suspicious flow (DDoS-like)
    suspicious_flow = {
        'dst_ip': '192.0.2.10',  # Example malicious IP
        'dst_port': 80,
        'protocol': 'TCP',
        'packets_per_sec': 1500.0,  # Very high
        'bytes_per_sec': 150000.0,
        'upload_bytes': 100000,
        'download_bytes': 1000,  # High upload ratio
        'duration_sec': 2.0,
        'new_connections_per_min': 200.0,  # Flood
        'unique_dst_ips_per_min': 150.0,  # Scanning
        'failure_count': 50,
        'total_connections': 200,
        'unique_dst_ips': set(f'192.0.2.{i}' for i in range(150))
    }
    
    suspicious_app = {
        'permission_count': 15,  # Many permissions
        'is_system_app': False,
        'install_age_days': 2,  # Recently installed
        'background_restricted': True
    }
    
    features, names = extractor.extract_features(suspicious_flow, suspicious_app)
    print("Suspicious flow (DDoS-like):")
    for name, value in zip(names, features):
        print(f"  {name}: {value}")

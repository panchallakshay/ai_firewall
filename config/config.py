"""
Configuration management for Shakti X AI Firewall
Central configuration for ML models, detection thresholds, API keys, and rules
"""

import os
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class MLConfig:
    """Machine Learning model configuration"""
    # Model paths
    isolation_forest_model_path: str = "models/isolation_forest.tflite"
    autoencoder_model_path: str = "models/lstm_autoencoder.tflite"
    threat_classifier_model_path: str = "models/threat_classifier.tflite"
    
    # Model parameters
    isolation_forest_contamination: float = 0.1  # Expected outlier ratio
    autoencoder_threshold: float = 0.5  # Reconstruction error threshold
    
    # Feature extraction
    time_window_seconds: int = 60  # Window for feature aggregation
    min_packets_for_analysis: int = 10  # Minimum packets before analysis
    
    # Continuous learning
    enable_continuous_learning: bool = True
    learning_rate: float = 0.001
    model_update_interval_hours: int = 24
    min_samples_for_update: int = 1000


@dataclass
class ThreatIntelConfig:
    """Threat Intelligence API configuration"""
    # API Keys (set via environment variables for security)
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    alienvault_api_key: str = os.getenv("ALIENVAULT_API_KEY", "")
    
    # API Endpoints
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"
    alienvault_url: str = "https://otx.alienvault.com/api/v1/indicators"
    urlhaus_url: str = "https://urlhaus-api.abuse.ch/v1/url/"
    virustotal_url: str = "https://www.virustotal.com/api/v3/ip_addresses"
    
    # Rate limiting
    abuseipdb_max_requests_per_day: int = 1000
    virustotal_max_requests_per_minute: int = 4
    
    # Caching
    cache_ttl_days: int = 7
    enable_disk_cache: bool = True
    cache_directory: str = "cache/threat_intel"
    
    # Threat scoring
    threat_score_threshold: int = 50  # 0-100, above this is considered malicious
    min_sources_for_block: int = 2  # Require multiple sources to confirm threat


@dataclass
class DetectionConfig:
    """Detection thresholds and rules"""
    # Anomaly detection thresholds
    anomaly_score_threshold: float = 0.7  # 0-1, higher = more anomalous
    
    # Rate-based detection
    max_packets_per_sec: int = 1000  # DDoS threshold
    max_bytes_per_sec: int = 10_000_000  # 10 MB/s
    max_dns_queries_per_min: int = 100
    max_unique_destinations_per_min: int = 50
    
    # Data exfiltration detection
    max_upload_bytes_per_min: int = 50_000_000  # 50 MB/min
    suspicious_upload_ratio: float = 10.0  # Upload/download ratio
    
    # Behavioral detection
    background_traffic_threshold: float = 0.8  # 80% background = suspicious
    new_destination_spike_threshold: int = 20  # New IPs in short time
    
    # DNS-based detection
    max_dns_txt_queries_per_min: int = 5  # TXT queries often used for C2
    dns_failure_rate_threshold: float = 0.5  # 50% failure rate
    
    # Port scanning detection
    unique_ports_threshold: int = 50  # Scanning many ports
    port_scan_time_window_sec: int = 60
    
    # Alert thresholds
    info_threshold: float = 30.0  # Threat score 0-30 = INFO
    low_threshold: float = 50.0  # 30-50 = LOW
    medium_threshold: float = 70.0  # 50-70 = MEDIUM
    high_threshold: float = 85.0  # 70-85 = HIGH
    # 85-100 = CRITICAL


@dataclass
class FilterConfig:
    """Packet filtering rules"""
    # Blocked ports (dangerous/legacy protocols)
    blocked_ports: List[int] = None
    
    # Blocked protocols
    block_icmp: bool = False  # Usually safe, but can be used for tunneling
    
    # Geo-blocking
    blocked_countries: List[str] = None  # ISO country codes
    enable_geo_blocking: bool = False
    
    # Time-based rules
    enable_time_based_rules: bool = False
    night_mode_start_hour: int = 22  # 10 PM
    night_mode_end_hour: int = 6  # 6 AM
    
    # VPN detection
    detect_vpn_leakage: bool = True
    
    # Certificate pinning
    detect_mitm_attempts: bool = True
    
    def __post_init__(self):
        if self.blocked_ports is None:
            # Default dangerous ports
            self.blocked_ports = [
                21,    # FTP
                23,    # Telnet
                135,   # Windows RPC
                139,   # NetBIOS
                445,   # SMB
                1433,  # MS SQL
                3306,  # MySQL
                3389,  # RDP
                5432,  # PostgreSQL
                5900,  # VNC
            ]
        
        if self.blocked_countries is None:
            self.blocked_countries = []  # User configurable


@dataclass
class SystemConfig:
    """System-level configuration"""
    # Logging
    log_level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_file: str = "logs/shakti_x.log"
    max_log_size_mb: int = 100
    
    # Performance
    max_worker_threads: int = 4
    packet_queue_size: int = 10000
    enable_gpu_acceleration: bool = True  # Use NPU/GPU for ML inference
    
    # Storage
    database_path: str = "data/shakti_x.db"
    max_alerts_stored: int = 10000
    max_traffic_history_days: int = 30
    
    # Android integration
    vpn_service_enabled: bool = True
    notification_enabled: bool = True
    battery_optimization_enabled: bool = True


class Config:
    """Main configuration class"""
    def __init__(self):
        self.ml = MLConfig()
        self.threat_intel = ThreatIntelConfig()
        self.detection = DetectionConfig()
        self.filter = FilterConfig()
        self.system = SystemConfig()
    
    def validate(self) -> bool:
        """Validate configuration"""
        # Check API keys
        if not self.threat_intel.abuseipdb_api_key:
            print("WARNING: AbuseIPDB API key not set. Set ABUSEIPDB_API_KEY environment variable.")
        
        # Check model paths
        if not os.path.exists(os.path.dirname(self.ml.isolation_forest_model_path)):
            os.makedirs(os.path.dirname(self.ml.isolation_forest_model_path), exist_ok=True)
        
        # Check cache directory
        if self.threat_intel.enable_disk_cache:
            os.makedirs(self.threat_intel.cache_directory, exist_ok=True)
        
        # Check log directory
        os.makedirs(os.path.dirname(self.system.log_file), exist_ok=True)
        
        return True
    
    def to_dict(self) -> Dict:
        """Export configuration as dictionary"""
        return {
            'ml': self.ml.__dict__,
            'threat_intel': {
                k: v for k, v in self.threat_intel.__dict__.items() 
                if 'api_key' not in k  # Don't export API keys
            },
            'detection': self.detection.__dict__,
            'filter': self.filter.__dict__,
            'system': self.system.__dict__
        }


# Global configuration instance
config = Config()

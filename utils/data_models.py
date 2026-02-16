"""
Data models and schemas for Shakti X AI Firewall
Defines core data structures for network packets, traffic flows, threats, and features
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class Protocol(Enum):
    """Network protocol types"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class TrafficDirection(Enum):
    """Traffic direction"""
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BOTH = "BOTH"


class ThreatLevel(Enum):
    """Threat severity levels"""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class DNSQueryType(Enum):
    """DNS query types"""
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    PTR = "PTR"
    SOA = "SOA"
    OTHER = "OTHER"


@dataclass
class NetworkPacket:
    """Represents a single network packet"""
    timestamp: datetime
    app_package_name: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: Protocol
    direction: TrafficDirection
    payload_size: int
    payload_hash: Optional[str] = None
    domain: Optional[str] = None
    dns_query_type: Optional[DNSQueryType] = None
    tls_fingerprint: Optional[str] = None  # JA3 hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'app_package_name': self.app_package_name,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol.value,
            'direction': self.direction.value,
            'payload_size': self.payload_size,
            'payload_hash': self.payload_hash,
            'domain': self.domain,
            'dns_query_type': self.dns_query_type.value if self.dns_query_type else None,
            'tls_fingerprint': self.tls_fingerprint
        }


@dataclass
class TrafficFlow:
    """Represents aggregated traffic flow for an app"""
    app_package_name: str
    start_time: datetime
    end_time: datetime
    
    # Packet counts
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    
    # Byte counts
    total_bytes: int = 0
    inbound_bytes: int = 0
    outbound_bytes: int = 0
    
    # Connection stats
    unique_destinations: set = field(default_factory=set)
    unique_ports: set = field(default_factory=set)
    dns_queries: int = 0
    failed_connections: int = 0
    
    # Behavioral metrics
    background_packets: int = 0  # Packets when app in background
    foreground_packets: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        duration = (self.end_time - self.start_time).total_seconds()
        
        return {
            'app_package_name': self.app_package_name,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_seconds': duration,
            'total_packets': self.total_packets,
            'tcp_packets': self.tcp_packets,
            'udp_packets': self.udp_packets,
            'icmp_packets': self.icmp_packets,
            'total_bytes': self.total_bytes,
            'inbound_bytes': self.inbound_bytes,
            'outbound_bytes': self.outbound_bytes,
            'unique_destinations': len(self.unique_destinations),
            'unique_ports': len(self.unique_ports),
            'dns_queries': self.dns_queries,
            'failed_connections': self.failed_connections,
            'background_packets': self.background_packets,
            'foreground_packets': self.foreground_packets
        }


@dataclass
class TrafficFeatures:
    """
    Feature vector for ML models
    Contains all 20+ features for anomaly detection
    """
    app_package_name: str
    timestamp: datetime
    
    # Rate-based features
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    dns_queries_per_min: float = 0.0
    unique_destinations_per_min: float = 0.0
    tcp_syn_rate: float = 0.0
    error_rate: float = 0.0
    
    # Behavioral features
    background_ratio: float = 0.0  # Ratio of background to total traffic
    session_duration: float = 0.0  # Average session duration in seconds
    burstiness: float = 0.0  # Variance in packet timing
    
    # Protocol distribution
    tcp_ratio: float = 0.0
    udp_ratio: float = 0.0
    icmp_ratio: float = 0.0
    
    # Port distribution features
    port_entropy: float = 0.0  # Shannon entropy of port distribution
    high_port_ratio: float = 0.0  # Ratio of high ports (>1024)
    
    # Data transfer patterns
    upload_download_ratio: float = 0.0
    avg_packet_size: float = 0.0
    data_size_variance: float = 0.0
    
    # DNS features
    dns_txt_queries: int = 0  # Suspicious for C2 communication
    dns_failure_rate: float = 0.0
    
    # Connection patterns
    new_destination_rate: float = 0.0  # Rate of connecting to new IPs
    connection_failure_rate: float = 0.0
    
    def to_array(self) -> List[float]:
        """Convert to numpy-compatible array for ML models"""
        return [
            self.packets_per_sec,
            self.bytes_per_sec,
            self.dns_queries_per_min,
            self.unique_destinations_per_min,
            self.tcp_syn_rate,
            self.error_rate,
            self.background_ratio,
            self.session_duration,
            self.burstiness,
            self.tcp_ratio,
            self.udp_ratio,
            self.icmp_ratio,
            self.port_entropy,
            self.high_port_ratio,
            self.upload_download_ratio,
            self.avg_packet_size,
            self.data_size_variance,
            float(self.dns_txt_queries),
            self.dns_failure_rate,
            self.new_destination_rate,
            self.connection_failure_rate
        ]
    
    @staticmethod
    def feature_names() -> List[str]:
        """Get feature names for model interpretation"""
        return [
            'packets_per_sec', 'bytes_per_sec', 'dns_queries_per_min',
            'unique_destinations_per_min', 'tcp_syn_rate', 'error_rate',
            'background_ratio', 'session_duration', 'burstiness',
            'tcp_ratio', 'udp_ratio', 'icmp_ratio',
            'port_entropy', 'high_port_ratio', 'upload_download_ratio',
            'avg_packet_size', 'data_size_variance', 'dns_txt_queries',
            'dns_failure_rate', 'new_destination_rate', 'connection_failure_rate'
        ]


@dataclass
class ThreatAlert:
    """Represents a security threat alert"""
    alert_id: str
    timestamp: datetime
    app_package_name: str
    threat_level: ThreatLevel
    threat_type: str  # e.g., "DDoS", "Data Exfiltration", "Malicious Domain"
    threat_score: float  # 0-100
    description: str
    
    # Evidence
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    domain: Optional[str] = None
    blocked: bool = False
    
    # ML model info
    model_confidence: float = 0.0
    anomaly_score: float = 0.0
    
    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat(),
            'app_package_name': self.app_package_name,
            'threat_level': self.threat_level.name,
            'threat_type': self.threat_type,
            'threat_score': self.threat_score,
            'description': self.description,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'domain': self.domain,
            'blocked': self.blocked,
            'model_confidence': self.model_confidence,
            'anomaly_score': self.anomaly_score,
            'metadata': self.metadata
        }


@dataclass
class AppBehavior:
    """Tracks behavioral profile for an app"""
    app_package_name: str
    is_system_app: bool
    first_seen: datetime
    last_seen: datetime
    
    # Baseline metrics (learned over time)
    baseline_pps: float = 0.0  # Normal packets per second
    baseline_bps: float = 0.0  # Normal bytes per second
    baseline_destinations: int = 0  # Normal number of destinations
    
    # Known destinations (whitelist)
    known_destinations: set = field(default_factory=set)
    
    # Permissions
    has_internet_permission: bool = True
    has_network_state_permission: bool = True
    
    # Behavioral flags
    sudden_traffic_spike: bool = False
    new_destination_detected: bool = False
    permission_violation: bool = False
    
    # Historical stats
    total_sessions: int = 0
    total_data_transferred: int = 0
    avg_session_duration: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'app_package_name': self.app_package_name,
            'is_system_app': self.is_system_app,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'baseline_pps': self.baseline_pps,
            'baseline_bps': self.baseline_bps,
            'baseline_destinations': self.baseline_destinations,
            'known_destinations_count': len(self.known_destinations),
            'has_internet_permission': self.has_internet_permission,
            'has_network_state_permission': self.has_network_state_permission,
            'sudden_traffic_spike': self.sudden_traffic_spike,
            'new_destination_detected': self.new_destination_detected,
            'permission_violation': self.permission_violation,
            'total_sessions': self.total_sessions,
            'total_data_transferred': self.total_data_transferred,
            'avg_session_duration': self.avg_session_duration
        }


@dataclass
class ThreatIntelligenceResult:
    """Result from threat intelligence lookup"""
    ip_or_domain: str
    is_malicious: bool
    threat_score: float  # 0-100
    sources: List[str]  # Which APIs flagged it
    categories: List[str]  # e.g., ["malware", "botnet", "phishing"]
    last_seen: Optional[datetime] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    cached: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'ip_or_domain': self.ip_or_domain,
            'is_malicious': self.is_malicious,
            'threat_score': self.threat_score,
            'sources': self.sources,
            'categories': self.categories,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'country': self.country,
            'asn': self.asn,
            'cached': self.cached
        }

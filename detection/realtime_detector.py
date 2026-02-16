"""
Real-time Threat Detection Engine
Detects DDoS, data exfiltration, VPN leakage, and other attack patterns in real-time
"""

from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import numpy as np

from utils.data_models import NetworkPacket, TrafficFeatures, ThreatAlert, ThreatLevel, Protocol
from config.config import config


class RealtimeDetector:
    """
    Real-time detection of specific attack patterns
    Complements ML-based anomaly detection with rule-based pattern matching
    """
    
    def __init__(self):
        self.config = config.detection
        
        # Per-app tracking for pattern detection
        self.app_tracking: Dict[str, Dict] = defaultdict(lambda: {
            'packet_timestamps': deque(maxlen=1000),
            'byte_counts': deque(maxlen=1000),
            'destinations': deque(maxlen=500),
            'ports_scanned': set(),
            'port_scan_start': None,
            'upload_bytes': 0,
            'download_bytes': 0,
            'last_upload_check': datetime.now(),
            'dns_queries': deque(maxlen=100),
            'failed_connections': deque(maxlen=100),
            'background_data_bytes': 0,
            'foreground_data_bytes': 0
        })
        
        # System-wide tracking
        self.vpn_interface_ips: set = set()
        self.detected_attacks: Dict[str, datetime] = {}  # Cooldown for repeated alerts
    
    def detect_ddos(self, app: str, features: TrafficFeatures) -> Tuple[bool, float, str]:
        """
        Detect DDoS attack patterns
        High packet rate + high connection rate
        """
        is_ddos = False
        score = 0.0
        details = ""
        
        # Check packet rate
        if features.packets_per_sec > self.config.max_packets_per_sec:
            score += 0.5
            details += f"High PPS: {features.packets_per_sec:.0f}. "
        
        # Check byte rate
        if features.bytes_per_sec > self.config.max_bytes_per_sec:
            score += 0.3
            details += f"High BPS: {features.bytes_per_sec:.0f}. "
        
        # Check unique destinations
        if features.unique_destinations_per_min > self.config.max_unique_destinations_per_min:
            score += 0.2
            details += f"Many destinations: {features.unique_destinations_per_min:.0f}/min. "
        
        is_ddos = score >= 0.7
        
        return is_ddos, score, details
    
    def detect_data_exfiltration(self, app: str, features: TrafficFeatures) -> Tuple[bool, float, str]:
        """
        Detect data exfiltration patterns
        High upload rate + suspicious upload/download ratio
        """
        tracking = self.app_tracking[app]
        is_exfiltration = False
        score = 0.0
        details = ""
        
        # Check upload rate
        time_since_check = (datetime.now() - tracking['last_upload_check']).total_seconds()
        if time_since_check >= 60:  # Check every minute
            upload_rate = tracking['upload_bytes'] / time_since_check
            
            if upload_rate > self.config.max_upload_bytes_per_min / 60:
                score += 0.5
                details += f"High upload rate: {upload_rate:.0f} B/s. "
            
            # Reset counters
            tracking['upload_bytes'] = 0
            tracking['download_bytes'] = 0
            tracking['last_upload_check'] = datetime.now()
        
        # Check upload/download ratio
        if features.upload_download_ratio > self.config.suspicious_upload_ratio:
            score += 0.4
            details += f"Suspicious upload ratio: {features.upload_download_ratio:.1f}. "
        
        # Check if happening in background
        if features.background_ratio > 0.7:
            score += 0.1
            details += "Background upload. "
        
        is_exfiltration = score >= 0.6
        
        return is_exfiltration, score, details
    
    def detect_port_scanning(self, app: str, packet: NetworkPacket) -> Tuple[bool, float, str]:
        """
        Detect port scanning behavior
        Many unique ports in short time window
        """
        tracking = self.app_tracking[app]
        
        # Track port access
        tracking['ports_scanned'].add(packet.destination_port)
        
        # Start timer if not already started
        if not tracking['port_scan_start']:
            tracking['port_scan_start'] = packet.timestamp
        
        # Check if within time window
        time_elapsed = (packet.timestamp - tracking['port_scan_start']).total_seconds()
        
        if time_elapsed <= self.config.port_scan_time_window_sec:
            unique_ports = len(tracking['ports_scanned'])
            
            if unique_ports >= self.config.unique_ports_threshold:
                score = min(unique_ports / self.config.unique_ports_threshold, 1.0)
                details = f"Scanned {unique_ports} ports in {time_elapsed:.0f}s"
                return True, score, details
        else:
            # Reset window
            tracking['ports_scanned'].clear()
            tracking['port_scan_start'] = packet.timestamp
        
        return False, 0.0, ""
    
    def detect_dns_tunneling(self, app: str, features: TrafficFeatures) -> Tuple[bool, float, str]:
        """
        Detect DNS tunneling (C2 communication via DNS)
        High DNS query rate + TXT queries + unusual patterns
        """
        is_tunneling = False
        score = 0.0
        details = ""
        
        # Check DNS query rate
        if features.dns_queries_per_min > self.config.max_dns_queries_per_min:
            score += 0.4
            details += f"High DNS rate: {features.dns_queries_per_min:.0f}/min. "
        
        # Check for TXT queries (common in DNS tunneling)
        if features.dns_txt_queries > self.config.max_dns_txt_queries_per_min:
            score += 0.5
            details += f"Suspicious TXT queries: {features.dns_txt_queries}. "
        
        # Check DNS failure rate
        if features.dns_failure_rate > self.config.dns_failure_rate_threshold:
            score += 0.1
            details += f"High DNS failure rate: {features.dns_failure_rate:.1%}. "
        
        is_tunneling = score >= 0.6
        
        return is_tunneling, score, details
    
    def detect_vpn_leakage(self, packet: NetworkPacket) -> Tuple[bool, float, str]:
        """
        Detect VPN tunnel leakage
        Traffic bypassing VPN when VPN is supposed to be active
        """
        # This would require integration with Android VPN service
        # to know which interface is VPN and detect bypass
        
        # Placeholder implementation
        # In production, would check if packet went through VPN interface
        
        return False, 0.0, ""
    
    def detect_battery_abuse(self, app: str, features: TrafficFeatures) -> Tuple[bool, float, str]:
        """
        Detect apps abusing battery via excessive background network activity
        """
        is_abuse = False
        score = 0.0
        details = ""
        
        # High background traffic ratio
        if features.background_ratio > self.config.background_traffic_threshold:
            score += 0.5
            details += f"High background traffic: {features.background_ratio:.1%}. "
        
        # High data rate in background
        if features.background_ratio > 0.5 and features.bytes_per_sec > 1_000_000:  # 1 MB/s
            score += 0.3
            details += f"High background data rate: {features.bytes_per_sec:.0f} B/s. "
        
        # Continuous activity
        if features.session_duration > 3600:  # 1 hour
            score += 0.2
            details += f"Long session: {features.session_duration/3600:.1f}h. "
        
        is_abuse = score >= 0.6
        
        return is_abuse, score, details
    
    def detect_mitm_attempt(self, packet: NetworkPacket) -> Tuple[bool, float, str]:
        """
        Detect Man-in-the-Middle attack attempts
        Certificate pinning failures, unusual TLS fingerprints
        """
        # This would require TLS inspection capabilities
        # Placeholder for now
        
        if packet.tls_fingerprint:
            # Would check against known good fingerprints
            # or detect anomalous handshakes
            pass
        
        return False, 0.0, ""
    
    def update_tracking(self, packet: NetworkPacket, is_foreground: bool):
        """Update tracking data for pattern detection"""
        app = packet.app_package_name
        tracking = self.app_tracking[app]
        
        # Update timestamps
        tracking['packet_timestamps'].append(packet.timestamp)
        tracking['byte_counts'].append(packet.payload_size)
        
        # Update destinations
        tracking['destinations'].append(packet.destination_ip)
        
        # Update upload/download bytes
        if packet.direction.name == 'OUTBOUND':
            tracking['upload_bytes'] += packet.payload_size
        else:
            tracking['download_bytes'] += packet.payload_size
        
        # Update background/foreground data
        if is_foreground:
            tracking['foreground_data_bytes'] += packet.payload_size
        else:
            tracking['background_data_bytes'] += packet.payload_size
        
        # Track DNS queries
        if packet.dns_query_type:
            tracking['dns_queries'].append({
                'timestamp': packet.timestamp,
                'type': packet.dns_query_type,
                'domain': packet.domain
            })
    
    def run_all_detectors(
        self, 
        app: str, 
        packet: NetworkPacket, 
        features: TrafficFeatures,
        is_foreground: bool
    ) -> List[Tuple[str, bool, float, str]]:
        """
        Run all real-time detectors
        Returns list of (detector_name, is_detected, score, details)
        """
        # Update tracking first
        self.update_tracking(packet, is_foreground)
        
        results = []
        
        # DDoS detection
        is_ddos, ddos_score, ddos_details = self.detect_ddos(app, features)
        if is_ddos:
            results.append(('DDoS', is_ddos, ddos_score, ddos_details))
        
        # Data exfiltration
        is_exfil, exfil_score, exfil_details = self.detect_data_exfiltration(app, features)
        if is_exfil:
            results.append(('Data Exfiltration', is_exfil, exfil_score, exfil_details))
        
        # Port scanning
        is_scan, scan_score, scan_details = self.detect_port_scanning(app, packet)
        if is_scan:
            results.append(('Port Scanning', is_scan, scan_score, scan_details))
        
        # DNS tunneling
        is_tunnel, tunnel_score, tunnel_details = self.detect_dns_tunneling(app, features)
        if is_tunnel:
            results.append(('DNS Tunneling', is_tunnel, tunnel_score, tunnel_details))
        
        # Battery abuse
        is_abuse, abuse_score, abuse_details = self.detect_battery_abuse(app, features)
        if is_abuse:
            results.append(('Battery Abuse', is_abuse, abuse_score, abuse_details))
        
        # VPN leakage
        is_leak, leak_score, leak_details = self.detect_vpn_leakage(packet)
        if is_leak:
            results.append(('VPN Leakage', is_leak, leak_score, leak_details))
        
        # MITM attempt
        is_mitm, mitm_score, mitm_details = self.detect_mitm_attempt(packet)
        if is_mitm:
            results.append(('MITM Attempt', is_mitm, mitm_score, mitm_details))
        
        return results
    
    def cleanup_old_data(self, max_age_hours: int = 24):
        """Remove old tracking data"""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        
        for app, tracking in list(self.app_tracking.items()):
            # Remove old timestamps
            while tracking['packet_timestamps'] and tracking['packet_timestamps'][0] < cutoff:
                tracking['packet_timestamps'].popleft()
            
            # If no recent activity, remove app
            if not tracking['packet_timestamps']:
                del self.app_tracking[app]

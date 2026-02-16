"""
Traffic Analyzer - Real-time traffic analysis and feature extraction
Computes all 20+ features for ML-based anomaly detection
"""

import time
import math
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import numpy as np

from utils.data_models import (
    NetworkPacket, TrafficFlow, TrafficFeatures, 
    Protocol, TrafficDirection, DNSQueryType
)
from config.config import config


class TrafficAnalyzer:
    """
    Analyzes network traffic and extracts features for ML models
    Maintains time-windowed statistics per app
    """
    
    def __init__(self, window_size_seconds: int = 60):
        self.window_size = window_size_seconds
        
        # Per-app traffic flows
        self.flows: Dict[str, TrafficFlow] = {}
        
        # Time-windowed packet storage (for feature computation)
        self.packet_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Per-app metrics tracking
        self.app_metrics: Dict[str, Dict] = defaultdict(lambda: {
            'packet_timestamps': deque(maxlen=1000),
            'byte_counts': deque(maxlen=1000),
            'dns_queries': deque(maxlen=100),
            'destinations': set(),
            'ports': set(),
            'syn_packets': 0,
            'failed_connections': 0,
            'background_packets': 0,
            'foreground_packets': 0,
            'session_start_times': deque(maxlen=100),
            'session_end_times': deque(maxlen=100),
        })
        
        # App foreground state (updated by Android)
        self.app_foreground_state: Dict[str, bool] = {}
    
    def process_packet(self, packet: NetworkPacket, is_foreground: bool = True) -> TrafficFeatures:
        """
        Process a single packet and update metrics
        Returns current feature vector for the app
        """
        app = packet.app_package_name
        now = packet.timestamp
        
        # Update foreground state
        self.app_foreground_state[app] = is_foreground
        
        # Initialize or update flow
        if app not in self.flows:
            self.flows[app] = TrafficFlow(
                app_package_name=app,
                start_time=now,
                end_time=now
            )
        
        flow = self.flows[app]
        flow.end_time = now
        
        # Update packet counts
        flow.total_packets += 1
        if packet.protocol == Protocol.TCP:
            flow.tcp_packets += 1
        elif packet.protocol == Protocol.UDP:
            flow.udp_packets += 1
        elif packet.protocol == Protocol.ICMP:
            flow.icmp_packets += 1
        
        # Update byte counts
        flow.total_bytes += packet.payload_size
        if packet.direction == TrafficDirection.INBOUND:
            flow.inbound_bytes += packet.payload_size
        else:
            flow.outbound_bytes += packet.payload_size
        
        # Track destinations and ports
        flow.unique_destinations.add(packet.destination_ip)
        flow.unique_ports.add(packet.destination_port)
        
        # DNS queries
        if packet.dns_query_type:
            flow.dns_queries += 1
            self.app_metrics[app]['dns_queries'].append({
                'timestamp': now,
                'type': packet.dns_query_type,
                'domain': packet.domain
            })
        
        # Background/foreground tracking
        if is_foreground:
            flow.foreground_packets += 1
        else:
            flow.background_packets += 1
        
        # Store packet for windowed analysis
        self.packet_windows[app].append(packet)
        
        # Update metrics
        metrics = self.app_metrics[app]
        metrics['packet_timestamps'].append(now)
        metrics['byte_counts'].append(packet.payload_size)
        metrics['destinations'].add(packet.destination_ip)
        metrics['ports'].add(packet.destination_port)
        
        # Extract features
        features = self._extract_features(app, now)
        
        return features
    
    def _extract_features(self, app: str, current_time: datetime) -> TrafficFeatures:
        """
        Extract all 20+ features for ML model
        """
        flow = self.flows.get(app)
        metrics = self.app_metrics[app]
        
        if not flow:
            return TrafficFeatures(app_package_name=app, timestamp=current_time)
        
        # Time window for rate calculations
        window_start = current_time - timedelta(seconds=self.window_size)
        
        # Filter packets in current window
        recent_packets = [
            p for p in self.packet_windows[app]
            if p.timestamp >= window_start
        ]
        
        if not recent_packets:
            return TrafficFeatures(app_package_name=app, timestamp=current_time)
        
        # Calculate duration
        duration = (current_time - flow.start_time).total_seconds()
        if duration == 0:
            duration = 1
        
        window_duration = min(duration, self.window_size)
        
        # 1. Packets per second
        packets_per_sec = len(recent_packets) / window_duration
        
        # 2. Bytes per second
        recent_bytes = sum(p.payload_size for p in recent_packets)
        bytes_per_sec = recent_bytes / window_duration
        
        # 3. DNS queries per minute
        recent_dns = [
            q for q in metrics['dns_queries']
            if q['timestamp'] >= window_start
        ]
        dns_queries_per_min = len(recent_dns) * (60 / window_duration)
        
        # 4. Unique destinations per minute
        recent_destinations = set(p.destination_ip for p in recent_packets)
        unique_destinations_per_min = len(recent_destinations) * (60 / window_duration)
        
        # 5. TCP SYN rate (approximation - would need actual SYN flag from packet)
        tcp_packets = [p for p in recent_packets if p.protocol == Protocol.TCP]
        tcp_syn_rate = len(tcp_packets) / window_duration if tcp_packets else 0
        
        # 6. Error rate (failed connections / total attempts)
        error_rate = (
            metrics['failed_connections'] / flow.total_packets 
            if flow.total_packets > 0 else 0
        )
        
        # 7. Background ratio
        total_packets = flow.background_packets + flow.foreground_packets
        background_ratio = (
            flow.background_packets / total_packets 
            if total_packets > 0 else 0
        )
        
        # 8. Session duration (average)
        session_duration = self._calculate_avg_session_duration(metrics)
        
        # 9. Burstiness (variance in packet timing)
        burstiness = self._calculate_burstiness(recent_packets)
        
        # 10-12. Protocol ratios
        total = flow.total_packets
        tcp_ratio = flow.tcp_packets / total if total > 0 else 0
        udp_ratio = flow.udp_packets / total if total > 0 else 0
        icmp_ratio = flow.icmp_packets / total if total > 0 else 0
        
        # 13. Port entropy (Shannon entropy)
        port_entropy = self._calculate_entropy(
            [p.destination_port for p in recent_packets]
        )
        
        # 14. High port ratio
        high_ports = sum(1 for p in recent_packets if p.destination_port > 1024)
        high_port_ratio = high_ports / len(recent_packets)
        
        # 15. Upload/download ratio
        upload_download_ratio = (
            flow.outbound_bytes / flow.inbound_bytes 
            if flow.inbound_bytes > 0 else 0
        )
        
        # 16. Average packet size
        avg_packet_size = flow.total_bytes / flow.total_packets
        
        # 17. Data size variance
        packet_sizes = [p.payload_size for p in recent_packets]
        data_size_variance = np.var(packet_sizes) if len(packet_sizes) > 1 else 0
        
        # 18. DNS TXT queries (suspicious for C2)
        dns_txt_queries = sum(
            1 for q in recent_dns 
            if q['type'] == DNSQueryType.TXT
        )
        
        # 19. DNS failure rate
        dns_failure_rate = 0.0  # Would need DNS response codes
        
        # 20. New destination rate
        new_destination_rate = self._calculate_new_destination_rate(
            app, recent_destinations, window_duration
        )
        
        # 21. Connection failure rate
        connection_failure_rate = error_rate  # Same as error_rate
        
        return TrafficFeatures(
            app_package_name=app,
            timestamp=current_time,
            packets_per_sec=packets_per_sec,
            bytes_per_sec=bytes_per_sec,
            dns_queries_per_min=dns_queries_per_min,
            unique_destinations_per_min=unique_destinations_per_min,
            tcp_syn_rate=tcp_syn_rate,
            error_rate=error_rate,
            background_ratio=background_ratio,
            session_duration=session_duration,
            burstiness=burstiness,
            tcp_ratio=tcp_ratio,
            udp_ratio=udp_ratio,
            icmp_ratio=icmp_ratio,
            port_entropy=port_entropy,
            high_port_ratio=high_port_ratio,
            upload_download_ratio=upload_download_ratio,
            avg_packet_size=avg_packet_size,
            data_size_variance=data_size_variance,
            dns_txt_queries=dns_txt_queries,
            dns_failure_rate=dns_failure_rate,
            new_destination_rate=new_destination_rate,
            connection_failure_rate=connection_failure_rate
        )
    
    def _calculate_avg_session_duration(self, metrics: Dict) -> float:
        """Calculate average session duration"""
        starts = metrics['session_start_times']
        ends = metrics['session_end_times']
        
        if not starts or not ends:
            return 0.0
        
        durations = [
            (end - start).total_seconds()
            for start, end in zip(starts, ends)
            if end > start
        ]
        
        return np.mean(durations) if durations else 0.0
    
    def _calculate_burstiness(self, packets: List[NetworkPacket]) -> float:
        """
        Calculate burstiness (variance in inter-packet arrival times)
        Higher = more bursty traffic
        """
        if len(packets) < 2:
            return 0.0
        
        timestamps = [p.timestamp.timestamp() for p in packets]
        timestamps.sort()
        
        inter_arrival_times = [
            timestamps[i+1] - timestamps[i]
            for i in range(len(timestamps) - 1)
        ]
        
        if not inter_arrival_times:
            return 0.0
        
        mean_iat = np.mean(inter_arrival_times)
        var_iat = np.var(inter_arrival_times)
        
        # Coefficient of variation
        if mean_iat > 0:
            return var_iat / mean_iat
        return 0.0
    
    def _calculate_entropy(self, values: List[int]) -> float:
        """Calculate Shannon entropy of a distribution"""
        if not values:
            return 0.0
        
        # Count frequencies
        freq = defaultdict(int)
        for v in values:
            freq[v] += 1
        
        total = len(values)
        entropy = 0.0
        
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_new_destination_rate(
        self, 
        app: str, 
        recent_destinations: set, 
        window_duration: float
    ) -> float:
        """Calculate rate of new destination IPs"""
        # Get historical destinations
        all_destinations = self.app_metrics[app]['destinations']
        
        # Find new destinations
        new_destinations = recent_destinations - all_destinations
        
        # Update historical set
        all_destinations.update(recent_destinations)
        
        # Calculate rate
        return len(new_destinations) * (60 / window_duration)
    
    def get_flow(self, app: str) -> Optional[TrafficFlow]:
        """Get current traffic flow for an app"""
        return self.flows.get(app)
    
    def get_all_flows(self) -> Dict[str, TrafficFlow]:
        """Get all active traffic flows"""
        return self.flows.copy()
    
    def reset_flow(self, app: str):
        """Reset flow for an app (e.g., after session ends)"""
        if app in self.flows:
            del self.flows[app]
        if app in self.packet_windows:
            self.packet_windows[app].clear()
    
    def cleanup_old_data(self, max_age_hours: int = 24):
        """Remove old data to prevent memory bloat"""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        
        apps_to_remove = []
        for app, flow in self.flows.items():
            if flow.end_time < cutoff:
                apps_to_remove.append(app)
        
        for app in apps_to_remove:
            self.reset_flow(app)

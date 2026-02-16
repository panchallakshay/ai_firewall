"""
Shakti X AI Core - Main AI Engine
Orchestrates all ML-based threat detection components
"""

import uuid
from typing import List, Tuple, Optional
from datetime import datetime

from utils.data_models import (
    NetworkPacket, TrafficFeatures, ThreatAlert, 
    ThreatLevel, AppBehavior
)
from ml_engine.traffic_analyzer import TrafficAnalyzer
from ml_engine.anomaly_models import AnomalyDetector
from ml_engine.threat_intelligence import ThreatIntelligence
from ml_engine.continuous_learner import ContinuousLearner
from config.config import config


class ShaktiXAICore:
    """
    Main AI engine that coordinates all threat detection components
    """
    
    def __init__(self):
        print("🔥 Initializing Shakti X AI Firewall Core...")
        
        # Initialize components
        self.traffic_analyzer = TrafficAnalyzer(
            window_size_seconds=config.ml.time_window_seconds
        )
        self.anomaly_detector = AnomalyDetector()
        self.threat_intel = ThreatIntelligence()
        self.continuous_learner = ContinuousLearner()
        
        # Alert history
        self.alerts: List[ThreatAlert] = []
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'threats_blocked': 0,
            'anomalies_detected': 0,
            'false_positives': 0
        }
        
        print("✓ Shakti X AI Core initialized successfully")
    
    def process_packet(
        self, 
        packet: NetworkPacket, 
        is_foreground: bool = True,
        is_system_app: bool = False
    ) -> Tuple[bool, Optional[ThreatAlert]]:
        """
        Process a single network packet through the AI pipeline
        
        Returns:
            - should_block: bool
            - alert: Optional[ThreatAlert]
        """
        self.stats['packets_processed'] += 1
        
        # Step 1: Extract features from traffic
        features = self.traffic_analyzer.process_packet(packet, is_foreground)
        
        # Step 2: Learn baseline behavior (continuous learning)
        self.continuous_learner.learn_baseline(
            packet.app_package_name, 
            features, 
            is_system_app
        )
        
        # Step 3: Multi-layer threat detection
        threat_score = 0.0
        threat_indicators = []
        should_block = False
        
        # Layer 1: Anomaly Detection (ML-based)
        is_anomaly, anomaly_score, anomaly_details = self.anomaly_detector.detect_anomaly(features)
        
        if is_anomaly:
            self.stats['anomalies_detected'] += 1
            threat_score += anomaly_score * 40  # Max 40 points from anomaly
            threat_indicators.append(f"ML Anomaly (score: {anomaly_score:.2f})")
        
        # Layer 2: Behavioral Deviation Detection
        is_deviation, deviation_score, deviation_reason = self.continuous_learner.detect_deviation(
            packet.app_package_name, 
            features
        )
        
        if is_deviation:
            threat_score += deviation_score * 30  # Max 30 points from deviation
            threat_indicators.append(f"Behavioral Deviation ({deviation_reason})")
        
        # Layer 3: Threat Intelligence Lookup
        if packet.destination_ip or packet.domain:
            target = packet.domain if packet.domain else packet.destination_ip
            threat_intel_result = self.threat_intel.check_threat(target)
            
            if threat_intel_result.is_malicious:
                threat_score += threat_intel_result.threat_score * 0.3  # Max 30 points
                threat_indicators.append(
                    f"Malicious Destination ({', '.join(threat_intel_result.sources)})"
                )
                # Always block known malicious destinations
                should_block = True
        
        # Determine threat level and blocking decision
        if threat_score >= config.detection.high_threshold or should_block:
            threat_level = ThreatLevel.CRITICAL if threat_score >= 90 else ThreatLevel.HIGH
            should_block = True
        elif threat_score >= config.detection.medium_threshold:
            threat_level = ThreatLevel.MEDIUM
            should_block = False  # Log but don't block
        elif threat_score >= config.detection.low_threshold:
            threat_level = ThreatLevel.LOW
            should_block = False
        else:
            # No significant threat
            return False, None
        
        # Create threat alert
        alert = self._create_alert(
            packet=packet,
            threat_level=threat_level,
            threat_score=threat_score,
            threat_indicators=threat_indicators,
            anomaly_score=anomaly_score,
            anomaly_details=anomaly_details,
            should_block=should_block
        )
        
        # Store alert
        self.alerts.append(alert)
        self.stats['threats_detected'] += 1
        
        if should_block:
            self.stats['threats_blocked'] += 1
        
        return should_block, alert
    
    def _create_alert(
        self,
        packet: NetworkPacket,
        threat_level: ThreatLevel,
        threat_score: float,
        threat_indicators: List[str],
        anomaly_score: float,
        anomaly_details: dict,
        should_block: bool
    ) -> ThreatAlert:
        """Create a threat alert from detection results"""
        
        # Determine threat type
        threat_type = self._classify_threat_type(threat_indicators, anomaly_details)
        
        # Generate description
        description = f"{threat_type} detected from {packet.app_package_name}. "
        description += "Indicators: " + ", ".join(threat_indicators)
        
        alert = ThreatAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=packet.timestamp,
            app_package_name=packet.app_package_name,
            threat_level=threat_level,
            threat_type=threat_type,
            threat_score=threat_score,
            description=description,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            domain=packet.domain,
            blocked=should_block,
            model_confidence=anomaly_score,
            anomaly_score=anomaly_score,
            metadata={
                'protocol': packet.protocol.value,
                'direction': packet.direction.value,
                'port': packet.destination_port,
                'anomaly_details': anomaly_details
            }
        )
        
        return alert
    
    def _classify_threat_type(self, indicators: List[str], anomaly_details: dict) -> str:
        """Classify the type of threat based on indicators"""
        
        # Check for specific attack patterns
        if 'high_pps' in anomaly_details or 'high_bps' in anomaly_details:
            return "DDoS Attack"
        
        if 'high_upload_ratio' in anomaly_details:
            return "Data Exfiltration"
        
        if 'suspicious_dns_txt' in anomaly_details:
            return "C2 Communication"
        
        if 'many_destinations' in anomaly_details:
            return "Port Scanning"
        
        if any('Malicious Destination' in ind for ind in indicators):
            return "Malware Communication"
        
        if 'high_background_traffic' in anomaly_details:
            return "Background Data Abuse"
        
        return "Suspicious Activity"
    
    def get_app_statistics(self, app: str) -> dict:
        """Get real-time statistics for a specific app"""
        flow = self.traffic_analyzer.get_flow(app)
        baseline = self.continuous_learner.get_app_profile(app)
        
        stats = {
            'app_package_name': app,
            'flow': flow.to_dict() if flow else None,
            'baseline': baseline.to_dict() if baseline else None,
            'recent_alerts': [
                alert.to_dict() for alert in self.alerts
                if alert.app_package_name == app
            ][-10:]  # Last 10 alerts
        }
        
        return stats
    
    def get_all_statistics(self) -> dict:
        """Get system-wide statistics"""
        flows = self.traffic_analyzer.get_all_flows()
        
        return {
            'system_stats': self.stats,
            'active_apps': len(flows),
            'total_alerts': len(self.alerts),
            'recent_alerts': [alert.to_dict() for alert in self.alerts[-20:]],
            'per_app_flows': {
                app: flow.to_dict() 
                for app, flow in flows.items()
            }
        }
    
    def get_dashboard_data(self) -> dict:
        """
        Get comprehensive data for Android dashboard
        Includes all 20+ features for each active app
        """
        flows = self.traffic_analyzer.get_all_flows()
        dashboard_data = {}
        
        for app, flow in flows.items():
            # Get latest features
            features = self.traffic_analyzer._extract_features(app, datetime.now())
            baseline = self.continuous_learner.get_app_profile(app)
            
            # Get recent alerts
            app_alerts = [
                alert for alert in self.alerts[-50:]
                if alert.app_package_name == app
            ]
            
            dashboard_data[app] = {
                # Real-time features (all 20+)
                'features': {
                    'packets_per_sec': features.packets_per_sec,
                    'bytes_per_sec': features.bytes_per_sec,
                    'dns_queries_per_min': features.dns_queries_per_min,
                    'unique_destinations_per_min': features.unique_destinations_per_min,
                    'tcp_syn_rate': features.tcp_syn_rate,
                    'error_rate': features.error_rate,
                    'background_ratio': features.background_ratio,
                    'session_duration': features.session_duration,
                    'burstiness': features.burstiness,
                    'tcp_ratio': features.tcp_ratio,
                    'udp_ratio': features.udp_ratio,
                    'icmp_ratio': features.icmp_ratio,
                    'port_entropy': features.port_entropy,
                    'high_port_ratio': features.high_port_ratio,
                    'upload_download_ratio': features.upload_download_ratio,
                    'avg_packet_size': features.avg_packet_size,
                    'data_size_variance': features.data_size_variance,
                    'dns_txt_queries': features.dns_txt_queries,
                    'dns_failure_rate': features.dns_failure_rate,
                    'new_destination_rate': features.new_destination_rate,
                    'connection_failure_rate': features.connection_failure_rate
                },
                
                # Traffic flow summary
                'flow': flow.to_dict(),
                
                # Behavioral baseline
                'baseline': baseline.to_dict() if baseline else None,
                
                # Alerts
                'alert_count': len(app_alerts),
                'highest_threat_level': max(
                    [alert.threat_level.value for alert in app_alerts],
                    default=0
                ),
                'latest_alert': app_alerts[-1].to_dict() if app_alerts else None
            }
        
        return dashboard_data
    
    def record_user_feedback(self, alert_id: str, was_false_positive: bool):
        """Record user feedback on an alert"""
        # Find the alert
        alert = next((a for a in self.alerts if a.alert_id == alert_id), None)
        
        if not alert:
            return
        
        if was_false_positive:
            self.stats['false_positives'] += 1
        
        # Get features for this alert (would need to store with alert)
        # For now, placeholder
        # self.continuous_learner.record_feedback(features, was_false_positive)
    
    def train_models(self, training_data: List[TrafficFeatures]):
        """Train/retrain anomaly detection models"""
        return self.anomaly_detector.train(training_data)
    
    def cleanup(self):
        """Cleanup old data to prevent memory bloat"""
        self.traffic_analyzer.cleanup_old_data(max_age_hours=24)
        
        # Keep only recent alerts
        max_alerts = config.system.max_alerts_stored
        if len(self.alerts) > max_alerts:
            self.alerts = self.alerts[-max_alerts:]

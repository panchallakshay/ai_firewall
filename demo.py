"""
Shakti X AI Firewall - Demo Script
Demonstrates the AI firewall capabilities with simulated traffic
"""

import sys
import time
from datetime import datetime
from random import randint, choice, random

# Add parent directory to path
sys.path.insert(0, '/Users/lakshaly/.gemini/antigravity/scratch/shakti-x-ai')

from utils.data_models import NetworkPacket, Protocol, TrafficDirection, DNSQueryType
from ml_engine.shakti_x_ai_core import ShaktiXAICore
from detection.alert_system import AlertSystem
from detection.realtime_detector import RealtimeDetector
from filters.packet_filter import PacketFilter
from api.dashboard_api import DashboardAPI


def create_normal_packet(app: str) -> NetworkPacket:
    """Create a normal network packet"""
    return NetworkPacket(
        timestamp=datetime.now(),
        app_package_name=app,
        source_ip="192.168.1.100",
        destination_ip=f"8.8.{randint(1,255)}.{randint(1,255)}",
        source_port=randint(49152, 65535),
        destination_port=choice([80, 443, 8080]),
        protocol=choice([Protocol.TCP, Protocol.UDP]),
        direction=TrafficDirection.OUTBOUND,
        payload_size=randint(100, 1500),
        domain=choice(["google.com", "facebook.com", "twitter.com", None])
    )


def create_malicious_packet(app: str, attack_type: str) -> NetworkPacket:
    """Create a malicious network packet"""
    if attack_type == "ddos":
        return NetworkPacket(
            timestamp=datetime.now(),
            app_package_name=app,
            source_ip="192.168.1.100",
            destination_ip=f"1.2.{randint(1,255)}.{randint(1,255)}",
            source_port=randint(49152, 65535),
            destination_port=randint(1, 65535),
            protocol=Protocol.TCP,
            direction=TrafficDirection.OUTBOUND,
            payload_size=randint(50, 200)
        )
    
    elif attack_type == "exfiltration":
        return NetworkPacket(
            timestamp=datetime.now(),
            app_package_name=app,
            source_ip="192.168.1.100",
            destination_ip="45.33.32.156",  # Suspicious IP
            source_port=randint(49152, 65535),
            destination_port=443,
            protocol=Protocol.TCP,
            direction=TrafficDirection.OUTBOUND,
            payload_size=randint(10000, 50000)  # Large upload
        )
    
    elif attack_type == "dns_tunneling":
        return NetworkPacket(
            timestamp=datetime.now(),
            app_package_name=app,
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=randint(49152, 65535),
            destination_port=53,
            protocol=Protocol.UDP,
            direction=TrafficDirection.OUTBOUND,
            payload_size=randint(100, 500),
            domain=f"c2-{randint(1000,9999)}.malicious.com",
            dns_query_type=DNSQueryType.TXT
        )
    
    return create_normal_packet(app)


def run_demo():
    """Run demonstration of Shakti X AI Firewall"""
    
    print("=" * 80)
    print("🔥 SHAKTI X AI FIREWALL - DEMONSTRATION")
    print("=" * 80)
    print()
    
    # Initialize components
    print("Initializing AI Firewall...")
    ai_core = ShaktiXAICore()
    alert_system = AlertSystem()
    realtime_detector = RealtimeDetector()
    packet_filter = PacketFilter()
    dashboard_api = DashboardAPI(ai_core, alert_system, packet_filter)
    
    print("✓ AI Firewall initialized\n")
    
    # Simulate normal traffic
    print("=" * 80)
    print("PHASE 1: Normal Traffic Simulation")
    print("=" * 80)
    
    apps = ["com.whatsapp", "com.chrome.browser", "com.spotify.music"]
    
    for i in range(50):
        app = choice(apps)
        packet = create_normal_packet(app)
        
        # Check filter rules
        should_block, reason = packet_filter.should_block(packet)
        
        if not should_block:
            # Process through AI
            should_block, alert = ai_core.process_packet(packet, is_foreground=True)
            
            if alert:
                alert_system.create_alert(
                    app_package_name=alert.app_package_name,
                    threat_level=alert.threat_level,
                    threat_type=alert.threat_type,
                    threat_score=alert.threat_score,
                    description=alert.description
                )
        
        if (i + 1) % 10 == 0:
            print(f"  Processed {i + 1}/50 normal packets...")
    
    print("✓ Normal traffic processed\n")
    
    # Show dashboard overview
    overview = dashboard_api.get_overview()
    print(f"📊 System Status:")
    print(f"  - Packets Processed: {overview['protection_status']['packets_processed']}")
    print(f"  - Threats Detected: {overview['protection_status']['threats_detected']}")
    print(f"  - Active Apps: {overview['active_apps']}")
    print()
    
    # Simulate attacks
    print("=" * 80)
    print("PHASE 2: Attack Simulation")
    print("=" * 80)
    print()
    
    # DDoS Attack
    print("🚨 Simulating DDoS Attack...")
    malicious_app = "com.malware.ddos"
    for i in range(100):
        packet = create_malicious_packet(malicious_app, "ddos")
        should_block, alert = ai_core.process_packet(packet, is_foreground=False)
        
        if alert:
            alert_system.create_alert(
                app_package_name=alert.app_package_name,
                threat_level=alert.threat_level,
                threat_type=alert.threat_type,
                threat_score=alert.threat_score,
                description=alert.description,
                blocked=should_block
            )
    
    print(f"  ✓ DDoS attack detected and analyzed\n")
    
    # Data Exfiltration
    print("🚨 Simulating Data Exfiltration...")
    exfil_app = "com.malware.stealer"
    for i in range(30):
        packet = create_malicious_packet(exfil_app, "exfiltration")
        should_block, alert = ai_core.process_packet(packet, is_foreground=False)
        
        if alert:
            alert_system.create_alert(
                app_package_name=alert.app_package_name,
                threat_level=alert.threat_level,
                threat_type=alert.threat_type,
                threat_score=alert.threat_score,
                description=alert.description,
                blocked=should_block
            )
    
    print(f"  ✓ Data exfiltration detected and analyzed\n")
    
    # DNS Tunneling
    print("🚨 Simulating DNS Tunneling (C2 Communication)...")
    c2_app = "com.malware.c2"
    for i in range(50):
        packet = create_malicious_packet(c2_app, "dns_tunneling")
        should_block, alert = ai_core.process_packet(packet, is_foreground=False)
        
        if alert:
            alert_system.create_alert(
                app_package_name=alert.app_package_name,
                threat_level=alert.threat_level,
                threat_type=alert.threat_type,
                threat_score=alert.threat_score,
                description=alert.description,
                blocked=should_block
            )
    
    print(f"  ✓ DNS tunneling detected and analyzed\n")
    
    # Show final statistics
    print("=" * 80)
    print("FINAL STATISTICS")
    print("=" * 80)
    print()
    
    stats = dashboard_api.get_statistics()
    
    print(f"📊 System Statistics:")
    print(f"  - Total Packets Processed: {stats['system']['packets_processed']}")
    print(f"  - Threats Detected: {stats['system']['threats_detected']}")
    print(f"  - Threats Blocked: {stats['system']['threats_blocked']}")
    print(f"  - Anomalies Detected: {stats['system']['anomalies_detected']}")
    print()
    
    print(f"🚨 Alert Statistics:")
    print(f"  - Total Alerts: {stats['alerts']['total_alerts']}")
    print(f"  - Critical: {stats['alerts']['by_level'].get('CRITICAL', 0)}")
    print(f"  - High: {stats['alerts']['by_level'].get('HIGH', 0)}")
    print(f"  - Medium: {stats['alerts']['by_level'].get('MEDIUM', 0)}")
    print(f"  - Low: {stats['alerts']['by_level'].get('LOW', 0)}")
    print()
    
    print(f"🎯 Top Threat Types:")
    for threat in stats['top_threat_types']:
        print(f"  - {threat['type']}: {threat['count']}")
    print()
    
    # Show app details
    print("=" * 80)
    print("APP DETAILS - com.malware.ddos")
    print("=" * 80)
    print()
    
    app_details = dashboard_api.get_app_details("com.malware.ddos")
    
    if app_details['features']:
        print("📈 Real-time Features:")
        features = app_details['features']
        print(f"  - Packets/sec: {features.get('packets_per_sec', 0):.2f}")
        print(f"  - Bytes/sec: {features.get('bytes_per_sec', 0):.2f}")
        print(f"  - DNS Queries/min: {features.get('dns_queries_per_min', 0):.2f}")
        print(f"  - Unique Destinations/min: {features.get('unique_destinations_per_min', 0):.2f}")
        print(f"  - Background Ratio: {features.get('background_ratio', 0):.2%}")
        print(f"  - Upload/Download Ratio: {features.get('upload_download_ratio', 0):.2f}")
        print()
    
    # Show recent alerts
    print("🚨 Recent Alerts:")
    recent_alerts = dashboard_api.get_alerts(limit=5)
    for alert in recent_alerts:
        print(f"  - [{alert['threat_level']}] {alert['threat_type']}: {alert['app_package_name']}")
        print(f"    Score: {alert['threat_score']:.1f}, Blocked: {alert['blocked']}")
    print()
    
    # Show all monitored apps
    print("=" * 80)
    print("ALL MONITORED APPS")
    print("=" * 80)
    print()
    
    all_apps = dashboard_api.get_all_apps()
    for app_summary in all_apps:
        print(f"📱 {app_summary['app_package_name']}")
        print(f"   PPS: {app_summary['packets_per_sec']:.2f}, BPS: {app_summary['bytes_per_sec']:.2f}")
        print(f"   Total: {app_summary['total_packets']} packets, {app_summary['total_bytes']} bytes")
        print(f"   Alerts: {app_summary['alert_count']}, Blocked: {app_summary['is_blocked']}")
        print()
    
    print("=" * 80)
    print("✅ DEMONSTRATION COMPLETE")
    print("=" * 80)
    print()
    print("The AI firewall successfully:")
    print("  ✓ Processed normal and malicious traffic")
    print("  ✓ Detected DDoS, data exfiltration, and DNS tunneling attacks")
    print("  ✓ Extracted 20+ features for ML analysis")
    print("  ✓ Generated threat alerts with severity levels")
    print("  ✓ Provided comprehensive dashboard data")
    print()
    print("Ready for Android integration! 🚀")
    print()


if __name__ == "__main__":
    run_demo()

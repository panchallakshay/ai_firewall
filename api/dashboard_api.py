"""
Dashboard API - Provides data for Android app dashboard
Exposes all metrics, features, alerts, and statistics
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json

from ml_engine.shakti_x_ai_core import ShaktiXAICore
from detection.alert_system import AlertSystem
from filters.packet_filter import PacketFilter
from utils.data_models import ThreatLevel


class DashboardAPI:
    """
    API for Android dashboard to fetch real-time metrics and statistics
    """
    
    def __init__(self, ai_core: ShaktiXAICore, alert_system: AlertSystem, packet_filter: PacketFilter):
        self.ai_core = ai_core
        self.alert_system = alert_system
        self.packet_filter = packet_filter
    
    def get_overview(self) -> Dict:
        """
        Get system overview for dashboard home screen
        """
        stats = self.ai_core.get_all_statistics()
        alert_stats = self.alert_system.get_alert_statistics()
        
        # Get critical alerts count
        critical_alerts = len(self.alert_system.get_critical_alerts())
        
        # Get recent threat activity
        recent_threats = alert_stats.get('last_1h', 0)
        
        return {
            'status': 'active',
            'timestamp': datetime.now().isoformat(),
            'protection_status': {
                'enabled': True,
                'packets_processed': stats['system_stats']['packets_processed'],
                'threats_detected': stats['system_stats']['threats_detected'],
                'threats_blocked': stats['system_stats']['threats_blocked']
            },
            'alerts': {
                'critical': critical_alerts,
                'total_24h': alert_stats.get('last_24h', 0),
                'total_1h': recent_threats
            },
            'active_apps': stats['active_apps'],
            'threat_level': self._calculate_overall_threat_level(critical_alerts, recent_threats)
        }
    
    def get_app_details(self, app: str) -> Dict:
        """
        Get detailed metrics for a specific app
        Includes all 20+ features, flow stats, alerts, and baseline
        """
        app_stats = self.ai_core.get_app_statistics(app)
        app_alerts = self.alert_system.get_alerts_by_app(app)
        
        # Get current features from dashboard data
        dashboard_data = self.ai_core.get_dashboard_data()
        app_data = dashboard_data.get(app, {})
        
        return {
            'app_package_name': app,
            'timestamp': datetime.now().isoformat(),
            
            # Real-time features (all 20+)
            'features': app_data.get('features', {}),
            
            # Traffic flow
            'flow': app_stats.get('flow'),
            
            # Behavioral baseline
            'baseline': app_stats.get('baseline'),
            
            # Alerts
            'alerts': {
                'total': len(app_alerts),
                'recent': [a.to_dict() for a in app_alerts[-5:]],
                'by_level': self._count_alerts_by_level(app_alerts)
            },
            
            # Filtering status
            'filtering': {
                'is_blocked': app in self.packet_filter.blocked_apps,
                'is_whitelisted': app in self.packet_filter.allowed_apps,
                'has_custom_rules': app in self.packet_filter.app_rules
            }
        }
    
    def get_all_apps(self) -> List[Dict]:
        """
        Get summary of all monitored apps
        """
        dashboard_data = self.ai_core.get_dashboard_data()
        
        apps_summary = []
        for app, data in dashboard_data.items():
            apps_summary.append({
                'app_package_name': app,
                'packets_per_sec': data['features'].get('packets_per_sec', 0),
                'bytes_per_sec': data['features'].get('bytes_per_sec', 0),
                'total_packets': data['flow'].get('total_packets', 0),
                'total_bytes': data['flow'].get('total_bytes', 0),
                'alert_count': data.get('alert_count', 0),
                'highest_threat_level': data.get('highest_threat_level', 0),
                'is_blocked': app in self.packet_filter.blocked_apps
            })
        
        # Sort by activity (packets per second)
        apps_summary.sort(key=lambda x: x['packets_per_sec'], reverse=True)
        
        return apps_summary
    
    def get_real_time_features(self, app: str) -> Dict:
        """
        Get real-time feature values for an app
        Used for live charts/graphs in dashboard
        """
        dashboard_data = self.ai_core.get_dashboard_data()
        app_data = dashboard_data.get(app, {})
        
        return {
            'app': app,
            'timestamp': datetime.now().isoformat(),
            'features': app_data.get('features', {})
        }
    
    def get_alerts(
        self, 
        level: Optional[ThreatLevel] = None,
        app: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict]:
        """
        Get alerts with optional filtering
        """
        if app:
            alerts = self.alert_system.get_alerts_by_app(app, limit)
        elif level:
            alerts = self.alert_system.get_alerts_by_level(level, limit)
        else:
            alerts = self.alert_system.get_recent_alerts(limit)
        
        return [a.to_dict() for a in alerts]
    
    def get_alert_details(self, alert_id: str) -> Optional[Dict]:
        """Get detailed information about a specific alert"""
        alert = self.alert_system.get_alert(alert_id)
        
        if not alert:
            return None
        
        return {
            **alert.to_dict(),
            'notification': self.alert_system.format_notification(alert)
        }
    
    def get_statistics(self) -> Dict:
        """
        Get comprehensive statistics for analytics screen
        """
        system_stats = self.ai_core.get_all_statistics()
        alert_stats = self.alert_system.get_alert_statistics()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'system': system_stats['system_stats'],
            'alerts': alert_stats,
            'top_threat_types': self._get_top_threat_types(),
            'top_threat_apps': self._get_top_threat_apps(),
            'timeline': self._get_threat_timeline()
        }
    
    def get_filtering_rules(self) -> Dict:
        """Get current filtering rules"""
        return self.packet_filter.export_rules()
    
    def update_filtering_rules(self, rules: Dict) -> bool:
        """Update filtering rules"""
        try:
            self.packet_filter.import_rules(rules)
            return True
        except Exception as e:
            print(f"Failed to update rules: {e}")
            return False
    
    def block_app(self, app: str) -> bool:
        """Block an app"""
        self.packet_filter.block_app(app)
        return True
    
    def unblock_app(self, app: str) -> bool:
        """Unblock an app"""
        self.packet_filter.unblock_app(app)
        return True
    
    def block_domain(self, domain: str) -> bool:
        """Block a domain"""
        self.packet_filter.block_domain(domain)
        return True
    
    def report_false_positive(self, alert_id: str) -> bool:
        """Report an alert as false positive"""
        self.ai_core.record_user_feedback(alert_id, was_false_positive=True)
        return True
    
    def export_data(self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> str:
        """
        Export all data as JSON
        Useful for backup or analysis
        """
        alerts_json = self.alert_system.export_alerts(start_time, end_time)
        
        export = {
            'export_time': datetime.now().isoformat(),
            'system_stats': self.ai_core.get_all_statistics(),
            'alerts': json.loads(alerts_json),
            'filtering_rules': self.packet_filter.export_rules()
        }
        
        return json.dumps(export, indent=2)
    
    # Helper methods
    
    def _calculate_overall_threat_level(self, critical_count: int, recent_threats: int) -> str:
        """Calculate overall system threat level"""
        if critical_count > 0:
            return 'critical'
        elif recent_threats > 10:
            return 'high'
        elif recent_threats > 5:
            return 'medium'
        elif recent_threats > 0:
            return 'low'
        else:
            return 'safe'
    
    def _count_alerts_by_level(self, alerts: List) -> Dict[str, int]:
        """Count alerts by threat level"""
        counts = {level.name: 0 for level in ThreatLevel}
        
        for alert in alerts:
            counts[alert.threat_level.name] += 1
        
        return counts
    
    def _get_top_threat_types(self, limit: int = 5) -> List[Dict]:
        """Get most common threat types"""
        alert_stats = self.alert_system.get_alert_statistics()
        by_type = alert_stats.get('by_type', {})
        
        sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'type': threat_type, 'count': count}
            for threat_type, count in sorted_types[:limit]
        ]
    
    def _get_top_threat_apps(self, limit: int = 5) -> List[Dict]:
        """Get apps with most threats"""
        alert_stats = self.alert_system.get_alert_statistics()
        by_app = alert_stats.get('by_app', {})
        
        sorted_apps = sorted(by_app.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {'app': app, 'count': count}
            for app, count in sorted_apps[:limit]
        ]
    
    def _get_threat_timeline(self, hours: int = 24) -> List[Dict]:
        """Get threat timeline for last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_alerts = [
            a for a in self.alert_system.alerts
            if a.timestamp >= cutoff
        ]
        
        # Group by hour
        timeline = {}
        for alert in recent_alerts:
            hour = alert.timestamp.replace(minute=0, second=0, microsecond=0)
            hour_key = hour.isoformat()
            
            if hour_key not in timeline:
                timeline[hour_key] = {
                    'timestamp': hour_key,
                    'count': 0,
                    'by_level': {level.name: 0 for level in ThreatLevel}
                }
            
            timeline[hour_key]['count'] += 1
            timeline[hour_key]['by_level'][alert.threat_level.name] += 1
        
        # Convert to sorted list
        return sorted(timeline.values(), key=lambda x: x['timestamp'])

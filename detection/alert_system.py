"""
Alert System - Real-time alert generation and management
Handles alert creation, aggregation, deduplication, and notification formatting
"""

import uuid
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import json

from utils.data_models import ThreatAlert, ThreatLevel
from config.config import config


class AlertSystem:
    """
    Manages threat alerts with deduplication and aggregation
    """
    
    def __init__(self):
        # Alert storage
        self.alerts: List[ThreatAlert] = []
        self.alert_index: Dict[str, ThreatAlert] = {}  # alert_id -> alert
        
        # Deduplication tracking
        self.recent_alerts: Dict[str, datetime] = {}  # alert_key -> last_time
        self.alert_counts: Dict[str, int] = defaultdict(int)  # alert_key -> count
        
        # Alert cooldown (prevent spam)
        self.cooldown_seconds = {
            ThreatLevel.INFO: 300,      # 5 minutes
            ThreatLevel.LOW: 180,       # 3 minutes
            ThreatLevel.MEDIUM: 60,     # 1 minute
            ThreatLevel.HIGH: 30,       # 30 seconds
            ThreatLevel.CRITICAL: 0     # No cooldown for critical
        }
    
    def create_alert(
        self,
        app_package_name: str,
        threat_level: ThreatLevel,
        threat_type: str,
        threat_score: float,
        description: str,
        **kwargs
    ) -> Optional[ThreatAlert]:
        """
        Create a new threat alert with deduplication
        
        Returns None if alert is duplicate within cooldown period
        """
        # Generate alert key for deduplication
        alert_key = f"{app_package_name}:{threat_type}"
        
        # Check if duplicate within cooldown
        if alert_key in self.recent_alerts:
            last_time = self.recent_alerts[alert_key]
            cooldown = self.cooldown_seconds[threat_level]
            
            if (datetime.now() - last_time).total_seconds() < cooldown:
                # Increment count but don't create new alert
                self.alert_counts[alert_key] += 1
                return None
        
        # Create new alert
        alert = ThreatAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            app_package_name=app_package_name,
            threat_level=threat_level,
            threat_type=threat_type,
            threat_score=threat_score,
            description=description,
            **kwargs
        )
        
        # Store alert
        self.alerts.append(alert)
        self.alert_index[alert.alert_id] = alert
        
        # Update deduplication tracking
        self.recent_alerts[alert_key] = datetime.now()
        self.alert_counts[alert_key] = 1
        
        # Cleanup old alerts
        self._cleanup_old_alerts()
        
        return alert
    
    def get_alert(self, alert_id: str) -> Optional[ThreatAlert]:
        """Get alert by ID"""
        return self.alert_index.get(alert_id)
    
    def get_recent_alerts(self, limit: int = 50) -> List[ThreatAlert]:
        """Get most recent alerts"""
        return self.alerts[-limit:]
    
    def get_alerts_by_app(self, app: str, limit: int = 20) -> List[ThreatAlert]:
        """Get alerts for specific app"""
        app_alerts = [a for a in self.alerts if a.app_package_name == app]
        return app_alerts[-limit:]
    
    def get_alerts_by_level(self, level: ThreatLevel, limit: int = 50) -> List[ThreatAlert]:
        """Get alerts by threat level"""
        level_alerts = [a for a in self.alerts if a.threat_level == level]
        return level_alerts[-limit:]
    
    def get_critical_alerts(self) -> List[ThreatAlert]:
        """Get all unresolved critical alerts"""
        return [
            a for a in self.alerts
            if a.threat_level == ThreatLevel.CRITICAL
        ]
    
    def format_notification(self, alert: ThreatAlert) -> Dict:
        """
        Format alert for Android notification
        Returns notification data with title, message, priority
        """
        # Determine notification priority
        priority_map = {
            ThreatLevel.INFO: 'low',
            ThreatLevel.LOW: 'default',
            ThreatLevel.MEDIUM: 'high',
            ThreatLevel.HIGH: 'high',
            ThreatLevel.CRITICAL: 'max'
        }
        
        # Create notification title
        if alert.blocked:
            title = f"🛡️ Blocked: {alert.threat_type}"
        else:
            title = f"⚠️ {alert.threat_type} Detected"
        
        # Create notification message
        message = f"{alert.app_package_name}\n{alert.description}"
        
        # Add action buttons based on threat level
        actions = []
        
        if alert.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            actions.append({
                'action': 'block_app',
                'label': 'Block App',
                'app': alert.app_package_name
            })
        
        actions.append({
            'action': 'view_details',
            'label': 'View Details',
            'alert_id': alert.alert_id
        })
        
        actions.append({
            'action': 'false_positive',
            'label': 'Not a Threat',
            'alert_id': alert.alert_id
        })
        
        return {
            'notification_id': alert.alert_id,
            'title': title,
            'message': message,
            'priority': priority_map[alert.threat_level],
            'timestamp': alert.timestamp.isoformat(),
            'actions': actions,
            'metadata': {
                'app': alert.app_package_name,
                'threat_type': alert.threat_type,
                'threat_score': alert.threat_score,
                'blocked': alert.blocked
            }
        }
    
    def get_alert_statistics(self) -> Dict:
        """Get statistics about alerts"""
        if not self.alerts:
            return {
                'total_alerts': 0,
                'by_level': {},
                'by_type': {},
                'by_app': {},
                'blocked_count': 0
            }
        
        # Count by level
        by_level = defaultdict(int)
        for alert in self.alerts:
            by_level[alert.threat_level.name] += 1
        
        # Count by type
        by_type = defaultdict(int)
        for alert in self.alerts:
            by_type[alert.threat_type] += 1
        
        # Count by app
        by_app = defaultdict(int)
        for alert in self.alerts:
            by_app[alert.app_package_name] += 1
        
        # Count blocked
        blocked_count = sum(1 for a in self.alerts if a.blocked)
        
        return {
            'total_alerts': len(self.alerts),
            'by_level': dict(by_level),
            'by_type': dict(by_type),
            'by_app': dict(by_app),
            'blocked_count': blocked_count,
            'last_24h': self._count_recent_alerts(24),
            'last_1h': self._count_recent_alerts(1)
        }
    
    def _count_recent_alerts(self, hours: int) -> int:
        """Count alerts in last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        return sum(1 for a in self.alerts if a.timestamp >= cutoff)
    
    def aggregate_alerts(self, time_window_minutes: int = 5) -> List[Dict]:
        """
        Aggregate similar alerts within time window
        Useful for reducing notification spam
        """
        cutoff = datetime.now() - timedelta(minutes=time_window_minutes)
        recent = [a for a in self.alerts if a.timestamp >= cutoff]
        
        # Group by app + threat type
        groups = defaultdict(list)
        for alert in recent:
            key = f"{alert.app_package_name}:{alert.threat_type}"
            groups[key].append(alert)
        
        # Create aggregated summaries
        aggregated = []
        for key, alerts in groups.items():
            if len(alerts) > 1:
                app, threat_type = key.split(':', 1)
                aggregated.append({
                    'app': app,
                    'threat_type': threat_type,
                    'count': len(alerts),
                    'highest_score': max(a.threat_score for a in alerts),
                    'highest_level': max(a.threat_level.value for a in alerts),
                    'blocked_count': sum(1 for a in alerts if a.blocked),
                    'first_seen': min(a.timestamp for a in alerts).isoformat(),
                    'last_seen': max(a.timestamp for a in alerts).isoformat()
                })
        
        return aggregated
    
    def export_alerts(self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> str:
        """Export alerts as JSON"""
        if start_time is None:
            start_time = datetime.min
        if end_time is None:
            end_time = datetime.max
        
        filtered_alerts = [
            a for a in self.alerts
            if start_time <= a.timestamp <= end_time
        ]
        
        export_data = {
            'export_time': datetime.now().isoformat(),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'alert_count': len(filtered_alerts),
            'alerts': [a.to_dict() for a in filtered_alerts]
        }
        
        return json.dumps(export_data, indent=2)
    
    def _cleanup_old_alerts(self):
        """Remove old alerts to prevent memory bloat"""
        max_alerts = config.system.max_alerts_stored
        
        if len(self.alerts) > max_alerts:
            # Remove oldest alerts
            removed = self.alerts[:-max_alerts]
            self.alerts = self.alerts[-max_alerts:]
            
            # Update index
            for alert in removed:
                if alert.alert_id in self.alert_index:
                    del self.alert_index[alert.alert_id]
        
        # Clean up deduplication tracking (older than 1 hour)
        cutoff = datetime.now() - timedelta(hours=1)
        old_keys = [
            key for key, time in self.recent_alerts.items()
            if time < cutoff
        ]
        
        for key in old_keys:
            del self.recent_alerts[key]
            if key in self.alert_counts:
                del self.alert_counts[key]

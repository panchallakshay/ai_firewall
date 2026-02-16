"""
Continuous Learning System
On-device learning that adapts to user's app behavior patterns
Privacy-preserving federated learning approach
"""

import numpy as np
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
from pathlib import Path

from utils.data_models import TrafficFeatures, AppBehavior
from config.config import config


class ContinuousLearner:
    """
    Learns and adapts to normal app behavior patterns on-device
    Implements incremental learning without full retraining
    """
    
    def __init__(self):
        self.config = config.ml
        
        # Per-app behavioral baselines
        self.app_baselines: Dict[str, AppBehavior] = {}
        
        # Recent feature history for learning
        self.feature_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        
        # Learning state
        self.learning_enabled = self.config.enable_continuous_learning
        self.last_update_time = datetime.now()
        
        # Anomaly feedback (user corrections)
        self.false_positives: List[TrafficFeatures] = []
        self.true_positives: List[TrafficFeatures] = []
        
        # Load existing baselines
        self._load_baselines()
    
    def learn_baseline(self, app: str, features: TrafficFeatures, is_system_app: bool = False):
        """
        Learn normal baseline behavior for an app
        Uses exponential moving average for incremental updates
        """
        if not self.learning_enabled:
            return
        
        # Initialize baseline if new app
        if app not in self.app_baselines:
            self.app_baselines[app] = AppBehavior(
                app_package_name=app,
                is_system_app=is_system_app,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
        
        baseline = self.app_baselines[app]
        baseline.last_seen = datetime.now()
        
        # Store feature history
        self.feature_history[app].append(features)
        
        # Update baseline metrics using exponential moving average
        alpha = 0.1  # Learning rate (0.1 = 10% weight to new data)
        
        baseline.baseline_pps = (
            alpha * features.packets_per_sec + 
            (1 - alpha) * baseline.baseline_pps
        )
        
        baseline.baseline_bps = (
            alpha * features.bytes_per_sec + 
            (1 - alpha) * baseline.baseline_bps
        )
        
        # Track known destinations
        # Would extract from actual packets, placeholder here
        baseline.total_sessions += 1
        
        # Calculate average session duration
        if len(self.feature_history[app]) > 1:
            durations = [f.session_duration for f in self.feature_history[app]]
            baseline.avg_session_duration = np.mean(durations)
        
        # Periodically save baselines
        if (datetime.now() - self.last_update_time).total_seconds() / 3600 >= self.config.model_update_interval_hours:
            self._save_baselines()
            self.last_update_time = datetime.now()
    
    def detect_deviation(self, app: str, features: TrafficFeatures) -> tuple[bool, float, str]:
        """
        Detect if current behavior deviates from learned baseline
        
        Returns:
            - is_deviation: bool
            - deviation_score: float (0-1)
            - reason: str
        """
        if app not in self.app_baselines:
            # New app, no baseline yet
            return False, 0.0, "no_baseline"
        
        baseline = self.app_baselines[app]
        
        # Calculate deviations for key metrics
        deviations = {}
        
        # Packets per second deviation
        if baseline.baseline_pps > 0:
            pps_deviation = abs(features.packets_per_sec - baseline.baseline_pps) / baseline.baseline_pps
            deviations['pps'] = pps_deviation
        
        # Bytes per second deviation
        if baseline.baseline_bps > 0:
            bps_deviation = abs(features.bytes_per_sec - baseline.baseline_bps) / baseline.baseline_bps
            deviations['bps'] = bps_deviation
        
        # Background ratio deviation (sudden increase is suspicious)
        if features.background_ratio > 0.7 and not baseline.is_system_app:
            deviations['background'] = features.background_ratio
        
        # New destination rate (sudden spike)
        if features.new_destination_rate > 20:
            deviations['new_destinations'] = features.new_destination_rate / 20
            baseline.new_destination_detected = True
        
        # DNS query spike
        if features.dns_queries_per_min > 50:
            deviations['dns_spike'] = features.dns_queries_per_min / 50
        
        # Calculate overall deviation score
        if deviations:
            deviation_score = np.mean(list(deviations.values()))
            # Clip to 0-1 range
            deviation_score = min(deviation_score, 1.0)
        else:
            deviation_score = 0.0
        
        # Determine if significant deviation
        is_deviation = deviation_score > 0.5  # 50% threshold
        
        # Get primary reason
        if deviations:
            reason = max(deviations.items(), key=lambda x: x[1])[0]
        else:
            reason = "normal"
        
        # Update behavioral flags
        if is_deviation:
            baseline.sudden_traffic_spike = True
        
        return is_deviation, deviation_score, reason
    
    def record_feedback(self, features: TrafficFeatures, was_false_positive: bool):
        """
        Record user feedback on alerts to improve model
        """
        if was_false_positive:
            self.false_positives.append(features)
        else:
            self.true_positives.append(features)
        
        # If enough feedback collected, trigger model update
        total_feedback = len(self.false_positives) + len(self.true_positives)
        
        if total_feedback >= self.config.min_samples_for_update:
            self._update_models_with_feedback()
    
    def _update_models_with_feedback(self):
        """
        Update anomaly detection models based on user feedback
        This implements the continuous learning loop
        """
        print(f"Updating models with {len(self.false_positives)} false positives and {len(self.true_positives)} true positives")
        
        # In production, would retrain or fine-tune models here
        # For now, adjust thresholds based on feedback
        
        if len(self.false_positives) > len(self.true_positives) * 2:
            # Too many false positives, increase threshold
            config.detection.anomaly_score_threshold *= 1.1
            print("Increased anomaly threshold to reduce false positives")
        
        elif len(self.true_positives) > len(self.false_positives) * 2:
            # Too many true positives being missed, decrease threshold
            config.detection.anomaly_score_threshold *= 0.9
            print("Decreased anomaly threshold to catch more threats")
        
        # Clear feedback after update
        self.false_positives.clear()
        self.true_positives.clear()
    
    def get_app_profile(self, app: str) -> Optional[AppBehavior]:
        """Get learned behavioral profile for an app"""
        return self.app_baselines.get(app)
    
    def get_all_profiles(self) -> Dict[str, AppBehavior]:
        """Get all app behavioral profiles"""
        return self.app_baselines.copy()
    
    def export_threat_signatures(self) -> dict:
        """
        Export anonymized threat signatures for federated learning
        Only shares patterns, not user data
        """
        if not self.true_positives:
            return {}
        
        # Aggregate threat patterns
        threat_features = [f.to_array() for f in self.true_positives]
        
        # Calculate statistical summary (no raw data)
        signatures = {
            'mean_features': np.mean(threat_features, axis=0).tolist(),
            'std_features': np.std(threat_features, axis=0).tolist(),
            'count': len(threat_features),
            'timestamp': datetime.now().isoformat()
        }
        
        return signatures
    
    def _save_baselines(self):
        """Save learned baselines to disk"""
        baseline_dir = Path("data/baselines")
        baseline_dir.mkdir(parents=True, exist_ok=True)
        
        baseline_file = baseline_dir / "app_baselines.json"
        
        # Convert to JSON-serializable format
        baselines_dict = {
            app: baseline.to_dict()
            for app, baseline in self.app_baselines.items()
        }
        
        with open(baseline_file, 'w') as f:
            json.dump(baselines_dict, f, indent=2)
        
        print(f"✓ Saved {len(baselines_dict)} app baselines")
    
    def _load_baselines(self):
        """Load previously learned baselines"""
        baseline_file = Path("data/baselines/app_baselines.json")
        
        if not baseline_file.exists():
            return
        
        try:
            with open(baseline_file, 'r') as f:
                baselines_dict = json.load(f)
            
            # Reconstruct AppBehavior objects
            for app, data in baselines_dict.items():
                self.app_baselines[app] = AppBehavior(
                    app_package_name=data['app_package_name'],
                    is_system_app=data['is_system_app'],
                    first_seen=datetime.fromisoformat(data['first_seen']),
                    last_seen=datetime.fromisoformat(data['last_seen']),
                    baseline_pps=data['baseline_pps'],
                    baseline_bps=data['baseline_bps'],
                    baseline_destinations=data['baseline_destinations'],
                    has_internet_permission=data['has_internet_permission'],
                    has_network_state_permission=data['has_network_state_permission'],
                    total_sessions=data['total_sessions'],
                    total_data_transferred=data['total_data_transferred'],
                    avg_session_duration=data['avg_session_duration']
                )
            
            print(f"✓ Loaded {len(self.app_baselines)} app baselines")
        
        except Exception as e:
            print(f"Could not load baselines: {e}")
    
    def detect_model_drift(self) -> bool:
        """
        Detect if the model has drifted and needs retraining
        Compares recent prediction accuracy to baseline
        """
        # Simple drift detection: if too many false positives recently
        recent_feedback = len(self.false_positives) + len(self.true_positives)
        
        if recent_feedback < 50:
            return False  # Not enough data
        
        false_positive_rate = len(self.false_positives) / recent_feedback
        
        # If >30% false positives, model has drifted
        return false_positive_rate > 0.3

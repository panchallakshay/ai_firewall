"""
Anomaly Detection Models
Implements Isolation Forest, LSTM Autoencoder, and One-Class SVM for traffic anomaly detection
"""

import numpy as np
from typing import List, Tuple, Optional
from datetime import datetime
import pickle
from pathlib import Path

# For production, these would use TensorFlow Lite
# For now, using sklearn for demonstration
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

from utils.data_models import TrafficFeatures
from config.config import config


class AnomalyDetector:
    """
    Multi-model anomaly detection system
    Combines Isolation Forest, Autoencoder, and One-Class SVM
    """
    
    def __init__(self):
        self.config = config.ml
        
        # Models
        self.isolation_forest: Optional[IsolationForest] = None
        self.one_class_svm: Optional[OneClassSVM] = None
        self.scaler = StandardScaler()
        
        # For LSTM Autoencoder (would be TFLite model in production)
        self.autoencoder = None
        self.autoencoder_threshold = self.config.autoencoder_threshold
        
        # Model state
        self.is_trained = False
        self.feature_names = TrafficFeatures.feature_names()
        
        # Load pre-trained models if available
        self._load_models()
    
    def train(self, training_data: List[TrafficFeatures]):
        """
        Train anomaly detection models on normal traffic
        In production, this would be done offline and models converted to TFLite
        """
        if len(training_data) < 100:
            print("Warning: Insufficient training data. Need at least 100 samples.")
            return False
        
        # Convert features to numpy array
        X = np.array([f.to_array() for f in training_data])
        
        # Fit scaler
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        print("Training Isolation Forest...")
        self.isolation_forest = IsolationForest(
            contamination=self.config.isolation_forest_contamination,
            random_state=42,
            n_estimators=100
        )
        self.isolation_forest.fit(X_scaled)
        
        # Train One-Class SVM
        print("Training One-Class SVM...")
        self.one_class_svm = OneClassSVM(
            kernel='rbf',
            gamma='auto',
            nu=0.1  # Expected outlier fraction
        )
        self.one_class_svm.fit(X_scaled)
        
        # For LSTM Autoencoder, would train here
        # self._train_autoencoder(X_scaled)
        
        self.is_trained = True
        
        # Save models
        self._save_models()
        
        print("✓ Anomaly detection models trained successfully")
        return True
    
    def detect_anomaly(self, features: TrafficFeatures) -> Tuple[bool, float, dict]:
        """
        Detect if traffic features are anomalous
        
        Returns:
            - is_anomaly: bool
            - anomaly_score: float (0-1, higher = more anomalous)
            - details: dict with per-model scores
        """
        if not self.is_trained:
            # Use rule-based detection if models not trained
            return self._rule_based_detection(features)
        
        # Convert to array and scale
        X = np.array([features.to_array()])
        X_scaled = self.scaler.transform(X)
        
        # Get predictions from each model
        scores = {}
        
        # 1. Isolation Forest
        if_score = self.isolation_forest.score_samples(X_scaled)[0]
        if_pred = self.isolation_forest.predict(X_scaled)[0]
        # Convert to 0-1 scale (more negative = more anomalous)
        if_normalized = 1.0 / (1.0 + np.exp(if_score))  # Sigmoid
        scores['isolation_forest'] = if_normalized
        scores['isolation_forest_anomaly'] = (if_pred == -1)
        
        # 2. One-Class SVM
        svm_pred = self.one_class_svm.predict(X_scaled)[0]
        svm_score = self.one_class_svm.score_samples(X_scaled)[0]
        svm_normalized = 1.0 / (1.0 + np.exp(svm_score))
        scores['one_class_svm'] = svm_normalized
        scores['one_class_svm_anomaly'] = (svm_pred == -1)
        
        # 3. LSTM Autoencoder (if available)
        if self.autoencoder:
            ae_score = self._autoencoder_score(X_scaled)
            scores['autoencoder'] = ae_score
            scores['autoencoder_anomaly'] = (ae_score > self.autoencoder_threshold)
        
        # Aggregate scores (ensemble)
        anomaly_scores = [
            scores.get('isolation_forest', 0),
            scores.get('one_class_svm', 0),
            scores.get('autoencoder', 0)
        ]
        avg_score = np.mean([s for s in anomaly_scores if s > 0])
        
        # Determine if anomaly (majority vote or high average score)
        anomaly_votes = sum([
            scores.get('isolation_forest_anomaly', False),
            scores.get('one_class_svm_anomaly', False),
            scores.get('autoencoder_anomaly', False)
        ])
        
        is_anomaly = (anomaly_votes >= 2) or (avg_score > 0.7)
        
        return is_anomaly, avg_score, scores
    
    def _rule_based_detection(self, features: TrafficFeatures) -> Tuple[bool, float, dict]:
        """
        Fallback rule-based anomaly detection when ML models not available
        Uses thresholds from config
        """
        detection_config = config.detection
        anomaly_indicators = []
        scores = {}
        
        # Check rate-based anomalies
        if features.packets_per_sec > detection_config.max_packets_per_sec:
            anomaly_indicators.append('high_pps')
            scores['high_pps'] = min(features.packets_per_sec / detection_config.max_packets_per_sec, 1.0)
        
        if features.bytes_per_sec > detection_config.max_bytes_per_sec:
            anomaly_indicators.append('high_bps')
            scores['high_bps'] = min(features.bytes_per_sec / detection_config.max_bytes_per_sec, 1.0)
        
        if features.dns_queries_per_min > detection_config.max_dns_queries_per_min:
            anomaly_indicators.append('high_dns_rate')
            scores['high_dns_rate'] = min(features.dns_queries_per_min / detection_config.max_dns_queries_per_min, 1.0)
        
        # Check behavioral anomalies
        if features.background_ratio > detection_config.background_traffic_threshold:
            anomaly_indicators.append('high_background_traffic')
            scores['high_background_traffic'] = features.background_ratio
        
        if features.unique_destinations_per_min > detection_config.max_unique_destinations_per_min:
            anomaly_indicators.append('many_destinations')
            scores['many_destinations'] = min(
                features.unique_destinations_per_min / detection_config.max_unique_destinations_per_min, 
                1.0
            )
        
        # Check DNS anomalies
        if features.dns_txt_queries > detection_config.max_dns_txt_queries_per_min:
            anomaly_indicators.append('suspicious_dns_txt')
            scores['suspicious_dns_txt'] = 0.9  # High score for C2 indicator
        
        # Check data exfiltration patterns
        if features.upload_download_ratio > detection_config.suspicious_upload_ratio:
            anomaly_indicators.append('high_upload_ratio')
            scores['high_upload_ratio'] = min(
                features.upload_download_ratio / detection_config.suspicious_upload_ratio,
                1.0
            )
        
        # Calculate overall score
        if scores:
            avg_score = np.mean(list(scores.values()))
        else:
            avg_score = 0.0
        
        is_anomaly = len(anomaly_indicators) >= 2 or avg_score > 0.7
        
        scores['rule_based'] = True
        scores['indicators'] = anomaly_indicators
        
        return is_anomaly, avg_score, scores
    
    def _autoencoder_score(self, X: np.ndarray) -> float:
        """
        Calculate reconstruction error from autoencoder
        Higher error = more anomalous
        """
        if not self.autoencoder:
            return 0.0
        
        # In production, this would use TFLite interpreter
        # For now, placeholder
        reconstruction = self.autoencoder.predict(X)
        mse = np.mean((X - reconstruction) ** 2)
        
        # Normalize to 0-1
        return min(mse / self.autoencoder_threshold, 1.0)
    
    def _save_models(self):
        """Save trained models to disk"""
        model_dir = Path(self.config.isolation_forest_model_path).parent
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Save Isolation Forest
        if_path = model_dir / "isolation_forest.pkl"
        with open(if_path, 'wb') as f:
            pickle.dump(self.isolation_forest, f)
        
        # Save One-Class SVM
        svm_path = model_dir / "one_class_svm.pkl"
        with open(svm_path, 'wb') as f:
            pickle.dump(self.one_class_svm, f)
        
        # Save scaler
        scaler_path = model_dir / "scaler.pkl"
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        print(f"✓ Models saved to {model_dir}")
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        model_dir = Path(self.config.isolation_forest_model_path).parent
        
        try:
            # Load Isolation Forest
            if_path = model_dir / "isolation_forest.pkl"
            if if_path.exists():
                with open(if_path, 'rb') as f:
                    self.isolation_forest = pickle.load(f)
            
            # Load One-Class SVM
            svm_path = model_dir / "one_class_svm.pkl"
            if svm_path.exists():
                with open(svm_path, 'rb') as f:
                    self.one_class_svm = pickle.load(f)
            
            # Load scaler
            scaler_path = model_dir / "scaler.pkl"
            if scaler_path.exists():
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
            
            if self.isolation_forest and self.one_class_svm:
                self.is_trained = True
                print("✓ Pre-trained models loaded successfully")
        
        except Exception as e:
            print(f"Could not load pre-trained models: {e}")
            self.is_trained = False
    
    def get_feature_importance(self) -> dict:
        """
        Get feature importance scores
        Useful for understanding which features contribute most to anomalies
        """
        if not self.is_trained or not self.isolation_forest:
            return {}
        
        # For Isolation Forest, we can approximate importance
        # by looking at feature usage in trees
        importance = {}
        
        # Placeholder - would need actual implementation
        for i, name in enumerate(self.feature_names):
            importance[name] = 1.0 / (i + 1)  # Dummy values
        
        return importance


class LSTMAutoencoder:
    """
    LSTM Autoencoder for temporal anomaly detection
    In production, this would be a TensorFlow Lite model
    """
    
    def __init__(self, sequence_length: int = 10):
        self.sequence_length = sequence_length
        self.model = None
        self.is_trained = False
    
    def train(self, sequences: np.ndarray):
        """
        Train LSTM autoencoder on normal traffic sequences
        sequences shape: (n_samples, sequence_length, n_features)
        """
        # In production, would build and train TensorFlow model here
        # Then convert to TFLite
        pass
    
    def predict(self, sequence: np.ndarray) -> np.ndarray:
        """Reconstruct input sequence"""
        # In production, would use TFLite interpreter
        return sequence  # Placeholder
    
    def detect_anomaly(self, sequence: np.ndarray, threshold: float = 0.5) -> Tuple[bool, float]:
        """
        Detect anomaly based on reconstruction error
        """
        reconstruction = self.predict(sequence)
        mse = np.mean((sequence - reconstruction) ** 2)
        
        is_anomaly = mse > threshold
        return is_anomaly, mse

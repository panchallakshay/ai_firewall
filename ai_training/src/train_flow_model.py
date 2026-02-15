"""
Train Flow Anomaly Detection Model
Uses MLP architecture for connection behavior classification
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import json
import sys
import os

# Add src to path
sys.path.append(os.path.dirname(__file__))
from features_flow import FlowFeatureExtractor


class FlowModelTrainer:
    """Train flow anomaly detection model"""
    
    def __init__(self, ip_blocklist_path: str = None):
        """
        Initialize trainer
        
        Args:
            ip_blocklist_path: Path to IP blocklist file (optional)
        """
        ip_blocklist = []
        if ip_blocklist_path and os.path.exists(ip_blocklist_path):
            with open(ip_blocklist_path, 'r') as f:
                ip_blocklist = [line.strip() for line in f if line.strip()]
        
        self.extractor = FlowFeatureExtractor(ip_blocklist)
        self.scaler = StandardScaler()
        self.model = None
        self.feature_names = None
    
    def load_cic_dataset(self, csv_path: str, sample_size: int = None) -> pd.DataFrame:
        """
        Load CIC-DDoS2019 dataset
        
        Args:
            csv_path: Path to CIC CSV file
            sample_size: Optional sample size to limit dataset
        
        Returns:
            DataFrame with features and labels
        """
        print(f"Loading CIC dataset from {csv_path}...")
        
        # Load CSV
        df_raw = pd.read_csv(csv_path)
        
        if sample_size:
            df_raw = df_raw.sample(n=min(sample_size, len(df_raw)), random_state=42)
        
        print(f"Loaded {len(df_raw)} flow records")
        
        # CIC dataset has a 'Label' column
        # Map labels to our classes
        label_mapping = {
            'BENIGN': 0,  # ALLOW
            'DrDoS_DNS': 2,  # BLOCK
            'DrDoS_LDAP': 2,
            'DrDoS_MSSQL': 2,
            'DrDoS_NetBIOS': 2,
            'DrDoS_NTP': 2,
            'DrDoS_SNMP': 2,
            'DrDoS_SSDP': 2,
            'DrDoS_UDP': 2,
            'Syn': 2,
            'TFTP': 2,
            'UDP-lag': 2,
            'WebDDoS': 1,  # WARN (less severe)
        }
        
        # Extract features from CIC flows
        data = []
        
        for idx, row in df_raw.iterrows():
            if idx % 10000 == 0:
                print(f"Processing flow {idx}/{len(df_raw)}...")
            
            try:
                # Map CIC columns to our flow stats
                flow_stats = {
                    'dst_ip': row.get('Destination IP', '0.0.0.0'),
                    'dst_port': int(row.get('Destination Port', 0)),
                    'protocol': 'TCP' if row.get('Protocol', 6) == 6 else 'UDP',
                    'packets_per_sec': float(row.get('Flow Packets/s', 0)),
                    'bytes_per_sec': float(row.get('Flow Bytes/s', 0)),
                    'upload_bytes': float(row.get('Total Fwd Packets', 0)) * float(row.get('Average Packet Size', 0)),
                    'download_bytes': float(row.get('Total Backward Packets', 0)) * float(row.get('Average Packet Size', 0)),
                    'duration_sec': float(row.get('Flow Duration', 0)) / 1000000.0,  # Convert microseconds
                    'new_connections_per_min': float(row.get('Flow Packets/s', 0)) * 60 / max(float(row.get('Flow Duration', 1)) / 1000000.0, 1),
                    'unique_dst_ips_per_min': np.random.uniform(1, 5),  # Not in CIC, simulate
                    'failure_count': 0,  # Not in CIC
                    'total_connections': 1,
                    'unique_dst_ips': {row.get('Destination IP', '0.0.0.0')}
                }
                
                # Simulate app info (not in CIC dataset)
                app_info = {
                    'permission_count': np.random.randint(3, 15),
                    'is_system_app': np.random.random() < 0.1,
                    'install_age_days': np.random.randint(1, 365),
                    'background_restricted': np.random.random() < 0.3
                }
                
                # Extract features
                features, names = self.extractor.extract_features(flow_stats, app_info)
                
                if self.feature_names is None:
                    self.feature_names = names
                
                # Get label
                label_str = row.get('Label', 'BENIGN')
                label = label_mapping.get(label_str, 0)
                
                data.append(features + [label])
                
            except Exception as e:
                print(f"Error processing flow {idx}: {e}")
                continue
        
        # Create DataFrame
        columns = self.feature_names + ['label']
        df = pd.DataFrame(data, columns=columns)
        
        print(f"\nDataset summary:")
        print(df['label'].value_counts())
        print(f"Total samples: {len(df)}")
        
        return df
    
    def build_model(self, input_dim: int) -> keras.Model:
        """
        Build MLP model for flow anomaly detection
        
        Args:
            input_dim: Number of input features
        
        Returns:
            Compiled Keras model
        """
        model = keras.Sequential([
            layers.Input(shape=(input_dim,)),
            layers.Dense(128, activation='relu', name='hidden1'),
            layers.Dropout(0.3),
            layers.Dense(64, activation='relu', name='hidden2'),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu', name='hidden3'),
            layers.Dropout(0.2),
            layers.Dense(3, activation='softmax', name='output')  # 3 classes
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train(self, df: pd.DataFrame, epochs: int = 50, batch_size: int = 64):
        """
        Train the model
        
        Args:
            df: DataFrame with features and labels
            epochs: Number of training epochs
            batch_size: Batch size
        """
        # Separate features and labels
        X = df[self.feature_names].values
        y = df['label'].values
        
        # Split dataset
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        print(f"\nTraining set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        
        # Build model
        self.model = self.build_model(input_dim=X_train_scaled.shape[1])
        
        print("\nModel architecture:")
        self.model.summary()
        
        # Train model
        print("\nTraining model...")
        history = self.model.fit(
            X_train_scaled, y_train,
            validation_split=0.2,
            epochs=epochs,
            batch_size=batch_size,
            verbose=1
        )
        
        # Evaluate on test set
        print("\nEvaluating on test set...")
        test_loss, test_acc = self.model.evaluate(X_test_scaled, y_test, verbose=0)
        print(f"Test accuracy: {test_acc:.4f}")
        print(f"Test loss: {test_loss:.4f}")
        
        # Detailed metrics
        y_pred = np.argmax(self.model.predict(X_test_scaled, verbose=0), axis=1)
        
        # Get unique classes present in test set
        unique_classes = np.unique(np.concatenate([y_test, y_pred]))
        target_names = ['ALLOW', 'WARN', 'BLOCK']
        actual_target_names = [target_names[i] for i in unique_classes]
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred,
                                   labels=unique_classes,
                                   target_names=actual_target_names))
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        return history
    
    def save_model(self, output_dir: str):
        """
        Save trained model and metadata
        
        Args:
            output_dir: Directory to save model files
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Save Keras model
        keras_path = os.path.join(output_dir, 'flow_model.h5')
        self.model.save(keras_path)
        print(f"\nSaved Keras model to {keras_path}")
        
        # Save scaler parameters
        scaler_params = {
            'mean': self.scaler.mean_.tolist(),
            'scale': self.scaler.scale_.tolist()
        }
        
        # Save metadata
        metadata = {
            'model_type': 'flow_anomaly_detection',
            'version': '1.0',
            'num_features': len(self.feature_names),
            'feature_names': self.feature_names,
            'classes': ['ALLOW', 'WARN', 'BLOCK'],
            'scaler': scaler_params
        }
        
        metadata_path = os.path.join(output_dir, 'flow_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"Saved metadata to {metadata_path}")


def main():
    """Main training pipeline"""
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    OUTPUT_DIR = os.path.join(BASE_DIR, 'out')
    
    cic_path = os.path.join(DATA_DIR, 'cic_ddos2019_flows.csv')
    ip_blocklist_path = os.path.join(DATA_DIR, 'ip_blocklist.txt')
    
    # Check if data files exist
    if not os.path.exists(cic_path):
        print(f"ERROR: CIC dataset not found: {cic_path}")
        print("Please download CIC-DDoS2019 dataset and save to this path")
        print("Download from: https://www.unb.ca/cic/datasets/ddos-2019.html")
        return
    
    # Initialize trainer
    trainer = FlowModelTrainer(
        ip_blocklist_path=ip_blocklist_path if os.path.exists(ip_blocklist_path) else None
    )
    
    # Load dataset (sample for faster training - remove sample_size for full dataset)
    df = trainer.load_cic_dataset(cic_path, sample_size=100000)
    
    # Train model
    trainer.train(df, epochs=50, batch_size=64)
    
    # Save model
    trainer.save_model(OUTPUT_DIR)
    
    print("\n✓ Flow model training complete!")


if __name__ == "__main__":
    main()

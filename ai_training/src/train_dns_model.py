"""
Train DNS Threat Detection Model
Uses MLP architecture for domain-based threat classification
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
from features_dns import DnsFeatureExtractor, load_tranco_ranks


class DnsModelTrainer:
    """Train DNS threat detection model"""
    
    def __init__(self, tranco_path: str = None):
        """
        Initialize trainer
        
        Args:
            tranco_path: Path to Tranco rankings CSV (optional)
        """
        self.tranco_ranks = load_tranco_ranks(tranco_path) if tranco_path else {}
        self.extractor = DnsFeatureExtractor(self.tranco_ranks)
        self.scaler = StandardScaler()
        self.model = None
        self.feature_names = None
    
    def load_domain_dataset(self, benign_path: str, malicious_path: str) -> pd.DataFrame:
        """
        Load and prepare domain dataset
        
        Args:
            benign_path: Path to benign domains file (one per line)
            malicious_path: Path to malicious domains file (one per line)
        
        Returns:
            DataFrame with features and labels
        """
        print("Loading domain datasets...")
        
        # Load benign domains
        with open(benign_path, 'r') as f:
            benign_domains = [line.strip() for line in f if line.strip()]
        
        # Load malicious domains
        with open(malicious_path, 'r') as f:
            malicious_domains = [line.strip() for line in f if line.strip()]
        
        print(f"Loaded {len(benign_domains)} benign domains")
        print(f"Loaded {len(malicious_domains)} malicious domains")
        
        # Extract features
        data = []
        
        # Process benign domains (label = 0)
        for domain in benign_domains:
            try:
                features, names = self.extractor.extract_features(
                    domain,
                    dns_stats={'queries_per_min': np.random.uniform(0, 5),
                              'unique_domains_per_min': np.random.uniform(0, 3)}
                )
                data.append(features + [0])  # ALLOW
                if self.feature_names is None:
                    self.feature_names = names
            except Exception as e:
                print(f"Error processing benign domain {domain}: {e}")
        
        # Process malicious domains
        # Split into WARN (label=1) and BLOCK (label=2)
        for i, domain in enumerate(malicious_domains):
            try:
                # Simulate burst behavior for some malicious domains
                if i % 3 == 0:  # High activity
                    dns_stats = {
                        'queries_per_min': np.random.uniform(20, 100),
                        'unique_domains_per_min': np.random.uniform(15, 50)
                    }
                    label = 2  # BLOCK
                else:  # Moderate activity
                    dns_stats = {
                        'queries_per_min': np.random.uniform(5, 20),
                        'unique_domains_per_min': np.random.uniform(3, 15)
                    }
                    label = 1  # WARN
                
                features, _ = self.extractor.extract_features(domain, dns_stats)
                data.append(features + [label])
            except Exception as e:
                print(f"Error processing malicious domain {domain}: {e}")
        
        # Create DataFrame
        columns = self.feature_names + ['label']
        df = pd.DataFrame(data, columns=columns)
        
        print(f"\nDataset summary:")
        print(df['label'].value_counts())
        print(f"Total samples: {len(df)}")
        
        return df
    
    def build_model(self, input_dim: int) -> keras.Model:
        """
        Build MLP model for DNS threat detection
        
        Args:
            input_dim: Number of input features
        
        Returns:
            Compiled Keras model
        """
        model = keras.Sequential([
            layers.Input(shape=(input_dim,)),
            layers.Dense(64, activation='relu', name='hidden1'),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu', name='hidden2'),
            layers.Dropout(0.2),
            layers.Dense(16, activation='relu', name='hidden3'),
            layers.Dense(3, activation='softmax', name='output')  # 3 classes
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def train(self, df: pd.DataFrame, epochs: int = 50, batch_size: int = 32):
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
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['ALLOW', 'WARN', 'BLOCK']))
        
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
        keras_path = os.path.join(output_dir, 'dns_model.h5')
        self.model.save(keras_path)
        print(f"\nSaved Keras model to {keras_path}")
        
        # Save scaler parameters
        scaler_params = {
            'mean': self.scaler.mean_.tolist(),
            'scale': self.scaler.scale_.tolist()
        }
        
        # Save metadata
        metadata = {
            'model_type': 'dns_threat_detection',
            'version': '1.0',
            'num_features': len(self.feature_names),
            'feature_names': self.feature_names,
            'classes': ['ALLOW', 'WARN', 'BLOCK'],
            'scaler': scaler_params
        }
        
        metadata_path = os.path.join(output_dir, 'dns_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"Saved metadata to {metadata_path}")


def main():
    """Main training pipeline"""
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    OUTPUT_DIR = os.path.join(BASE_DIR, 'out')
    
    benign_path = os.path.join(DATA_DIR, 'benign_domains.txt')
    malicious_path = os.path.join(DATA_DIR, 'malicious_domains.txt')
    tranco_path = os.path.join(DATA_DIR, 'tranco_top1m.csv')  # Optional
    
    # Check if data files exist
    if not os.path.exists(benign_path):
        print(f"ERROR: Benign domains file not found: {benign_path}")
        print("Please download Tranco top domains and save to this path")
        return
    
    if not os.path.exists(malicious_path):
        print(f"ERROR: Malicious domains file not found: {malicious_path}")
        print("Please download URLhaus/PhishTank domains and save to this path")
        return
    
    # Initialize trainer
    trainer = DnsModelTrainer(
        tranco_path=tranco_path if os.path.exists(tranco_path) else None
    )
    
    # Load dataset
    df = trainer.load_domain_dataset(benign_path, malicious_path)
    
    # Train model
    trainer.train(df, epochs=50, batch_size=32)
    
    # Save model
    trainer.save_model(OUTPUT_DIR)
    
    print("\n✓ DNS model training complete!")


if __name__ == "__main__":
    main()

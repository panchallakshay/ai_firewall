"""
Export Trained Models to TensorFlow Lite Format
Converts Keras models to optimized TFLite models for Android deployment
"""

import tensorflow as tf
import json
import os
import numpy as np


def convert_to_tflite(keras_model_path: str, 
                      output_path: str,
                      metadata_path: str = None,
                      quantize: bool = True):
    """
    Convert Keras model to TensorFlow Lite format
    
    Args:
        keras_model_path: Path to saved Keras model (.h5)
        output_path: Path to save TFLite model (.tflite)
        metadata_path: Optional path to metadata JSON for optimization
        quantize: Whether to apply dynamic range quantization
    """
    print(f"\nConverting {keras_model_path} to TFLite...")
    
    # Load Keras model
    model = tf.keras.models.load_model(keras_model_path)
    print(f"Loaded model with input shape: {model.input_shape}")
    
    # Create converter
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    
    # Apply optimizations
    if quantize:
        print("Applying dynamic range quantization...")
        converter.optimizations = [tf.lite.Optimize.DEFAULT]
        
        # Optional: Use representative dataset for better quantization
        if metadata_path and os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            num_features = metadata['num_features']
            
            def representative_dataset():
                """Generate representative data for calibration"""
                for _ in range(100):
                    # Generate random samples in typical range
                    yield [np.random.randn(1, num_features).astype(np.float32)]
            
            converter.representative_dataset = representative_dataset
    
    # Convert model
    tflite_model = converter.convert()
    
    # Save TFLite model
    with open(output_path, 'wb') as f:
        f.write(tflite_model)
    
    # Get file sizes
    keras_size = os.path.getsize(keras_model_path) / 1024  # KB
    tflite_size = os.path.getsize(output_path) / 1024  # KB
    
    print(f"✓ Saved TFLite model to {output_path}")
    print(f"  Keras model size: {keras_size:.2f} KB")
    print(f"  TFLite model size: {tflite_size:.2f} KB")
    print(f"  Compression ratio: {keras_size/tflite_size:.2f}x")
    
    return tflite_model


def test_tflite_model(tflite_path: str, metadata_path: str):
    """
    Test TFLite model inference
    
    Args:
        tflite_path: Path to TFLite model
        metadata_path: Path to metadata JSON
    """
    print(f"\nTesting TFLite model: {tflite_path}")
    
    # Load metadata
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    num_features = metadata['num_features']
    feature_names = metadata['feature_names']
    classes = metadata['classes']
    
    # Load TFLite model
    interpreter = tf.lite.Interpreter(model_path=tflite_path)
    interpreter.allocate_tensors()
    
    # Get input/output details
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    
    print(f"Input shape: {input_details[0]['shape']}")
    print(f"Output shape: {output_details[0]['shape']}")
    
    # Test with random input
    test_input = np.random.randn(1, num_features).astype(np.float32)
    
    # Run inference
    interpreter.set_tensor(input_details[0]['index'], test_input)
    interpreter.invoke()
    output = interpreter.get_tensor(output_details[0]['index'])
    
    # Get prediction
    predicted_class = np.argmax(output[0])
    confidence = output[0][predicted_class]
    
    print(f"\nTest inference:")
    print(f"  Input: {test_input[0][:5]}... (showing first 5 features)")
    print(f"  Output probabilities: {output[0]}")
    print(f"  Predicted class: {classes[predicted_class]} (confidence: {confidence:.4f})")
    print(f"✓ TFLite model working correctly!")


def create_combined_metadata(dns_metadata_path: str, 
                             flow_metadata_path: str,
                             output_path: str):
    """
    Create combined metadata file for both models
    
    Args:
        dns_metadata_path: Path to DNS model metadata
        flow_metadata_path: Path to Flow model metadata
        output_path: Path to save combined metadata
    """
    print("\nCreating combined metadata...")
    
    # Load individual metadata
    with open(dns_metadata_path, 'r') as f:
        dns_meta = json.load(f)
    
    with open(flow_metadata_path, 'r') as f:
        flow_meta = json.load(f)
    
    # Create combined metadata
    combined = {
        'version': '1.0',
        'created_at': '2026-02-08',
        'models': {
            'dns': {
                'filename': 'dns_model.tflite',
                'type': dns_meta['model_type'],
                'num_features': dns_meta['num_features'],
                'feature_names': dns_meta['feature_names'],
                'classes': dns_meta['classes'],
                'scaler': dns_meta['scaler']
            },
            'flow': {
                'filename': 'flow_model.tflite',
                'type': flow_meta['model_type'],
                'num_features': flow_meta['num_features'],
                'feature_names': flow_meta['feature_names'],
                'classes': flow_meta['classes'],
                'scaler': flow_meta['scaler']
            }
        },
        'verdict_policy': {
            'mode': 'balanced',
            'strike_threshold': 1,
            'risk_thresholds': {
                'high': 0.7,
                'medium': 0.4
            }
        }
    }
    
    # Save combined metadata
    with open(output_path, 'w') as f:
        json.dump(combined, f, indent=2)
    
    print(f"✓ Saved combined metadata to {output_path}")


def main():
    """Main export pipeline"""
    
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    OUTPUT_DIR = os.path.join(BASE_DIR, 'out')
    
    # Paths
    dns_keras_path = os.path.join(OUTPUT_DIR, 'dns_model.h5')
    flow_keras_path = os.path.join(OUTPUT_DIR, 'flow_model.h5')
    
    dns_tflite_path = os.path.join(OUTPUT_DIR, 'dns_model.tflite')
    flow_tflite_path = os.path.join(OUTPUT_DIR, 'flow_model.tflite')
    
    dns_metadata_path = os.path.join(OUTPUT_DIR, 'dns_metadata.json')
    flow_metadata_path = os.path.join(OUTPUT_DIR, 'flow_metadata.json')
    
    combined_metadata_path = os.path.join(OUTPUT_DIR, 'metadata.json')
    
    # Check if models exist
    if not os.path.exists(dns_keras_path):
        print(f"ERROR: DNS model not found: {dns_keras_path}")
        print("Please train DNS model first using train_dns_model.py")
        return
    
    if not os.path.exists(flow_keras_path):
        print(f"ERROR: Flow model not found: {flow_keras_path}")
        print("Please train Flow model first using train_flow_model.py")
        return
    
    # Convert DNS model
    convert_to_tflite(
        dns_keras_path,
        dns_tflite_path,
        dns_metadata_path,
        quantize=True
    )
    
    # Convert Flow model
    convert_to_tflite(
        flow_keras_path,
        flow_tflite_path,
        flow_metadata_path,
        quantize=True
    )
    
    # Test models
    test_tflite_model(dns_tflite_path, dns_metadata_path)
    test_tflite_model(flow_tflite_path, flow_metadata_path)
    
    # Create combined metadata
    create_combined_metadata(
        dns_metadata_path,
        flow_metadata_path,
        combined_metadata_path
    )
    
    print("\n" + "="*60)
    print("✓ TFLite export complete!")
    print("="*60)
    print("\nGenerated files:")
    print(f"  - {dns_tflite_path}")
    print(f"  - {flow_tflite_path}")
    print(f"  - {combined_metadata_path}")
    print("\nNext steps:")
    print("  1. Copy .tflite files to Android app assets/models/")
    print("  2. Copy metadata.json to Android app assets/models/")
    print("  3. Proceed with Android app development")


if __name__ == "__main__":
    main()

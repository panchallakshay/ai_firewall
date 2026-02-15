package com.aifirewall.ai

import android.content.Context
import android.content.res.AssetManager
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import org.json.JSONObject

/**
 * ModelManager - Loads and manages TFLite models
 * 
 * Responsibilities:
 * - Load DNS and Flow models from assets
 * - Load metadata (feature specs, scaler params)
 * - Provide model interpreters for inference
 * 
 * Why TFLite?
 * - Optimized for mobile (6.97 KB + 16.14 KB)
 * - Fast inference (<5ms per prediction)
 * - Works offline (no internet required)
 * - Low memory footprint
 */
class ModelManager(private val context: Context) {
    
    // TFLite interpreters
    private var dnsInterpreter: Interpreter? = null
    private var flowInterpreter: Interpreter? = null
    
    // Model metadata
    private var metadata: JSONObject? = null
    
    // Scaler parameters (for feature normalization)
    private var dnsScalerMean: FloatArray? = null
    private var dnsScalerScale: FloatArray? = null
    private var flowScalerMean: FloatArray? = null
    private var flowScalerScale: FloatArray? = null
    
    companion object {
        private const val DNS_MODEL_PATH = "models/dns_model.tflite"
        private const val FLOW_MODEL_PATH = "models/flow_model.tflite"
        private const val METADATA_PATH = "models/metadata.json"
        
        // Model input sizes
        const val DNS_FEATURE_COUNT = 11
        const val FLOW_FEATURE_COUNT = 15
        const val OUTPUT_CLASS_COUNT = 3  // ALLOW, WARN, BLOCK
    }
    
    /**
     * Initialize models and load metadata
     * Call this during app startup or VPN service creation
     */
    fun initialize() {
        try {
            // Load metadata first
            loadMetadata()
            
            // Load DNS model
            val dnsModel = loadModelFile(DNS_MODEL_PATH)
            dnsInterpreter = Interpreter(dnsModel, Interpreter.Options().apply {
                setNumThreads(2)  // Use 2 threads for faster inference
            })
            
            // Load Flow model
            val flowModel = loadModelFile(FLOW_MODEL_PATH)
            flowInterpreter = Interpreter(flowModel, Interpreter.Options().apply {
                setNumThreads(2)
            })
            
            // Extract scaler parameters
            extractScalerParams()
            
            android.util.Log.d("ModelManager", "Models initialized successfully")
            android.util.Log.d("ModelManager", "DNS model: $DNS_FEATURE_COUNT inputs, $OUTPUT_CLASS_COUNT outputs")
            android.util.Log.d("ModelManager", "Flow model: $FLOW_FEATURE_COUNT inputs, $OUTPUT_CLASS_COUNT outputs")
            
        } catch (e: Exception) {
            android.util.Log.e("ModelManager", "Failed to initialize models", e)
            throw e
        }
    }
    
    /**
     * Load TFLite model file from assets
     */
    private fun loadModelFile(modelPath: String): MappedByteBuffer {
        val assetFileDescriptor = context.assets.openFd(modelPath)
        val inputStream = FileInputStream(assetFileDescriptor.fileDescriptor)
        val fileChannel = inputStream.channel
        val startOffset = assetFileDescriptor.startOffset
        val declaredLength = assetFileDescriptor.declaredLength
        return fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength)
    }
    
    /**
     * Load metadata JSON from assets
     */
    private fun loadMetadata() {
        val inputStream = context.assets.open(METADATA_PATH)
        val size = inputStream.available()
        val buffer = ByteArray(size)
        inputStream.read(buffer)
        inputStream.close()
        
        val json = String(buffer, Charsets.UTF_8)
        metadata = JSONObject(json)
    }
    
    /**
     * Extract scaler parameters from metadata
     * These are used to normalize features before inference
     * 
     * Why normalize?
     * - Models were trained on normalized data (mean=0, std=1)
     * - Must apply same normalization at inference time
     * - Formula: (x - mean) / scale
     */
    private fun extractScalerParams() {
        metadata?.let { meta ->
            // DNS scaler
            val dnsScaler = meta.getJSONObject("models")
                .getJSONObject("dns")
                .getJSONObject("scaler")
            
            dnsScalerMean = jsonArrayToFloatArray(dnsScaler.getJSONArray("mean"))
            dnsScalerScale = jsonArrayToFloatArray(dnsScaler.getJSONArray("scale"))
            
            // Flow scaler
            val flowScaler = meta.getJSONObject("models")
                .getJSONObject("flow")
                .getJSONObject("scaler")
            
            flowScalerMean = jsonArrayToFloatArray(flowScaler.getJSONArray("mean"))
            flowScalerScale = jsonArrayToFloatArray(flowScaler.getJSONArray("scale"))
        }
    }
    
    /**
     * Convert JSON array to FloatArray
     */
    private fun jsonArrayToFloatArray(jsonArray: org.json.JSONArray): FloatArray {
        return FloatArray(jsonArray.length()) { i ->
            jsonArray.getDouble(i).toFloat()
        }
    }
    
    /**
     * Run DNS model inference
     * 
     * @param features 11 DNS features (unnormalized)
     * @return Array of 3 probabilities [ALLOW, WARN, BLOCK]
     */
    fun runDnsInference(features: FloatArray): FloatArray {
        require(features.size == DNS_FEATURE_COUNT) {
            "Expected $DNS_FEATURE_COUNT features, got ${features.size}"
        }
        
        // Normalize features
        val normalizedFeatures = normalizeFeatures(features, dnsScalerMean!!, dnsScalerScale!!)
        
        // Prepare input buffer
        val inputBuffer = ByteBuffer.allocateDirect(4 * DNS_FEATURE_COUNT).apply {
            order(ByteOrder.nativeOrder())
            normalizedFeatures.forEach { putFloat(it) }
            rewind()
        }
        
        // Prepare output buffer
        val outputBuffer = ByteBuffer.allocateDirect(4 * OUTPUT_CLASS_COUNT).apply {
            order(ByteOrder.nativeOrder())
        }
        
        // Run inference
        dnsInterpreter?.run(inputBuffer, outputBuffer)
        
        // Extract output probabilities
        outputBuffer.rewind()
        return FloatArray(OUTPUT_CLASS_COUNT) { outputBuffer.float }
    }
    
    /**
     * Run Flow model inference
     * 
     * @param features 15 Flow features (unnormalized)
     * @return Array of 3 probabilities [ALLOW, WARN, BLOCK]
     */
    fun runFlowInference(features: FloatArray): FloatArray {
        require(features.size == FLOW_FEATURE_COUNT) {
            "Expected $FLOW_FEATURE_COUNT features, got ${features.size}"
        }
        
        // Normalize features
        val normalizedFeatures = normalizeFeatures(features, flowScalerMean!!, flowScalerScale!!)
        
        // Prepare input buffer
        val inputBuffer = ByteBuffer.allocateDirect(4 * FLOW_FEATURE_COUNT).apply {
            order(ByteOrder.nativeOrder())
            normalizedFeatures.forEach { putFloat(it) }
            rewind()
        }
        
        // Prepare output buffer
        val outputBuffer = ByteBuffer.allocateDirect(4 * OUTPUT_CLASS_COUNT).apply {
            order(ByteOrder.nativeOrder())
        }
        
        // Run inference
        flowInterpreter?.run(inputBuffer, outputBuffer)
        
        // Extract output probabilities
        outputBuffer.rewind()
        return FloatArray(OUTPUT_CLASS_COUNT) { outputBuffer.float }
    }
    
    /**
     * Normalize features using scaler parameters
     * Formula: (x - mean) / scale
     */
    private fun normalizeFeatures(
        features: FloatArray,
        mean: FloatArray,
        scale: FloatArray
    ): FloatArray {
        return FloatArray(features.size) { i ->
            (features[i] - mean[i]) / scale[i]
        }
    }
    
    /**
     * Get metadata JSON
     */
    fun getMetadata(): JSONObject? = metadata
    
    /**
     * Clean up resources
     */
    fun close() {
        dnsInterpreter?.close()
        flowInterpreter?.close()
        dnsInterpreter = null
        flowInterpreter = null
    }
}

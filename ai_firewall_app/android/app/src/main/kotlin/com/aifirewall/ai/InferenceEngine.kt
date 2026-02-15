package com.aifirewall.ai

import com.aifirewall.telemetry.FlowStats

/**
 * InferenceEngine - Runs AI model inference and combines results
 * 
 * This is the main AI component that:
 * 1. Extracts features from network data
 * 2. Runs DNS and Flow models
 * 3. Returns predictions with confidence scores
 * 
 * Thread-safe and optimized for real-time inference (<5ms per prediction)
 */
class InferenceEngine(private val modelManager: ModelManager) {
    
    private val featureExtractor = FeatureExtractor()
    
    /**
     * Prediction result from AI models
     * 
     * @param verdict Predicted class (0=ALLOW, 1=WARN, 2=BLOCK)
     * @param confidence Confidence score (0.0 to 1.0)
     * @param probabilities Full probability distribution [ALLOW, WARN, BLOCK]
     */
    data class Prediction(
        val verdict: Verdict,
        val confidence: Float,
        val probabilities: FloatArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            
            other as Prediction
            
            if (verdict != other.verdict) return false
            if (confidence != other.confidence) return false
            if (!probabilities.contentEquals(other.probabilities)) return false
            
            return true
        }
        
        override fun hashCode(): Int {
            var result = verdict.hashCode()
            result = 31 * result + confidence.hashCode()
            result = 31 * result + probabilities.contentHashCode()
            return result
        }
    }
    
    enum class Verdict {
        ALLOW,   // Safe, allow traffic
        WARN,    // Suspicious, monitor closely
        BLOCK    // Malicious, block immediately
    }
    
    /**
     * Run DNS model inference on a domain
     * 
     * @param domain Domain name to analyze
     * @param queriesPerMin DNS queries in last minute
     * @param uniqueDomainsPerMin Unique domains queried in last minute
     * @return Prediction with verdict and confidence
     */
    fun predictDns(
        domain: String,
        queriesPerMin: Float = 0f,
        uniqueDomainsPerMin: Float = 0f
    ): Prediction {
        // Extract features
        val features = featureExtractor.extractDnsFeatures(
            domain,
            queriesPerMin,
            uniqueDomainsPerMin
        )
        
        // Run model inference
        val probabilities = modelManager.runDnsInference(features)
        
        // Get predicted class and confidence
        val predictedClass = probabilities.indices.maxByOrNull { probabilities[it] } ?: 0
        val confidence = probabilities[predictedClass]
        
        val verdict = when (predictedClass) {
            0 -> Verdict.ALLOW
            1 -> Verdict.WARN
            2 -> Verdict.BLOCK
            else -> Verdict.ALLOW
        }
        
        return Prediction(verdict, confidence, probabilities)
    }
    
    /**
     * Run Flow model inference on network flow
     * 
     * @param flowStats Flow statistics from FlowTracker
     * @param permissionCount Number of app permissions
     * @param isSystemApp Whether app is a system app
     * @return Prediction with verdict and confidence
     */
    fun predictFlow(
        flowStats: FlowStats,
        permissionCount: Int = 10,
        isSystemApp: Boolean = false
    ): Prediction {
        // Extract features
        val features = featureExtractor.extractFlowFeatures(
            flowStats,
            permissionCount,
            isSystemApp
        )
        
        // Run model inference
        val probabilities = modelManager.runFlowInference(features)
        
        // Get predicted class and confidence
        val predictedClass = probabilities.indices.maxByOrNull { probabilities[it] } ?: 0
        val confidence = probabilities[predictedClass]
        
        val verdict = when (predictedClass) {
            0 -> Verdict.ALLOW
            1 -> Verdict.WARN
            2 -> Verdict.BLOCK
            else -> Verdict.ALLOW
        }
        
        return Prediction(verdict, confidence, probabilities)
    }
    
    /**
     * Combine DNS and Flow predictions
     * 
     * Strategy:
     * - If either model says BLOCK with high confidence (>0.7), BLOCK
     * - If both models say ALLOW, ALLOW
     * - Otherwise, WARN
     * 
     * This implements "defense in depth" - both models must agree to ALLOW
     * 
     * @param dnsPrediction DNS model prediction
     * @param flowPrediction Flow model prediction
     * @return Combined prediction
     */
    fun combinePredictions(
        dnsPrediction: Prediction,
        flowPrediction: Prediction
    ): Prediction {
        // High confidence BLOCK from either model -> BLOCK
        if (dnsPrediction.verdict == Verdict.BLOCK && dnsPrediction.confidence > 0.7f) {
            return dnsPrediction
        }
        if (flowPrediction.verdict == Verdict.BLOCK && flowPrediction.confidence > 0.7f) {
            return flowPrediction
        }
        
        // Both models say ALLOW -> ALLOW
        if (dnsPrediction.verdict == Verdict.ALLOW && flowPrediction.verdict == Verdict.ALLOW) {
            val avgConfidence = (dnsPrediction.confidence + flowPrediction.confidence) / 2
            return Prediction(Verdict.ALLOW, avgConfidence, dnsPrediction.probabilities)
        }
        
        // Any other combination -> WARN
        val avgConfidence = (dnsPrediction.confidence + flowPrediction.confidence) / 2
        return Prediction(Verdict.WARN, avgConfidence, dnsPrediction.probabilities)
    }
}

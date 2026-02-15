package com.aifirewall.ai

import android.content.Context
import com.aifirewall.telemetry.FlowStats
import com.aifirewall.telemetry.PacketMetadata

/**
 * FirewallAI - Main AI firewall integration class
 * 
 * This class ties together all AI components:
 * - ModelManager: Loads TFLite models
 * - FeatureExtractor: Extracts features from network data
 * - InferenceEngine: Runs AI predictions
 * - VerdictPolicy: Applies strike system
 * - ReasonEngine: Generates explanations
 * 
 * Usage Example:
 * ```
 * val firewallAI = FirewallAI(context)
 * firewallAI.initialize()
 * 
 * // For DNS query
 * val dnsVerdict = firewallAI.evaluateDomain("example.com")
 * 
 * // For network flow
 * val flowVerdict = firewallAI.evaluateFlow(flowStats)
 * ```
 */
class FirewallAI(context: Context) {
    
    private val modelManager = ModelManager(context)
    private val inferenceEngine = InferenceEngine(modelManager)
    private val verdictPolicy = VerdictPolicy()
    private val reasonEngine = ReasonEngine()
    private val featureExtractor = FeatureExtractor()
    
    /**
     * Initialize AI firewall
     * Call this during app startup or VPN service creation
     */
    fun initialize() {
        modelManager.initialize()
        android.util.Log.i("FirewallAI", "AI Firewall initialized successfully")
    }
    
    /**
     * Evaluate a domain name
     * 
     * @param domain Domain to evaluate
     * @param queriesPerMin DNS queries in last minute
     * @param uniqueDomainsPerMin Unique domains queried in last minute
     * @param isRuleBlocked Whether domain matches blocklist
     * @return Final verdict with explanation
     */
    fun evaluateDomain(
        domain: String,
        queriesPerMin: Float = 0f,
        uniqueDomainsPerMin: Float = 0f,
        isRuleBlocked: Boolean = false
    ): EvaluationResult {
        // Extract features
        val features = featureExtractor.extractDnsFeatures(
            domain,
            queriesPerMin,
            uniqueDomainsPerMin
        )
        
        // Run AI inference
        val prediction = inferenceEngine.predictDns(
            domain,
            queriesPerMin,
            uniqueDomainsPerMin
        )
        
        // Apply verdict policy
        val flowKey = "dns:$domain"
        val verdict = verdictPolicy.applyPolicy(flowKey, prediction, isRuleBlocked)
        
        // Generate explanation
        val explanation = reasonEngine.explainDnsVerdict(
            domain,
            prediction,
            features,
            isRuleBlocked
        )
        
        return EvaluationResult(
            verdict = verdict,
            explanation = explanation,
            modelType = "DNS"
        )
    }
    
    /**
     * Evaluate a network flow
     * 
     * @param flowStats Flow statistics from FlowTracker
     * @param permissionCount Number of app permissions
     * @param isSystemApp Whether app is a system app
     * @return Final verdict with explanation
     */
    fun evaluateFlow(
        flowStats: FlowStats,
        permissionCount: Int = 10,
        isSystemApp: Boolean = false
    ): EvaluationResult {
        // Extract features
        val features = featureExtractor.extractFlowFeatures(
            flowStats,
            permissionCount,
            isSystemApp
        )
        
        // Run AI inference
        val prediction = inferenceEngine.predictFlow(
            flowStats,
            permissionCount,
            isSystemApp
        )
        
        // Apply verdict policy
        val verdict = verdictPolicy.applyPolicy(flowStats.flowKey, prediction)
        
        // Generate explanation
        val explanation = reasonEngine.explainFlowVerdict(
            flowStats,
            prediction,
            features
        )
        
        return EvaluationResult(
            verdict = verdict,
            explanation = explanation,
            modelType = "Flow"
        )
    }
    
    /**
     * Evaluate both DNS and Flow (combined verdict)
     * 
     * @param domain Domain name
     * @param flowStats Flow statistics
     * @return Combined verdict
     */
    fun evaluateCombined(
        domain: String,
        flowStats: FlowStats,
        queriesPerMin: Float = 0f,
        uniqueDomainsPerMin: Float = 0f,
        permissionCount: Int = 10,
        isSystemApp: Boolean = false,
        isRuleBlocked: Boolean = false
    ): EvaluationResult {
        // Get DNS prediction
        val dnsPrediction = inferenceEngine.predictDns(
            domain,
            queriesPerMin,
            uniqueDomainsPerMin
        )
        
        // Get Flow prediction
        val flowPrediction = inferenceEngine.predictFlow(
            flowStats,
            permissionCount,
            isSystemApp
        )
        
        // Combine predictions
        val combinedPrediction = inferenceEngine.combinePredictions(
            dnsPrediction,
            flowPrediction
        )
        
        // Apply verdict policy
        val verdict = verdictPolicy.applyPolicy(
            flowStats.flowKey,
            combinedPrediction,
            isRuleBlocked
        )
        
        // Generate combined explanation
        val dnsFeatures = featureExtractor.extractDnsFeatures(
            domain,
            queriesPerMin,
            uniqueDomainsPerMin
        )
        val dnsExplanation = reasonEngine.explainDnsVerdict(
            domain,
            dnsPrediction,
            dnsFeatures,
            isRuleBlocked
        )
        
        val flowFeatures = featureExtractor.extractFlowFeatures(
            flowStats,
            permissionCount,
            isSystemApp
        )
        val flowExplanation = reasonEngine.explainFlowVerdict(
            flowStats,
            flowPrediction,
            flowFeatures
        )
        
        // Merge explanations
        val mergedExplanation = ReasonEngine.Explanation(
            summary = verdict.reason,
            ruleReasons = dnsExplanation.ruleReasons + flowExplanation.ruleReasons,
            behaviorEvidence = dnsExplanation.behaviorEvidence + flowExplanation.behaviorEvidence,
            aiEvidence = dnsExplanation.aiEvidence + flowExplanation.aiEvidence,
            confidence = "DNS: ${dnsExplanation.confidence}, Flow: ${flowExplanation.confidence}",
            recommendation = verdict.reason
        )
        
        return EvaluationResult(
            verdict = verdict,
            explanation = mergedExplanation,
            modelType = "Combined (DNS + Flow)"
        )
    }
    
    /**
     * Set policy mode
     */
    fun setPolicyMode(mode: VerdictPolicy.Mode) {
        verdictPolicy.setMode(mode)
    }
    
    /**
     * Get current policy mode
     */
    fun getPolicyMode(): VerdictPolicy.Mode {
        return verdictPolicy.getMode()
    }
    
    /**
     * Reset strikes for a flow (user override)
     */
    fun resetStrikes(flowKey: String) {
        verdictPolicy.resetStrikes(flowKey)
    }
    
    /**
     * Get strike count for a flow
     */
    fun getStrikes(flowKey: String): Int {
        return verdictPolicy.getStrikes(flowKey)
    }
    
    /**
     * Cleanup old entries (call periodically)
     */
    fun cleanup() {
        verdictPolicy.cleanup()
    }
    
    /**
     * Shutdown AI firewall
     */
    fun shutdown() {
        modelManager.close()
    }
    
    /**
     * Evaluation result
     */
    data class EvaluationResult(
        val verdict: VerdictPolicy.FinalVerdict,
        val explanation: ReasonEngine.Explanation,
        val modelType: String
    ) {
        /**
         * Get formatted explanation text
         */
        fun getFormattedExplanation(): String {
            return ReasonEngine().formatExplanation(explanation)
        }
        
        /**
         * Should block this traffic?
         */
        fun shouldBlock(): Boolean {
            return verdict.action == VerdictPolicy.Action.BLOCK_SOFT ||
                   verdict.action == VerdictPolicy.Action.BLOCK_HARD
        }
        
        /**
         * Should show warning?
         */
        fun shouldWarn(): Boolean {
            return verdict.action == VerdictPolicy.Action.WARN
        }
        
        /**
         * Can user override?
         */
        fun canOverride(): Boolean {
            return verdict.allowUserOverride
        }
    }
}

package com.aifirewall.ai

import com.aifirewall.telemetry.FlowStats
import com.aifirewall.telemetry.Protocol

/**
 * ReasonEngine - Generates human-readable explanations for firewall decisions
 * 
 * Why Explainability?
 * - Users need to understand WHY traffic was blocked
 * - Builds trust in AI decisions
 * - Helps identify false positives
 * - Required for compliance (GDPR, etc.)
 * 
 * Explanation Components:
 * 1. Rule-based reasons (blocklist matches)
 * 2. Behavioral evidence (AI features)
 * 3. AI confidence scores
 * 4. Recommended actions
 */
class ReasonEngine {
    
    /**
     * Complete explanation for a verdict
     */
    data class Explanation(
        val summary: String,                    // One-line summary
        val ruleReasons: List<String>,          // Blocklist rule matches
        val behaviorEvidence: List<String>,     // Suspicious behaviors detected
        val aiEvidence: List<String>,           // AI model insights
        val confidence: String,                 // Confidence level
        val recommendation: String              // What user should do
    )
    
    /**
     * Generate explanation for DNS verdict
     * 
     * @param domain Domain name
     * @param prediction AI prediction
     * @param features Extracted features
     * @param isRuleBlocked Whether blocklist matched
     * @return Human-readable explanation
     */
    fun explainDnsVerdict(
        domain: String,
        prediction: InferenceEngine.Prediction,
        features: FloatArray,
        isRuleBlocked: Boolean = false
    ): Explanation {
        val ruleReasons = mutableListOf<String>()
        val behaviorEvidence = mutableListOf<String>()
        val aiEvidence = mutableListOf<String>()
        
        // Rule-based reasons
        if (isRuleBlocked) {
            ruleReasons.add("Domain '$domain' is on the blocklist")
        }
        
        // Analyze features for behavioral evidence
        // Feature indices: [length, entropy, tld_risk, digit_ratio, vowel_ratio, 
        //                   max_consec_consonants, subdomain_count, special_chars,
        //                   queries_per_min, unique_domains_per_min, burst_pattern]
        
        if (features[1] > 3.5f) {  // High entropy
            behaviorEvidence.add("Domain has high randomness (${String.format("%.2f", features[1])}), typical of DGA malware")
        }
        
        if (features[2] > 0.5f) {  // High-risk TLD
            behaviorEvidence.add("Domain uses high-risk TLD commonly abused by attackers")
        }
        
        if (features[3] > 0.3f) {  // High digit ratio
            behaviorEvidence.add("Domain contains many digits (${(features[3] * 100).toInt()}%), unusual for legitimate sites")
        }
        
        if (features[4] < 0.2f) {  // Low vowel ratio
            behaviorEvidence.add("Domain has few vowels, making it unpronounceable (DGA indicator)")
        }
        
        if (features[5] > 5f) {  // Many consecutive consonants
            behaviorEvidence.add("Domain has ${features[5].toInt()} consecutive consonants, typical of random generation")
        }
        
        if (features[8] > 20f) {  // High query rate
            behaviorEvidence.add("Excessive DNS queries (${features[8].toInt()}/min), possible C&C communication")
        }
        
        if (features[10] > 0.5f) {  // Burst pattern
            behaviorEvidence.add("Burst pattern detected: many queries to many domains quickly")
        }
        
        // AI evidence
        val allowProb = prediction.probabilities[0]
        val warnProb = prediction.probabilities[1]
        val blockProb = prediction.probabilities[2]
        
        when (prediction.verdict) {
            InferenceEngine.Verdict.BLOCK -> {
                aiEvidence.add("AI model is ${(blockProb * 100).toInt()}% confident this is malicious")
                if (blockProb > 0.9f) {
                    aiEvidence.add("Very high confidence - strong threat indicators present")
                }
            }
            InferenceEngine.Verdict.WARN -> {
                aiEvidence.add("AI model detected suspicious patterns (${(warnProb * 100).toInt()}% confidence)")
                aiEvidence.add("Not enough evidence for definitive block, monitoring recommended")
            }
            InferenceEngine.Verdict.ALLOW -> {
                aiEvidence.add("AI model is ${(allowProb * 100).toInt()}% confident this is safe")
            }
        }
        
        // Generate summary
        val summary = when {
            isRuleBlocked -> "Blocked: Domain on blocklist"
            prediction.verdict == InferenceEngine.Verdict.BLOCK -> 
                "Blocked: AI detected malicious domain (${(blockProb * 100).toInt()}% confidence)"
            prediction.verdict == InferenceEngine.Verdict.WARN -> 
                "Warning: Suspicious domain detected"
            else -> "Allowed: Domain appears safe"
        }
        
        // Confidence level
        val confidence = when {
            prediction.confidence > 0.9f -> "Very High (${(prediction.confidence * 100).toInt()}%)"
            prediction.confidence > 0.7f -> "High (${(prediction.confidence * 100).toInt()}%)"
            prediction.confidence > 0.5f -> "Medium (${(prediction.confidence * 100).toInt()}%)"
            else -> "Low (${(prediction.confidence * 100).toInt()}%)"
        }
        
        // Recommendation
        val recommendation = when (prediction.verdict) {
            InferenceEngine.Verdict.BLOCK -> 
                "Block this domain. If you believe this is a false positive, you can override."
            InferenceEngine.Verdict.WARN -> 
                "Monitor this domain. If it continues suspicious behavior, it will be blocked."
            InferenceEngine.Verdict.ALLOW -> 
                "This domain is safe to access."
        }
        
        return Explanation(
            summary = summary,
            ruleReasons = ruleReasons,
            behaviorEvidence = behaviorEvidence,
            aiEvidence = aiEvidence,
            confidence = confidence,
            recommendation = recommendation
        )
    }
    
    /**
     * Generate explanation for Flow verdict
     * 
     * @param flowStats Flow statistics
     * @param prediction AI prediction
     * @param features Extracted features
     * @return Human-readable explanation
     */
    fun explainFlowVerdict(
        flowStats: FlowStats,
        prediction: InferenceEngine.Prediction,
        features: FloatArray
    ): Explanation {
        val ruleReasons = mutableListOf<String>()
        val behaviorEvidence = mutableListOf<String>()
        val aiEvidence = mutableListOf<String>()
        
        // Analyze features for behavioral evidence
        // Feature indices: [packets_per_sec, bytes_per_sec, upload_download_ratio,
        //                   avg_packet_size, duration, failure_rate,
        //                   new_connections_per_min, unique_dests_per_min,
        //                   protocol, port_risk, dst_ip_risk, permission_count,
        //                   system_app, connection_burst, scanning_pattern]
        
        if (features[0] > 100f) {  // High packet rate
            behaviorEvidence.add("Very high packet rate (${features[0].toInt()} pps), possible DDoS attack")
        }
        
        if (features[2] > 10f || features[2] < 0.1f) {  // Unusual upload/download ratio
            behaviorEvidence.add("Unusual upload/download ratio (${String.format("%.2f", features[2])})")
        }
        
        if (features[5] > 0.5f) {  // High failure rate
            behaviorEvidence.add("High connection failure rate (${(features[5] * 100).toInt()}%), possible scanning")
        }
        
        if (features[6] > 50f) {  // Many new connections
            behaviorEvidence.add("Excessive new connections (${features[6].toInt()}/min), possible flood attack")
        }
        
        if (features[7] > 20f) {  // Many unique destinations
            behaviorEvidence.add("Connecting to many destinations (${features[7].toInt()}/min), possible port scan")
        }
        
        if (features[9] > 0.5f) {  // High-risk port
            behaviorEvidence.add("Connection to high-risk port (${flowStats.dstPort})")
        }
        
        if (features[13] > 0.5f) {  // Connection burst
            behaviorEvidence.add("Connection burst detected: rapid connection attempts")
        }
        
        if (features[14] > 0.5f) {  // Scanning pattern
            behaviorEvidence.add("Port scanning pattern detected")
        }
        
        // AI evidence
        val allowProb = prediction.probabilities[0]
        val warnProb = prediction.probabilities[1]
        val blockProb = prediction.probabilities[2]
        
        when (prediction.verdict) {
            InferenceEngine.Verdict.BLOCK -> {
                aiEvidence.add("AI model is ${(blockProb * 100).toInt()}% confident this is an attack")
                if (blockProb > 0.9f) {
                    aiEvidence.add("Attack signature matches known DDoS/scanning patterns")
                }
            }
            InferenceEngine.Verdict.WARN -> {
                aiEvidence.add("AI model detected anomalous behavior (${(warnProb * 100).toInt()}% confidence)")
            }
            InferenceEngine.Verdict.ALLOW -> {
                aiEvidence.add("AI model is ${(allowProb * 100).toInt()}% confident this is normal traffic")
            }
        }
        
        // Generate summary
        val summary = when (prediction.verdict) {
            InferenceEngine.Verdict.BLOCK -> 
                "Blocked: Attack detected (${(blockProb * 100).toInt()}% confidence)"
            InferenceEngine.Verdict.WARN -> 
                "Warning: Anomalous network behavior"
            InferenceEngine.Verdict.ALLOW -> 
                "Allowed: Normal network traffic"
        }
        
        // Confidence level
        val confidence = when {
            prediction.confidence > 0.9f -> "Very High (${(prediction.confidence * 100).toInt()}%)"
            prediction.confidence > 0.7f -> "High (${(prediction.confidence * 100).toInt()}%)"
            prediction.confidence > 0.5f -> "Medium (${(prediction.confidence * 100).toInt()}%)"
            else -> "Low (${(prediction.confidence * 100).toInt()}%)"
        }
        
        // Recommendation
        val recommendation = when (prediction.verdict) {
            InferenceEngine.Verdict.BLOCK -> 
                "Block this connection. If this is a legitimate app, check for malware."
            InferenceEngine.Verdict.WARN -> 
                "Monitor this connection. Repeated warnings will result in blocking."
            InferenceEngine.Verdict.ALLOW -> 
                "This connection is safe."
        }
        
        return Explanation(
            summary = summary,
            ruleReasons = ruleReasons,
            behaviorEvidence = behaviorEvidence,
            aiEvidence = aiEvidence,
            confidence = confidence,
            recommendation = recommendation
        )
    }
    
    /**
     * Format explanation as user-friendly text
     */
    fun formatExplanation(explanation: Explanation): String {
        val sb = StringBuilder()
        
        sb.appendLine(explanation.summary)
        sb.appendLine()
        
        if (explanation.ruleReasons.isNotEmpty()) {
            sb.appendLine("📋 Rule Matches:")
            explanation.ruleReasons.forEach { sb.appendLine("  • $it") }
            sb.appendLine()
        }
        
        if (explanation.behaviorEvidence.isNotEmpty()) {
            sb.appendLine("🔍 Suspicious Behaviors:")
            explanation.behaviorEvidence.forEach { sb.appendLine("  • $it") }
            sb.appendLine()
        }
        
        if (explanation.aiEvidence.isNotEmpty()) {
            sb.appendLine("🤖 AI Analysis:")
            explanation.aiEvidence.forEach { sb.appendLine("  • $it") }
            sb.appendLine()
        }
        
        sb.appendLine("📊 Confidence: ${explanation.confidence}")
        sb.appendLine()
        sb.appendLine("💡 Recommendation: ${explanation.recommendation}")
        
        return sb.toString()
    }
}

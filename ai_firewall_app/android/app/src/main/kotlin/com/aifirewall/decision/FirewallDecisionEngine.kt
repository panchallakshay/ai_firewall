package com.aifirewall.decision

import android.content.Context
import com.aifirewall.ai.FirewallAI
import com.aifirewall.ai.VerdictPolicy
import com.aifirewall.ai.ReasonEngine
import com.aifirewall.rules.BlocklistManager
import com.aifirewall.rules.RuleEngine
import com.aifirewall.telemetry.FlowStats

/**
 * FirewallDecisionEngine - Combines Rules + AI for final verdict
 * 
 * Decision Hierarchy:
 * 1. CRITICAL rules (blocklists) → Immediate BLOCK
 * 2. HIGH severity rules → BLOCK
 * 3. AI predictions → ALLOW/WARN/BLOCK with strike system
 * 4. MEDIUM/LOW rules → WARN
 * 
 * Why This Hierarchy?
 * - Known threats (blocklists) blocked immediately
 * - Deterministic rules catch obvious attacks
 * - AI handles novel/subtle threats
 * - Low-severity rules provide warnings only
 * 
 * This implements "defense in depth" - multiple layers of protection
 */
class FirewallDecisionEngine(context: Context) {
    
    private val firewallAI = FirewallAI(context)
    private val blocklistManager = BlocklistManager(context)
    private val ruleEngine = RuleEngine(blocklistManager)
    
    /**
     * Final firewall decision
     */
    data class FirewallDecision(
        val action: Action,
        val reason: String,
        val ruleMatches: List<RuleEngine.RuleMatch>,
        val aiVerdict: VerdictPolicy.FinalVerdict?,
        val aiExplanation: ReasonEngine.Explanation?,
        val confidence: Float,
        val allowUserOverride: Boolean
    ) {
        /**
         * Should block this traffic?
         */
        fun shouldBlock(): Boolean {
            return action == Action.BLOCK_HARD || action == Action.BLOCK_SOFT
        }
        
        /**
         * Should show warning?
         */
        fun shouldWarn(): Boolean {
            return action == Action.WARN
        }
        
        /**
         * Get formatted explanation
         */
        fun getFormattedExplanation(): String {
            val sb = StringBuilder()
            
            sb.appendLine("🛡️ Firewall Decision: ${action.name}")
            sb.appendLine()
            sb.appendLine("📋 Summary: $reason")
            sb.appendLine()
            
            if (ruleMatches.isNotEmpty()) {
                sb.appendLine("⚠️ Rule Matches (${ruleMatches.size}):")
                ruleMatches.forEach { match ->
                    sb.appendLine("  • [${match.severity}] ${match.rule.name}: ${match.reason}")
                }
                sb.appendLine()
            }
            
            if (aiExplanation != null) {
                sb.appendLine("🤖 AI Analysis:")
                if (aiExplanation.behaviorEvidence.isNotEmpty()) {
                    aiExplanation.behaviorEvidence.forEach { sb.appendLine("  • $it") }
                }
                if (aiExplanation.aiEvidence.isNotEmpty()) {
                    aiExplanation.aiEvidence.forEach { sb.appendLine("  • $it") }
                }
                sb.appendLine()
            }
            
            sb.appendLine("📊 Confidence: ${(confidence * 100).toInt()}%")
            
            if (allowUserOverride) {
                sb.appendLine()
                sb.appendLine("💡 You can override this decision if you believe it's incorrect.")
            }
            
            return sb.toString()
        }
    }
    
    enum class Action {
        ALLOW,          // Allow traffic
        WARN,           // Allow but show warning
        BLOCK_SOFT,     // Block but allow user override
        BLOCK_HARD      // Block without override
    }
    
    /**
     * Initialize firewall decision engine
     */
    fun initialize() {
        firewallAI.initialize()
        blocklistManager.loadBlocklists()
        android.util.Log.i("FirewallDecisionEngine", "Firewall decision engine initialized")
    }
    
    /**
     * Evaluate a connection and make final decision
     * 
     * @param domain Optional domain name
     * @param flowStats Flow statistics
     * @param dstIp Destination IP
     * @param permissionCount App permission count
     * @param isSystemApp Whether app is a system app
     * @return Final firewall decision
     */
    fun evaluate(
        domain: String? = null,
        flowStats: FlowStats,
        dstIp: String,
        permissionCount: Int = 10,
        isSystemApp: Boolean = false
    ): FirewallDecision {
        // Step 1: Check rules (blocklists + thresholds)
        val ruleMatches = ruleEngine.evaluateFlow(flowStats, domain, dstIp)
        val highestSeverity = ruleEngine.getHighestSeverity(ruleMatches)
        
        // Step 2: CRITICAL rules → Immediate BLOCK_HARD
        if (ruleEngine.hasCriticalMatch(ruleMatches)) {
            val criticalMatch = ruleMatches.first { it.severity == RuleEngine.Severity.CRITICAL }
            return FirewallDecision(
                action = Action.BLOCK_HARD,
                reason = criticalMatch.reason,
                ruleMatches = ruleMatches,
                aiVerdict = null,
                aiExplanation = null,
                confidence = 1.0f,
                allowUserOverride = false
            )
        }
        
        // Step 3: HIGH severity rules → BLOCK_SOFT
        if (highestSeverity == RuleEngine.Severity.HIGH) {
            val highMatch = ruleMatches.first { it.severity == RuleEngine.Severity.HIGH }
            return FirewallDecision(
                action = Action.BLOCK_SOFT,
                reason = highMatch.reason,
                ruleMatches = ruleMatches,
                aiVerdict = null,
                aiExplanation = null,
                confidence = 0.9f,
                allowUserOverride = true
            )
        }
        
        // Step 4: Run AI evaluation
        val aiResult = if (domain != null) {
            // Evaluate both DNS and Flow
            firewallAI.evaluateCombined(
                domain = domain,
                flowStats = flowStats,
                permissionCount = permissionCount,
                isSystemApp = isSystemApp
            )
        } else {
            // Evaluate Flow only
            firewallAI.evaluateFlow(flowStats, permissionCount, isSystemApp)
        }
        
        // Step 5: Combine AI verdict with rule matches
        val finalAction = when (aiResult.verdict.action) {
            VerdictPolicy.Action.BLOCK_HARD -> Action.BLOCK_HARD
            VerdictPolicy.Action.BLOCK_SOFT -> Action.BLOCK_SOFT
            VerdictPolicy.Action.WARN -> {
                // If we have MEDIUM severity rules, escalate to BLOCK_SOFT
                if (highestSeverity == RuleEngine.Severity.MEDIUM) {
                    Action.BLOCK_SOFT
                } else {
                    Action.WARN
                }
            }
            VerdictPolicy.Action.ALLOW -> {
                // If we have any rule matches, show warning
                if (ruleMatches.isNotEmpty()) {
                    Action.WARN
                } else {
                    Action.ALLOW
                }
            }
        }
        
        // Step 6: Generate combined reason
        val reason = when {
            ruleMatches.isNotEmpty() && aiResult.verdict.action != VerdictPolicy.Action.ALLOW -> {
                "Rules + AI detected threat: ${aiResult.verdict.reason}"
            }
            ruleMatches.isNotEmpty() -> {
                "Rule triggered: ${ruleMatches.first().reason}"
            }
            else -> aiResult.verdict.reason
        }
        
        return FirewallDecision(
            action = finalAction,
            reason = reason,
            ruleMatches = ruleMatches,
            aiVerdict = aiResult.verdict,
            aiExplanation = aiResult.explanation,
            confidence = aiResult.verdict.confidence,
            allowUserOverride = aiResult.verdict.allowUserOverride && finalAction != Action.BLOCK_HARD
        )
    }
    
    /**
     * Set AI policy mode
     */
    fun setPolicyMode(mode: VerdictPolicy.Mode) {
        firewallAI.setPolicyMode(mode)
    }
    
    /**
     * Get current policy mode
     */
    fun getPolicyMode(): VerdictPolicy.Mode {
        return firewallAI.getPolicyMode()
    }
    
    /**
     * Reset strikes for a flow (user override)
     */
    fun resetStrikes(flowKey: String) {
        firewallAI.resetStrikes(flowKey)
    }
    
    /**
     * Get strike count for a flow
     */
    fun getStrikes(flowKey: String): Int {
        return firewallAI.getStrikes(flowKey)
    }
    
    /**
     * Add domain to blocklist (runtime)
     */
    fun addDomainToBlocklist(domain: String) {
        blocklistManager.addDomain(domain)
    }
    
    /**
     * Remove domain from blocklist (runtime)
     */
    fun removeDomainFromBlocklist(domain: String) {
        blocklistManager.removeDomain(domain)
    }
    
    /**
     * Get blocklist statistics
     */
    fun getBlocklistStats() = blocklistManager.getStats()
    
    /**
     * Cleanup (call periodically)
     */
    fun cleanup() {
        firewallAI.cleanup()
    }
    
    /**
     * Shutdown
     */
    fun shutdown() {
        firewallAI.shutdown()
    }
}

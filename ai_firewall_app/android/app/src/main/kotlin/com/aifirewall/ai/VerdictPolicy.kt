package com.aifirewall.ai

import com.aifirewall.telemetry.FlowStats
import java.util.concurrent.ConcurrentHashMap

/**
 * VerdictPolicy - Implements strike-based verdict system
 * 
 * Why Strike System?
 * - Reduces false positives (single WARN doesn't block)
 * - Gives benefit of doubt to legitimate traffic
 * - Escalates repeated suspicious behavior
 * - User-configurable sensitivity
 * 
 * Strike Accumulation:
 * - ALLOW: No strikes
 * - WARN: +1 strike
 * - BLOCK: +3 strikes (immediate block if high confidence)
 * 
 * Strike Decay:
 * - Strikes decay over time (1 strike per 5 minutes)
 * - Clean behavior resets strikes
 * 
 * Modes:
 * - STRICT: 1 strike = block (high security)
 * - BALANCED: 3 strikes = block (recommended)
 * - PERMISSIVE: 5 strikes = block (low false positives)
 */
class VerdictPolicy {
    
    /**
     * Policy mode (user-configurable)
     */
    enum class Mode {
        STRICT,      // 1 strike threshold
        BALANCED,    // 3 strike threshold (default)
        PERMISSIVE   // 5 strike threshold
    }
    
    /**
     * Final verdict after applying policy
     */
    data class FinalVerdict(
        val action: Action,
        val reason: String,
        val strikes: Int,
        val confidence: Float,
        val allowUserOverride: Boolean
    )
    
    enum class Action {
        ALLOW,          // Allow traffic
        WARN,           // Allow but show warning
        BLOCK_SOFT,     // Block but allow user override
        BLOCK_HARD      // Block without override (high confidence threat)
    }
    
    // Strike tracking (per flow key)
    private val strikeMap = ConcurrentHashMap<String, StrikeRecord>()
    
    // Current policy mode
    private var mode = Mode.BALANCED
    
    // Strike thresholds
    private val strikeThresholds = mapOf(
        Mode.STRICT to 1,
        Mode.BALANCED to 3,
        Mode.PERMISSIVE to 5
    )
    
    /**
     * Strike record for a flow
     */
    private data class StrikeRecord(
        var strikes: Int,
        var lastUpdateTime: Long,
        var consecutiveAllows: Int
    )
    
    /**
     * Apply verdict policy to AI prediction
     * 
     * @param flowKey Unique flow identifier
     * @param prediction AI model prediction
     * @param isRuleBlocked Whether blocklist rule matched
     * @return Final verdict with action
     */
    fun applyPolicy(
        flowKey: String,
        prediction: InferenceEngine.Prediction,
        isRuleBlocked: Boolean = false
    ): FinalVerdict {
        // Rule-based block always takes precedence
        if (isRuleBlocked) {
            return FinalVerdict(
                action = Action.BLOCK_HARD,
                reason = "Matched blocklist rule",
                strikes = 0,
                confidence = 1.0f,
                allowUserOverride = false
            )
        }
        
        // Get or create strike record
        val record = strikeMap.getOrPut(flowKey) {
            StrikeRecord(strikes = 0, lastUpdateTime = System.currentTimeMillis(), consecutiveAllows = 0)
        }
        
        // Decay strikes over time (1 strike per 5 minutes)
        decayStrikes(record)
        
        // Update strikes based on prediction
        when (prediction.verdict) {
            InferenceEngine.Verdict.ALLOW -> {
                record.consecutiveAllows++
                // Reset strikes after 10 consecutive allows
                if (record.consecutiveAllows >= 10) {
                    record.strikes = 0
                    record.consecutiveAllows = 0
                }
            }
            InferenceEngine.Verdict.WARN -> {
                record.strikes += 1
                record.consecutiveAllows = 0
            }
            InferenceEngine.Verdict.BLOCK -> {
                // High confidence block -> immediate hard block
                if (prediction.confidence > 0.9f) {
                    return FinalVerdict(
                        action = Action.BLOCK_HARD,
                        reason = "High confidence threat detected (${(prediction.confidence * 100).toInt()}%)",
                        strikes = record.strikes + 3,
                        confidence = prediction.confidence,
                        allowUserOverride = false
                    )
                }
                record.strikes += 3
                record.consecutiveAllows = 0
            }
        }
        
        record.lastUpdateTime = System.currentTimeMillis()
        
        // Determine final action based on strikes
        val threshold = strikeThresholds[mode] ?: 3
        
        return when {
            record.strikes >= threshold -> {
                FinalVerdict(
                    action = Action.BLOCK_SOFT,
                    reason = "Strike threshold reached (${record.strikes}/$threshold)",
                    strikes = record.strikes,
                    confidence = prediction.confidence,
                    allowUserOverride = true
                )
            }
            record.strikes > 0 -> {
                FinalVerdict(
                    action = Action.WARN,
                    reason = "Suspicious behavior detected (${record.strikes}/$threshold strikes)",
                    strikes = record.strikes,
                    confidence = prediction.confidence,
                    allowUserOverride = true
                )
            }
            else -> {
                FinalVerdict(
                    action = Action.ALLOW,
                    reason = "Normal behavior",
                    strikes = 0,
                    confidence = prediction.confidence,
                    allowUserOverride = false
                )
            }
        }
    }
    
    /**
     * Decay strikes over time
     * 1 strike decays every 5 minutes
     */
    private fun decayStrikes(record: StrikeRecord) {
        val now = System.currentTimeMillis()
        val elapsedMinutes = (now - record.lastUpdateTime) / (60 * 1000)
        
        if (elapsedMinutes >= 5) {
            val strikesToDecay = (elapsedMinutes / 5).toInt()
            record.strikes = maxOf(0, record.strikes - strikesToDecay)
            record.lastUpdateTime = now
        }
    }
    
    /**
     * Set policy mode
     */
    fun setMode(newMode: Mode) {
        mode = newMode
    }
    
    /**
     * Get current mode
     */
    fun getMode(): Mode = mode
    
    /**
     * Get strike count for a flow
     */
    fun getStrikes(flowKey: String): Int {
        return strikeMap[flowKey]?.strikes ?: 0
    }
    
    /**
     * Reset strikes for a flow (user override)
     */
    fun resetStrikes(flowKey: String) {
        strikeMap[flowKey]?.let {
            it.strikes = 0
            it.consecutiveAllows = 0
        }
    }
    
    /**
     * Clear all strikes (reset firewall)
     */
    fun clearAllStrikes() {
        strikeMap.clear()
    }
    
    /**
     * Cleanup old entries (call periodically)
     */
    fun cleanup() {
        val now = System.currentTimeMillis()
        val cutoff = now - (30 * 60 * 1000)  // 30 minutes
        
        strikeMap.entries.removeIf { (_, record) ->
            record.lastUpdateTime < cutoff && record.strikes == 0
        }
    }
}

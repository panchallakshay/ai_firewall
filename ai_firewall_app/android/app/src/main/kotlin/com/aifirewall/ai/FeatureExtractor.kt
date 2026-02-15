package com.aifirewall.ai

import com.aifirewall.telemetry.PacketMetadata
import com.aifirewall.telemetry.FlowStats
import kotlin.math.log2
import kotlin.math.max

/**
 * FeatureExtractor - Extracts features from DNS queries and network flows
 * 
 * This class mirrors the Python feature extraction used during training.
 * CRITICAL: Features must be extracted EXACTLY the same way as training!
 * 
 * DNS Features (11 total):
 * 1. Domain length
 * 2. Entropy (randomness measure)
 * 3. TLD risk score
 * 4. Digit ratio
 * 5. Vowel ratio
 * 6. Consecutive consonants
 * 7. Subdomain count
 * 8. Special character count
 * 9. Queries per minute
 * 10. Unique domains per minute
 * 11. Burst pattern
 * 
 * Flow Features (15 total):
 * 1-11. Network behavior metrics
 * 12-15. App-level metrics
 */
class FeatureExtractor {
    
    companion object {
        // High-risk TLDs (commonly abused)
        private val HIGH_RISK_TLDS = setOf(
            "tk", "ml", "ga", "cf", "gq",  // Free TLDs
            "top", "xyz", "club", "work",   // Cheap TLDs
            "ru", "cn"                       // Often abused
        )
        
        // Medium-risk TLDs
        private val MEDIUM_RISK_TLDS = setOf(
            "info", "biz", "cc", "ws", "to"
        )
        
        private val VOWELS = setOf('a', 'e', 'i', 'o', 'u')
    }
    
    /**
     * Extract DNS features from domain name
     * 
     * @param domain Domain name (e.g., "example.com")
     * @param queriesPerMin Number of DNS queries in last minute
     * @param uniqueDomainsPerMin Number of unique domains queried in last minute
     * @return FloatArray of 11 features
     */
    fun extractDnsFeatures(
        domain: String,
        queriesPerMin: Float,
        uniqueDomainsPerMin: Float
    ): FloatArray {
        val domainLower = domain.lowercase()
        
        // 1. Domain length
        val domainLength = domainLower.length.toFloat()
        
        // 2. Entropy (randomness measure)
        val entropy = calculateEntropy(domainLower)
        
        // 3. TLD risk score
        val tld = extractTld(domainLower)
        val tldRisk = when {
            HIGH_RISK_TLDS.contains(tld) -> 1.0f
            MEDIUM_RISK_TLDS.contains(tld) -> 0.5f
            else -> 0.0f
        }
        
        // 4. Digit ratio
        val digitCount = domainLower.count { it.isDigit() }
        val digitRatio = digitCount.toFloat() / domainLength
        
        // 5. Vowel ratio
        val vowelCount = domainLower.count { VOWELS.contains(it) }
        val vowelRatio = vowelCount.toFloat() / domainLength
        
        // 6. Max consecutive consonants
        val maxConsecutiveConsonants = findMaxConsecutiveConsonants(domainLower).toFloat()
        
        // 7. Subdomain count
        val subdomainCount = domainLower.count { it == '.' }.toFloat()
        
        // 8. Special character count (excluding dots)
        val specialCharCount = domainLower.count { 
            !it.isLetterOrDigit() && it != '.'
        }.toFloat()
        
        // 9. Queries per minute (temporal pattern)
        val queriesPerMinFeature = queriesPerMin
        
        // 10. Unique domains per minute (diversity)
        val uniqueDomainsPerMinFeature = uniqueDomainsPerMin
        
        // 11. Burst pattern (high queries + high diversity = suspicious)
        val burstPattern = if (queriesPerMin > 10 && uniqueDomainsPerMin > 5) 1.0f else 0.0f
        
        return floatArrayOf(
            domainLength,
            entropy,
            tldRisk,
            digitRatio,
            vowelRatio,
            maxConsecutiveConsonants,
            subdomainCount,
            specialCharCount,
            queriesPerMinFeature,
            uniqueDomainsPerMinFeature,
            burstPattern
        )
    }
    
    /**
     * Extract Flow features from network statistics
     * 
     * @param flowStats Flow statistics from FlowTracker
     * @param permissionCount Number of app permissions
     * @param isSystemApp Whether app is a system app
     * @return FloatArray of 15 features
     */
    fun extractFlowFeatures(
        flowStats: FlowStats,
        permissionCount: Int,
        isSystemApp: Boolean
    ): FloatArray {
        // 1. Packets per second
        val packetsPerSec = flowStats.getPacketsPerSec()
        
        // 2. Bytes per second
        val bytesPerSec = flowStats.getBytesPerSec()
        
        // 3. Upload/download ratio
        val uploadDownloadRatio = flowStats.getUploadDownloadRatio()
        
        // 4. Average packet size
        val avgPacketSize = if (flowStats.packetCount > 0) {
            flowStats.byteCount.toFloat() / flowStats.packetCount
        } else 0f
        
        // 5. Connection duration (seconds)
        val durationSec = (flowStats.lastSeenTime - flowStats.startTime) / 1000f
        
        // 6. Failure rate
        val failureRate = if (flowStats.packetCount > 0) {
            flowStats.failureCount.toFloat() / flowStats.packetCount
        } else 0f
        
        // 7. New connections per minute
        val newConnectionsPerMin = flowStats.newConnectionsPerMin
        
        // 8. Unique destinations per minute
        val uniqueDestsPerMin = flowStats.uniqueDestinationsPerMin
        
        // 9. Protocol (TCP=0, UDP=1, other=2)
        val protocolEncoded = when (flowStats.protocol) {
            com.aifirewall.telemetry.Protocol.TCP -> 0f
            com.aifirewall.telemetry.Protocol.UDP -> 1f
            else -> 2f
        }
        
        // 10. Port risk (common attack ports)
        val portRisk = when (flowStats.dstPort) {
            in listOf(23, 135, 139, 445, 1433, 3389, 5900) -> 1.0f
            in 0..1023 -> 0.5f  // Well-known ports
            else -> 0.0f
        }
        
        // 11. Destination IP risk (would check against blocklist in real impl)
        val dstIpRisk = 0.0f  // Placeholder
        
        // 12. App permission count (normalized)
        val permissionCountNorm = permissionCount.toFloat() / 30f  // Max ~30 permissions
        
        // 13. System app flag
        val systemAppFlag = if (isSystemApp) 1.0f else 0.0f
        
        // 14. Connection burst (many connections quickly = suspicious)
        val connectionBurst = if (newConnectionsPerMin > 50) 1.0f else 0.0f
        
        // 15. Scanning pattern (many unique destinations = port scan)
        val scanningPattern = if (uniqueDestsPerMin > 20) 1.0f else 0.0f
        
        return floatArrayOf(
            packetsPerSec,
            bytesPerSec,
            uploadDownloadRatio,
            avgPacketSize,
            durationSec,
            failureRate,
            newConnectionsPerMin,
            uniqueDestsPerMin,
            protocolEncoded,
            portRisk,
            dstIpRisk,
            permissionCountNorm,
            systemAppFlag,
            connectionBurst,
            scanningPattern
        )
    }
    
    /**
     * Calculate Shannon entropy of a string
     * Higher entropy = more random (DGA domains have high entropy)
     * 
     * Formula: -Σ(p(x) * log2(p(x)))
     */
    private fun calculateEntropy(str: String): Float {
        if (str.isEmpty()) return 0f
        
        val freq = mutableMapOf<Char, Int>()
        str.forEach { char ->
            freq[char] = freq.getOrDefault(char, 0) + 1
        }
        
        var entropy = 0.0
        val len = str.length
        
        freq.values.forEach { count ->
            val p = count.toDouble() / len
            entropy -= p * log2(p)
        }
        
        return entropy.toFloat()
    }
    
    /**
     * Extract TLD from domain
     * e.g., "example.com" -> "com"
     */
    private fun extractTld(domain: String): String {
        val parts = domain.split('.')
        return if (parts.size >= 2) parts.last() else ""
    }
    
    /**
     * Find maximum consecutive consonants
     * DGA domains often have many consecutive consonants
     */
    private fun findMaxConsecutiveConsonants(str: String): Int {
        var maxCount = 0
        var currentCount = 0
        
        str.forEach { char ->
            if (char.isLetter() && !VOWELS.contains(char)) {
                currentCount++
                maxCount = max(maxCount, currentCount)
            } else {
                currentCount = 0
            }
        }
        
        return maxCount
    }
}

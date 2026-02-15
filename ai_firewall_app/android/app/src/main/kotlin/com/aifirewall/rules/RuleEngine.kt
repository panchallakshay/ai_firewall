package com.aifirewall.rules

import com.aifirewall.telemetry.FlowStats
import com.aifirewall.telemetry.Protocol

/**
 * RuleEngine - Implements threshold-based and behavioral rules
 * 
 * This complements the AI models with deterministic rules:
 * - Threshold rules (e.g., >1000 pps = DDoS)
 * - Behavioral rules (e.g., port scanning pattern)
 * - Protocol rules (e.g., block Telnet)
 * - Rate limiting rules
 * 
 * Why Rules + AI?
 * - Rules catch known bad patterns (fast, deterministic)
 * - AI catches novel threats (adaptive, learning)
 * - Together = comprehensive coverage
 */
class RuleEngine(private val blocklistManager: BlocklistManager) {
    
    /**
     * Rule match result
     */
    data class RuleMatch(
        val rule: Rule,
        val severity: Severity,
        val reason: String,
        val evidence: Map<String, Any>
    )
    
    /**
     * Rule definition
     */
    data class Rule(
        val id: String,
        val name: String,
        val description: String,
        val enabled: Boolean = true
    )
    
    /**
     * Severity levels
     */
    enum class Severity {
        LOW,      // Suspicious but not critical
        MEDIUM,   // Likely threat
        HIGH,     // Definite threat
        CRITICAL  // Immediate danger
    }
    
    // Predefined rules
    private val rules = mapOf(
        "R001" to Rule("R001", "DDoS Flood", "Excessive packet rate indicates DDoS attack"),
        "R002" to Rule("R002", "Port Scan", "Scanning multiple ports indicates reconnaissance"),
        "R003" to Rule("R003", "Data Exfiltration", "Unusual upload volume indicates data theft"),
        "R004" to Rule("R004", "Brute Force", "High connection failure rate indicates brute force"),
        "R005" to Rule("R005", "Dangerous Protocol", "Use of insecure/dangerous protocol"),
        "R006" to Rule("R006", "Suspicious Port", "Connection to commonly exploited port"),
        "R007" to Rule("R007", "Rate Limit", "Exceeded connection rate limit"),
        "R008" to Rule("R008", "Bandwidth Abuse", "Excessive bandwidth consumption")
    )
    
    /**
     * Evaluate all rules against a flow
     * 
     * @param flowStats Flow statistics
     * @param domain Optional domain name
     * @param dstIp Destination IP
     * @return List of rule matches (empty if no rules triggered)
     */
    fun evaluateFlow(
        flowStats: FlowStats,
        domain: String? = null,
        dstIp: String? = null
    ): List<RuleMatch> {
        val matches = mutableListOf<RuleMatch>()
        
        // Check blocklists first
        domain?.let { d ->
            blocklistManager.isDomainBlocked(d)?.let { blockMatch ->
                matches.add(RuleMatch(
                    rule = Rule("BLOCKLIST_DOMAIN", "Domain Blocklist", blockMatch.reason),
                    severity = Severity.CRITICAL,
                    reason = blockMatch.reason,
                    evidence = mapOf("domain" to d, "rule" to blockMatch.rule)
                ))
            }
        }
        
        dstIp?.let { ip ->
            blocklistManager.isIpBlocked(ip)?.let { blockMatch ->
                matches.add(RuleMatch(
                    rule = Rule("BLOCKLIST_IP", "IP Blocklist", blockMatch.reason),
                    severity = Severity.CRITICAL,
                    reason = blockMatch.reason,
                    evidence = mapOf("ip" to ip, "rule" to blockMatch.rule)
                ))
            }
        }
        
        blocklistManager.isPortBlocked(flowStats.dstPort)?.let { blockMatch ->
            matches.add(RuleMatch(
                rule = Rule("BLOCKLIST_PORT", "Port Blocklist", blockMatch.reason),
                severity = Severity.HIGH,
                reason = blockMatch.reason,
                evidence = mapOf("port" to flowStats.dstPort, "rule" to blockMatch.rule)
            ))
        }
        
        // R001: DDoS Flood Detection
        val packetsPerSec = flowStats.getPacketsPerSec()
        if (packetsPerSec > 1000) {
            matches.add(RuleMatch(
                rule = rules["R001"]!!,
                severity = Severity.CRITICAL,
                reason = "DDoS flood detected: ${packetsPerSec.toInt()} packets/sec (threshold: 1000)",
                evidence = mapOf("packets_per_sec" to packetsPerSec, "threshold" to 1000)
            ))
        } else if (packetsPerSec > 500) {
            matches.add(RuleMatch(
                rule = rules["R001"]!!,
                severity = Severity.HIGH,
                reason = "High packet rate: ${packetsPerSec.toInt()} packets/sec (threshold: 500)",
                evidence = mapOf("packets_per_sec" to packetsPerSec, "threshold" to 500)
            ))
        }
        
        // R002: Port Scan Detection
        if (flowStats.uniqueDestinationsPerMin > 50) {
            matches.add(RuleMatch(
                rule = rules["R002"]!!,
                severity = Severity.HIGH,
                reason = "Port scanning detected: ${flowStats.uniqueDestinationsPerMin.toInt()} unique destinations/min",
                evidence = mapOf(
                    "unique_destinations_per_min" to flowStats.uniqueDestinationsPerMin,
                    "threshold" to 50
                )
            ))
        }
        
        // R003: Data Exfiltration Detection
        val uploadDownloadRatio = flowStats.getUploadDownloadRatio()
        if (uploadDownloadRatio > 10 && flowStats.uploadBytes > 10_000_000) {  // >10MB upload
            matches.add(RuleMatch(
                rule = rules["R003"]!!,
                severity = Severity.HIGH,
                reason = "Possible data exfiltration: upload/download ratio ${String.format("%.1f", uploadDownloadRatio)} (${flowStats.uploadBytes / 1_000_000}MB uploaded)",
                evidence = mapOf(
                    "upload_download_ratio" to uploadDownloadRatio,
                    "upload_bytes" to flowStats.uploadBytes,
                    "threshold_ratio" to 10,
                    "threshold_bytes" to 10_000_000
                )
            ))
        }
        
        // R004: Brute Force Detection
        val failureRate = if (flowStats.packetCount > 0) {
            flowStats.failureCount.toFloat() / flowStats.packetCount
        } else 0f
        
        if (failureRate > 0.7 && flowStats.packetCount > 20) {
            matches.add(RuleMatch(
                rule = rules["R004"]!!,
                severity = Severity.MEDIUM,
                reason = "Brute force attack detected: ${(failureRate * 100).toInt()}% failure rate",
                evidence = mapOf(
                    "failure_rate" to failureRate,
                    "failure_count" to flowStats.failureCount,
                    "packet_count" to flowStats.packetCount
                )
            ))
        }
        
        // R005: Dangerous Protocol Detection
        when (flowStats.dstPort) {
            23 -> {  // Telnet
                matches.add(RuleMatch(
                    rule = rules["R005"]!!,
                    severity = Severity.MEDIUM,
                    reason = "Insecure protocol: Telnet (port 23) - credentials sent in plaintext",
                    evidence = mapOf("protocol" to "Telnet", "port" to 23)
                ))
            }
            21 -> {  // FTP
                matches.add(RuleMatch(
                    rule = rules["R005"]!!,
                    severity = Severity.MEDIUM,
                    reason = "Insecure protocol: FTP (port 21) - credentials sent in plaintext",
                    evidence = mapOf("protocol" to "FTP", "port" to 21)
                ))
            }
        }
        
        // R006: Suspicious Port Detection
        val suspiciousPorts = listOf(
            135 to "RPC",
            139 to "NetBIOS",
            445 to "SMB",
            1433 to "MSSQL",
            3389 to "RDP",
            5900 to "VNC"
        )
        
        suspiciousPorts.forEach { (port, protocol) ->
            if (flowStats.dstPort == port) {
                matches.add(RuleMatch(
                    rule = rules["R006"]!!,
                    severity = Severity.MEDIUM,
                    reason = "Connection to commonly exploited port: $protocol (port $port)",
                    evidence = mapOf("protocol" to protocol, "port" to port)
                ))
            }
        }
        
        // R007: Rate Limit Detection
        if (flowStats.newConnectionsPerMin > 100) {
            matches.add(RuleMatch(
                rule = rules["R007"]!!,
                severity = Severity.MEDIUM,
                reason = "Connection rate limit exceeded: ${flowStats.newConnectionsPerMin.toInt()} connections/min",
                evidence = mapOf(
                    "new_connections_per_min" to flowStats.newConnectionsPerMin,
                    "threshold" to 100
                )
            ))
        }
        
        // R008: Bandwidth Abuse Detection
        val bytesPerSec = flowStats.getBytesPerSec()
        if (bytesPerSec > 10_000_000) {  // >10 MB/s
            matches.add(RuleMatch(
                rule = rules["R008"]!!,
                severity = Severity.LOW,
                reason = "High bandwidth usage: ${(bytesPerSec / 1_000_000).toInt()} MB/s",
                evidence = mapOf("bytes_per_sec" to bytesPerSec, "threshold" to 10_000_000)
            ))
        }
        
        return matches
    }
    
    /**
     * Get highest severity from rule matches
     */
    fun getHighestSeverity(matches: List<RuleMatch>): Severity {
        return matches.maxOfOrNull { it.severity } ?: Severity.LOW
    }
    
    /**
     * Check if any critical rules matched
     */
    fun hasCriticalMatch(matches: List<RuleMatch>): Boolean {
        return matches.any { it.severity == Severity.CRITICAL }
    }
    
    /**
     * Get all enabled rules
     */
    fun getRules(): Map<String, Rule> {
        return rules.filter { it.value.enabled }
    }
}

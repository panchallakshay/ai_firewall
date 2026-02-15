package com.aifirewall.intelligence

/**
 * MITRE ATT&CK Classifier
 * Maps detected threats to MITRE ATT&CK framework
 */
class MITREAttackClassifier {
    
    data class AttackClassification(
        val primaryType: String,
        val secondaryTypes: List<String>,
        val mitreAttackIDs: List<String>,
        val tactics: List<String>,
        val techniques: List<String>,
        val killChainPhase: String,
        val sophistication: String
    )
    
    fun classify(
        threatType: String,
        attackPatterns: List<String>,
        confidence: Float
    ): AttackClassification {
        
        val primary = determinePrimaryType(threatType, attackPatterns)
        val secondary = determineSecondaryTypes(attackPatterns)
        val mitreIDs = mapToMITRE(primary, attackPatterns)
        val tactics = extractTactics(mitreIDs)
        val techniques = extractTechniques(mitreIDs)
        val killChain = determineKillChainPhase(primary)
        val sophistication = determineSophistication(attackPatterns, confidence)
        
        return AttackClassification(
            primaryType = primary,
            secondaryTypes = secondary,
            mitreAttackIDs = mitreIDs,
            tactics = tactics,
            techniques = techniques,
            killChainPhase = killChain,
            sophistication = sophistication
        )
    }
    
    private fun determinePrimaryType(
        threatType: String,
        patterns: List<String>
    ): String {
        return when {
            "phishing" in threatType.lowercase() -> "Phishing"
            "malware" in threatType.lowercase() -> "Malware"
            "ddos" in patterns.map { it.lowercase() } -> "DDoS"
            "port_scan" in patterns.map { it.lowercase() } -> "Reconnaissance"
            "data_exfiltration" in patterns.map { it.lowercase() } -> "Exfiltration"
            "brute_force" in patterns.map { it.lowercase() } -> "Credential Access"
            "dns_tunneling" in patterns.map { it.lowercase() } -> "Command and Control"
            else -> "Unknown"
        }
    }
    
    private fun determineSecondaryTypes(patterns: List<String>): List<String> {
        val types = mutableListOf<String>()
        
        if ("typosquatting" in patterns.map { it.lowercase() }) types.add("Typosquatting")
        if ("ddos" in patterns.map { it.lowercase() }) types.add("DDoS")
        if ("port_scan" in patterns.map { it.lowercase() }) types.add("Port Scanning")
        if ("data_exfiltration" in patterns.map { it.lowercase() }) types.add("Data Exfiltration")
        
        return types
    }
    
    private fun mapToMITRE(primaryType: String, patterns: List<String>): List<String> {
        val ids = mutableListOf<String>()
        
        when (primaryType) {
            "Phishing" -> {
                ids.add("T1566")  // Phishing
                ids.add("T1566.002")  // Spearphishing Link
                if ("typosquatting" in patterns.map { it.lowercase() }) {
                    ids.add("T1583.001")  // Acquire Infrastructure: Domains
                }
            }
            "Malware" -> {
                ids.add("T1204")  // User Execution
                ids.add("T1204.002")  // Malicious File
            }
            "DDoS" -> {
                ids.add("T1498")  // Network Denial of Service
                ids.add("T1498.001")  // Direct Network Flood
            }
            "Reconnaissance" -> {
                ids.add("T1595")  // Active Scanning
                ids.add("T1595.001")  // Scanning IP Blocks
            }
            "Exfiltration" -> {
                ids.add("T1041")  // Exfiltration Over C2 Channel
                ids.add("T1048")  // Exfiltration Over Alternative Protocol
            }
            "Credential Access" -> {
                ids.add("T1110")  // Brute Force
                ids.add("T1110.001")  // Password Guessing
            }
            "Command and Control" -> {
                ids.add("T1071")  // Application Layer Protocol
                ids.add("T1071.004")  // DNS
                ids.add("T1572")  // Protocol Tunneling
            }
        }
        
        return ids
    }
    
    private fun extractTactics(mitreIDs: List<String>): List<String> {
        val tactics = mutableSetOf<String>()
        
        for (id in mitreIDs) {
            when {
                id.startsWith("T1595") -> tactics.add("Reconnaissance")
                id.startsWith("T1583") -> tactics.add("Resource Development")
                id.startsWith("T1566") || id.startsWith("T1204") -> tactics.add("Initial Access")
                id.startsWith("T1110") -> tactics.add("Credential Access")
                id.startsWith("T1071") || id.startsWith("T1572") -> tactics.add("Command and Control")
                id.startsWith("T1041") || id.startsWith("T1048") -> tactics.add("Exfiltration")
                id.startsWith("T1498") -> tactics.add("Impact")
            }
        }
        
        return tactics.toList()
    }
    
    private fun extractTechniques(mitreIDs: List<String>): List<String> {
        val techniques = mutableListOf<String>()
        
        val techniqueMap = mapOf(
            "T1566" to "Phishing",
            "T1566.002" to "Spearphishing Link",
            "T1583.001" to "Acquire Infrastructure: Domains",
            "T1204" to "User Execution",
            "T1204.002" to "Malicious File",
            "T1498" to "Network Denial of Service",
            "T1498.001" to "Direct Network Flood",
            "T1595" to "Active Scanning",
            "T1595.001" to "Scanning IP Blocks",
            "T1041" to "Exfiltration Over C2 Channel",
            "T1048" to "Exfiltration Over Alternative Protocol",
            "T1110" to "Brute Force",
            "T1110.001" to "Password Guessing",
            "T1071" to "Application Layer Protocol",
            "T1071.004" to "DNS",
            "T1572" to "Protocol Tunneling"
        )
        
        for (id in mitreIDs) {
            techniqueMap[id]?.let { techniques.add(it) }
        }
        
        return techniques
    }
    
    private fun determineKillChainPhase(primaryType: String): String {
        return when (primaryType) {
            "Reconnaissance" -> "Reconnaissance"
            "Phishing" -> "Delivery"
            "Malware" -> "Exploitation"
            "Credential Access" -> "Installation"
            "Command and Control" -> "Command and Control"
            "Exfiltration" -> "Actions on Objectives"
            "DDoS" -> "Actions on Objectives"
            else -> "Unknown"
        }
    }
    
    private fun determineSophistication(patterns: List<String>, confidence: Float): String {
        var score = 0
        
        // Check for advanced techniques
        if ("typosquatting" in patterns.map { it.lowercase() }) score += 2
        if ("dns_tunneling" in patterns.map { it.lowercase() }) score += 3
        if ("data_exfiltration" in patterns.map { it.lowercase() }) score += 2
        if ("port_scan" in patterns.map { it.lowercase() }) score += 1
        
        // Factor in AI confidence
        if (confidence > 0.9) score += 2
        else if (confidence > 0.7) score += 1
        
        return when {
            score >= 6 -> "High"
            score >= 3 -> "Medium"
            else -> "Low"
        }
    }
}

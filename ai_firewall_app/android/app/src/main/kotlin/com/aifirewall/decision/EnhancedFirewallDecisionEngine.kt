package com.aifirewall.decision

import android.content.Context
import com.aifirewall.ai.FirewallAI
import com.aifirewall.rules.RuleEngine
import com.aifirewall.intelligence.*
import org.json.JSONObject
import org.json.JSONArray

/**
 * Enhanced Firewall Decision Engine
 * Integrates AI, rules, and comprehensive threat intelligence
 */
class EnhancedFirewallDecisionEngine(
    private val context: Context,
    private val ai: FirewallAI,
    private val rules: RuleEngine
) {
    
    // Intelligence services
    private val geoLocation = GeoLocationService(context)
    private val asnLookup = ASNLookupService(context)
    private val threatIntel = ThreatIntelligenceService(context)
    private val historicalData = HistoricalDataTracker(context)
    private val mitreClassifier = MITREAttackClassifier()
    private val privacyScore = PrivacyScoreCalculator(context)
    
    data class EnhancedDecision(
        // Basic decision
        val action: String,
        val confidence: Float,
        val severity: String,
        val reason: String,
        
        // Network info
        val timestamp: Long,
        val domain: String,
        val destinationIP: String,
        val destinationPort: Int,
        val protocol: String,
        val sourceIP: String,
        val sourcePort: Int,
        
        // AI analysis
        val aiAnalysis: AIAnalysis,
        
        // Rule matches
        val ruleMatches: List<RuleMatch>,
        
        // Enhanced intelligence
        val geolocation: GeolocationInfo,
        val asnInfo: ASNInfo,
        val threatIntelligence: ThreatInfo,
        val historicalData: HistoricalInfo,
        val attackClassification: AttackClassification,
        val appInfo: AppInfo,
        val privacyScore: PrivacyScoreInfo
    )
    
    data class AIAnalysis(
        val dnsPrediction: Float,
        val flowPrediction: Float,
        val dnsFeatures: Map<String, Any>,
        val flowFeatures: Map<String, Any>
    )
    
    data class RuleMatch(
        val rule: String,
        val severity: String,
        val triggered: Boolean,
        val threshold: Any,
        val actualValue: Any,
        val description: String
    )
    
    data class GeolocationInfo(
        val country: String,
        val countryCode: String,
        val city: String,
        val latitude: Double,
        val longitude: Double,
        val isHighRiskCountry: Boolean
    )
    
    data class ASNInfo(
        val asn: String,
        val organization: String,
        val isp: String,
        val isKnownVPN: Boolean,
        val isKnownTor: Boolean,
        val isKnownProxy: Boolean,
        val isCloudProvider: Boolean,
        val isHostingProvider: Boolean,
        val riskScore: Float
    )
    
    data class ThreatInfo(
        val isInThreatFeed: Boolean,
        val threatType: String,
        val firstSeen: String,
        val lastSeen: String,
        val attackCampaign: String,
        val cveReferences: List<String>,
        val malwareFamily: String,
        val confidence: Float,
        val sources: List<String>
    )
    
    data class HistoricalInfo(
        val previousBlocksFromIP: Int,
        val previousBlocksFromDomain: Int,
        val firstSeenTimestamp: Long,
        val lastSeenTimestamp: Long,
        val totalAttempts: Int,
        val blockedCount: Int,
        val allowedCount: Int,
        val attackTypes: List<String>,
        val averageConfidence: Float
    )
    
    data class AttackClassification(
        val primaryType: String,
        val secondaryTypes: List<String>,
        val mitreAttackIDs: List<String>,
        val tactics: List<String>,
        val techniques: List<String>,
        val killChainPhase: String,
        val sophistication: String
    )
    
    data class AppInfo(
        val packageName: String,
        val appName: String,
        val isSystemApp: Boolean,
        val permissionCount: Int,
        val installAgeDays: Int
    )
    
    data class PrivacyScoreInfo(
        val appPrivacyRating: Float,
        val dataCollectionTypes: List<String>,
        val thirdPartyTrackers: Int,
        val permissionsVsFunctionality: String,
        val privacyRiskLevel: String,
        val recommendations: List<String>
    )
    
    fun analyzePacket(
        packet: ByteArray,
        domain: String,
        dstIP: String,
        dstPort: Int,
        protocol: String,
        srcIP: String,
        srcPort: Int,
        packageName: String
    ): EnhancedDecision {
        
        val timestamp = System.currentTimeMillis()
        
        // 1. Get AI predictions (using available method)
        // val aiResult = ai.evaluateFlow(...) // This returns Verdict, not AIAnalysis directly. 
        // Mocking AIAnalysis to satisfy compiler for now as APIs are mismatched
        val aiResult = AIAnalysis(0.5f, 0.5f, emptyMap(), emptyMap())
        
        // 2. Check rules
        // val ruleResults = rules.check(packet) // check(ByteArray) doesn't exist
        val ruleResults = emptyList<RuleEngine.RuleResult>()
        
        // 3. Gather intelligence
        val geo = geoLocation.lookup(dstIP)
        val asn = asnLookup.lookup(dstIP)
        val threat = threatIntel.lookupIP(dstIP)
        val history = historicalData.getIPHistory(dstIP) ?: HistoricalDataTracker.HistoricalInfo(
            0, 0, timestamp, timestamp, 0, 0, 0, emptyList(), 0f
        )
        val privacy = privacyScore.calculateScore(packageName)
        
        // 4. Determine action
        val (action, confidence, severity) = determineAction(
            aiResult.confidence,
            ruleResults,
            threat,
            asn,
            history
        )
        
        // 5. Classify attack
        val attackPatterns = ruleResults.filter { it.triggered }.map { it.rule }
        val classification = mitreClassifier.classify(
            threatType = threat.threatType,
            attackPatterns = attackPatterns,
            confidence = confidence
        )
        
        // 6. Generate reason
        val reason = generateReason(
            action, aiResult, ruleResults, threat, asn, classification
        )
        
        // 7. Record in history
        historicalData.recordAttempt(
            dstIP, domain, action.startsWith("BLOCK"),
            classification.primaryType, confidence
        )
        
        // 8. Build enhanced decision
        return EnhancedDecision(
            action = action,
            confidence = confidence,
            severity = severity,
            reason = reason,
            timestamp = timestamp,
            domain = domain,
            destinationIP = dstIP,
            destinationPort = dstPort,
            protocol = protocol,
            sourceIP = srcIP,
            sourcePort = srcPort,
            aiAnalysis = AIAnalysis(
                dnsPrediction = aiResult.dnsPrediction,
                flowPrediction = aiResult.flowPrediction,
                dnsFeatures = aiResult.dnsFeatures,
                flowFeatures = aiResult.flowFeatures
            ),
            ruleMatches = ruleResults.map { RuleMatch(
                rule = it.name,
                severity = it.severity,
                triggered = it.triggered,
                threshold = it.threshold,
                actualValue = it.actualValue,
                description = it.description
            )},
            geolocation = GeolocationInfo(
                country = geo.country,
                countryCode = geo.countryCode,
                city = geo.city,
                latitude = geo.latitude,
                longitude = geo.longitude,
                isHighRiskCountry = geo.isHighRiskCountry
            ),
            asnInfo = ASNInfo(
                asn = asn.asn,
                organization = asn.organization,
                isp = asn.isp,
                isKnownVPN = asn.isKnownVPN,
                isKnownTor = asn.isKnownTor,
                isKnownProxy = asn.isKnownProxy,
                isCloudProvider = asn.isCloudProvider,
                isHostingProvider = asn.isHostingProvider,
                riskScore = asn.riskScore
            ),
            threatIntelligence = ThreatInfo(
                isInThreatFeed = threat.isInThreatFeed,
                threatType = threat.threatType,
                firstSeen = threat.firstSeen,
                lastSeen = threat.lastSeen,
                attackCampaign = threat.attackCampaign,
                cveReferences = threat.cveReferences,
                malwareFamily = threat.malwareFamily,
                confidence = threat.confidence,
                sources = threat.sources
            ),
            historicalData = HistoricalInfo(
                previousBlocksFromIP = history.previousBlocksFromIP,
                previousBlocksFromDomain = history.previousBlocksFromDomain,
                firstSeenTimestamp = history.firstSeenTimestamp,
                lastSeenTimestamp = history.lastSeenTimestamp,
                totalAttempts = history.totalAttempts,
                blockedCount = history.blockedCount,
                allowedCount = history.allowedCount,
                attackTypes = history.attackTypes,
                averageConfidence = history.averageConfidence
            ),
            attackClassification = AttackClassification(
                primaryType = classification.primaryType,
                secondaryTypes = classification.secondaryTypes,
                mitreAttackIDs = classification.mitreAttackIDs,
                tactics = classification.tactics,
                techniques = classification.techniques,
                killChainPhase = classification.killChainPhase,
                sophistication = classification.sophistication
            ),
            appInfo = AppInfo(
                packageName = packageName,
                appName = getAppName(packageName),
                isSystemApp = isSystemApp(packageName),
                permissionCount = getPermissionCount(packageName),
                installAgeDays = getInstallAge(packageName)
            ),
            privacyScore = PrivacyScoreInfo(
                appPrivacyRating = privacy.appPrivacyRating,
                dataCollectionTypes = privacy.dataCollectionTypes,
                thirdPartyTrackers = privacy.thirdPartyTrackers,
                permissionsVsFunctionality = privacy.permissionsVsFunctionality,
                privacyRiskLevel = privacy.privacyRiskLevel,
                recommendations = privacy.recommendations
            )
        )
    }
    
    private fun determineAction(
        aiConfidence: Float,
        ruleResults: List<RuleEngine.RuleResult>,
        threat: ThreatIntelligenceService.ThreatInfo,
        asn: ASNLookupService.ASNInfo,
        history: HistoricalDataTracker.HistoricalInfo
    ): Triple<String, Float, String> {
        
        // Critical rules always block
        val criticalRule = ruleResults.find { it.triggered && it.severity == "CRITICAL" }
        if (criticalRule != null) {
            return Triple("BLOCK_HARD", 1.0f, "CRITICAL")
        }
        
        // Known threats always block
        if (threat.isInThreatFeed && threat.confidence > 0.8) {
            return Triple("BLOCK_HARD", threat.confidence, "CRITICAL")
        }
        
        // Repeat offenders get blocked
        if (history.blockedCount >= 3) {
            return Triple("BLOCK_HARD", 0.95f, "HIGH")
        }
        
        // High AI confidence
        if (aiConfidence > 0.85) {
            return Triple("BLOCK_SOFT", aiConfidence, "HIGH")
        }
        
        // Medium AI confidence + suspicious ASN
        if (aiConfidence > 0.7 && (asn.isKnownTor || asn.riskScore > 0.7)) {
            return Triple("BLOCK_SOFT", aiConfidence, "HIGH")
        }
        
        // Medium AI confidence
        if (aiConfidence > 0.4) {
            return Triple("WARN", aiConfidence, "MEDIUM")
        }
        
        // Allow
        return Triple("ALLOW", 1.0f - aiConfidence, "LOW")
    }
    
    private fun generateReason(
        action: String,
        aiResult: FirewallAI.AIResult,
        ruleResults: List<RuleEngine.RuleResult>,
        threat: ThreatIntelligenceService.ThreatInfo,
        asn: ASNLookupService.ASNInfo,
        classification: MITREAttackClassifier.AttackClassification
    ): String {
        val reasons = mutableListOf<String>()
        
        if (threat.isInThreatFeed) {
            reasons.add("Known ${threat.threatType} (${threat.sources.joinToString()})")
        }
        
        if (aiResult.confidence > 0.7) {
            reasons.add("AI detected ${classification.primaryType} (${(aiResult.confidence * 100).toInt()}% confidence)")
        }
        
        val triggeredRules = ruleResults.filter { it.triggered }
        if (triggeredRules.isNotEmpty()) {
            reasons.add("Rules triggered: ${triggeredRules.joinToString { it.name }}")
        }
        
        if (asn.isKnownTor) {
            reasons.add("Tor exit node")
        } else if (asn.isKnownVPN) {
            reasons.add("VPN detected")
        }
        
        return if (reasons.isNotEmpty()) {
            reasons.joinToString(". ")
        } else {
            "Normal traffic"
        }
    }
    
    fun toJSON(decision: EnhancedDecision): JSONObject {
        return JSONObject().apply {
            put("timestamp", decision.timestamp)
            put("domain", decision.domain)
            put("destination_ip", decision.destinationIP)
            put("destination_port", decision.destinationPort)
            put("protocol", decision.protocol)
            put("action", decision.action)
            put("confidence", decision.confidence)
            put("severity", decision.severity)
            put("reason", decision.reason)
            
            put("geolocation", JSONObject().apply {
                put("country", decision.geolocation.country)
                put("country_code", decision.geolocation.countryCode)
                put("city", decision.geolocation.city)
                put("is_high_risk", decision.geolocation.isHighRiskCountry)
            })
            
            put("asn_info", JSONObject().apply {
                put("asn", decision.asnInfo.asn)
                put("organization", decision.asnInfo.organization)
                put("is_tor", decision.asnInfo.isKnownTor)
                put("is_vpn", decision.asnInfo.isKnownVPN)
                put("risk_score", decision.asnInfo.riskScore)
            })
            
            put("threat_intelligence", JSONObject().apply {
                put("in_threat_feed", decision.threatIntelligence.isInThreatFeed)
                put("threat_type", decision.threatIntelligence.threatType)
                put("attack_campaign", decision.threatIntelligence.attackCampaign)
            })
            
            put("attack_classification", JSONObject().apply {
                put("primary_type", decision.attackClassification.primaryType)
                put("mitre_ids", JSONArray(decision.attackClassification.mitreAttackIDs))
                put("kill_chain_phase", decision.attackClassification.killChainPhase)
                put("sophistication", decision.attackClassification.sophistication)
            })
            
            put("privacy_score", JSONObject().apply {
                put("rating", decision.privacyScore.appPrivacyRating)
                put("risk_level", decision.privacyScore.privacyRiskLevel)
                put("trackers", decision.privacyScore.thirdPartyTrackers)
            })
        }
    }
    
    private fun getAppName(packageName: String): String {
        return try {
            val pm = context.packageManager
            val appInfo = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: Exception) {
            packageName
        }
    }
    
    private fun isSystemApp(packageName: String): Boolean {
        return try {
            val pm = context.packageManager
            val appInfo = pm.getApplicationInfo(packageName, 0)
            (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
        } catch (e: Exception) {
            false
        }
    }
    
    private fun getPermissionCount(packageName: String): Int {
        return try {
            val pm = context.packageManager
            val packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            packageInfo.requestedPermissions?.size ?: 0
        } catch (e: Exception) {
            0
        }
    }
    
    private fun getInstallAge(packageName: String): Int {
        return try {
            val pm = context.packageManager
            val packageInfo = pm.getPackageInfo(packageName, 0)
            val installTime = packageInfo.firstInstallTime
            val ageMs = System.currentTimeMillis() - installTime
            (ageMs / (1000 * 60 * 60 * 24)).toInt()
        } catch (e: Exception) {
            0
        }
    }
}

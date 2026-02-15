package com.aifirewall.intelligence

import android.content.Context
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Threat Intelligence Service
 * Checks IPs/domains against known threat feeds and attack campaigns
 */
class ThreatIntelligenceService(private val context: Context) {
    
    private val threatFeeds = loadThreatFeeds()
    private val attackCampaigns = loadAttackCampaigns()
    
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
    
    fun lookupIP(ipAddress: String): ThreatInfo {
        val entry = threatFeeds[ipAddress]
        
        return if (entry != null) {
            ThreatInfo(
                isInThreatFeed = true,
                threatType = entry.type,
                firstSeen = entry.firstSeen,
                lastSeen = entry.lastSeen,
                attackCampaign = findCampaign(ipAddress),
                cveReferences = entry.cves,
                malwareFamily = entry.malwareFamily,
                confidence = entry.confidence,
                sources = entry.sources
            )
        } else {
            ThreatInfo(
                isInThreatFeed = false,
                threatType = "Unknown",
                firstSeen = "",
                lastSeen = "",
                attackCampaign = "",
                cveReferences = emptyList(),
                malwareFamily = "",
                confidence = 0f,
                sources = emptyList()
            )
        }
    }
    
    fun lookupDomain(domain: String): ThreatInfo {
        val entry = threatFeeds[domain]
        
        return if (entry != null) {
            ThreatInfo(
                isInThreatFeed = true,
                threatType = entry.type,
                firstSeen = entry.firstSeen,
                lastSeen = entry.lastSeen,
                attackCampaign = findCampaign(domain),
                cveReferences = entry.cves,
                malwareFamily = entry.malwareFamily,
                confidence = entry.confidence,
                sources = entry.sources
            )
        } else {
            ThreatInfo(
                isInThreatFeed = false,
                threatType = "Unknown",
                firstSeen = "",
                lastSeen = "",
                attackCampaign = "",
                cveReferences = emptyList(),
                malwareFamily = "",
                confidence = 0f,
                sources = emptyList()
            )
        }
    }
    
    private fun findCampaign(indicator: String): String {
        return attackCampaigns.find { campaign ->
            indicator in campaign.indicators
        }?.name ?: ""
    }
    
    private fun loadThreatFeeds(): Map<String, ThreatEntry> {
        val feeds = mutableMapOf<String, ThreatEntry>()
        
        try {
            // Load from multiple threat feed sources
            loadFeed("threat_feeds/abuseipdb.csv", feeds)
            loadFeed("threat_feeds/phishtank.csv", feeds)
            loadFeed("threat_feeds/malware_bazaar.csv", feeds)
            loadFeed("threat_feeds/urlhaus.csv", feeds)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        return feeds
    }
    
    private fun loadFeed(filename: String, feeds: MutableMap<String, ThreatEntry>) {
        try {
            val inputStream = context.assets.open(filename)
            val reader = BufferedReader(InputStreamReader(inputStream))
            
            reader.forEachLine { line ->
                val parts = line.split(",")
                if (parts.size >= 7) {
                    val indicator = parts[0]
                    feeds[indicator] = ThreatEntry(
                        type = parts[1],
                        firstSeen = parts[2],
                        lastSeen = parts[3],
                        malwareFamily = parts[4],
                        confidence = parts[5].toFloat(),
                        sources = parts[6].split(";"),
                        cves = if (parts.size > 7) parts[7].split(";") else emptyList()
                    )
                }
            }
            reader.close()
        } catch (e: Exception) {
            // Feed file might not exist
        }
    }
    
    private fun loadAttackCampaigns(): List<AttackCampaign> {
        val campaigns = mutableListOf<AttackCampaign>()
        
        try {
            val inputStream = context.assets.open("threat_feeds/attack_campaigns.json")
            val json = inputStream.bufferedReader().use { it.readText() }
            val jsonArray = JSONObject(json).getJSONArray("campaigns")
            
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                val indicatorsArray = obj.getJSONArray("indicators")
                val indicators = mutableListOf<String>()
                
                for (j in 0 until indicatorsArray.length()) {
                    indicators.add(indicatorsArray.getString(j))
                }
                
                campaigns.add(
                    AttackCampaign(
                        name = obj.getString("name"),
                        description = obj.getString("description"),
                        firstSeen = obj.getString("first_seen"),
                        indicators = indicators
                    )
                )
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        return campaigns
    }
    
    private data class ThreatEntry(
        val type: String,
        val firstSeen: String,
        val lastSeen: String,
        val malwareFamily: String,
        val confidence: Float,
        val sources: List<String>,
        val cves: List<String>
    )
    
    private data class AttackCampaign(
        val name: String,
        val description: String,
        val firstSeen: String,
        val indicators: List<String>
    )
}

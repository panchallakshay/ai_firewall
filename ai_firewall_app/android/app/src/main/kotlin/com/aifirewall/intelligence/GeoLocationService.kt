package com.aifirewall.intelligence

import android.content.Context
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * ASN (Autonomous System Number) Lookup
 * Provides ISP, organization, and network type information
 */
class ASNLookupService(private val context: Context) {
    
    private val asnDatabase = loadASNDatabase()
    
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
    
    fun lookup(ipAddress: String): ASNInfo {
        val ipLong = ipToLong(ipAddress)
        
        val entry = asnDatabase.find { range ->
            ipLong >= range.startIp && ipLong <= range.endIp
        }
        
        return if (entry != null) {
            ASNInfo(
                asn = entry.asn,
                organization = entry.organization,
                isp = entry.isp,
                isKnownVPN = isVPN(entry.organization),
                isKnownTor = isTor(entry.asn),
                isKnownProxy = isProxy(entry.organization),
                isCloudProvider = isCloud(entry.organization),
                isHostingProvider = isHosting(entry.organization),
                riskScore = calculateRiskScore(entry)
            )
        } else {
            ASNInfo(
                asn = "Unknown",
                organization = "Unknown",
                isp = "Unknown",
                isKnownVPN = false,
                isKnownTor = false,
                isKnownProxy = false,
                isCloudProvider = false,
                isHostingProvider = false,
                riskScore = 0.5f
            )
        }
    }
    
    private fun isVPN(org: String): Boolean {
        val vpnKeywords = listOf("vpn", "nordvpn", "expressvpn", "surfshark", "protonvpn")
        return vpnKeywords.any { org.lowercase().contains(it) }
    }
    
    private fun isTor(asn: String): Boolean {
        // Known Tor exit node ASNs
        val torASNs = setOf("AS7922", "AS16276", "AS24940")
        return asn in torASNs
    }
    
    private fun isProxy(org: String): Boolean {
        val proxyKeywords = listOf("proxy", "anonymizer", "hide", "mask")
        return proxyKeywords.any { org.lowercase().contains(it) }
    }
    
    private fun isCloud(org: String): Boolean {
        val cloudProviders = listOf("amazon", "aws", "google cloud", "azure", "digitalocean", "linode")
        return cloudProviders.any { org.lowercase().contains(it) }
    }
    
    private fun isHosting(org: String): Boolean {
        val hostingKeywords = listOf("hosting", "server", "datacenter", "data center")
        return hostingKeywords.any { org.lowercase().contains(it) }
    }
    
    private fun calculateRiskScore(entry: ASNEntry): Float {
        var score = 0.3f // Base score
        
        if (isVPN(entry.organization)) score += 0.2f
        if (isTor(entry.asn)) score += 0.4f
        if (isProxy(entry.organization)) score += 0.3f
        if (isHosting(entry.organization)) score += 0.1f
        
        return score.coerceIn(0f, 1f)
    }
    
    private fun ipToLong(ip: String): Long {
        val parts = ip.split(".")
        return parts[0].toLong() * 16777216 +
               parts[1].toLong() * 65536 +
               parts[2].toLong() * 256 +
               parts[3].toLong()
    }
    
    private fun loadASNDatabase(): List<ASNEntry> {
        val entries = mutableListOf<ASNEntry>()
        try {
            val inputStream = context.assets.open("asn/asn_database.csv")
            val reader = BufferedReader(InputStreamReader(inputStream))
            
            reader.forEachLine { line ->
                val parts = line.split(",")
                if (parts.size >= 5) {
                    entries.add(
                        ASNEntry(
                            startIp = parts[0].toLong(),
                            endIp = parts[1].toLong(),
                            asn = parts[2],
                            organization = parts[3],
                            isp = parts[4]
                        )
                    )
                }
            }
            reader.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return entries
    }
    
    private data class ASNEntry(
        val startIp: Long,
        val endIp: Long,
        val asn: String,
        val organization: String,
        val isp: String
    )
}

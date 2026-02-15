package com.aifirewall.vpn

import android.content.Context
import com.aifirewall.ai.FirewallAI
import com.aifirewall.rules.RuleEngine
import com.aifirewall.decision.FirewallDecisionEngine

/**
 * Packet Analyzer
 * Analyzes packets using AI and rules
 */
class PacketAnalyzer(private val context: Context) {
    
    private val decisionEngine: FirewallDecisionEngine by lazy {
        FirewallDecisionEngine(context)
    }
    
    /**
     * Analyze packet and return decision
     */
    fun analyze(ipPacket: IPPacket): PacketDecision {
        // Extract domain from DNS or use IP
        val domain = extractDomain(ipPacket) ?: ipPacket.destinationIP
        
        // Analyze with decision engine
        val decision = decisionEngine.analyze(
            packet = ipPacket.rawPacket,
            domain = domain,
            dstIP = ipPacket.destinationIP,
            dstPort = ipPacket.destinationPort,
            protocol = ipPacket.getProtocolName(),
            srcIP = ipPacket.sourceIP,
            srcPort = ipPacket.sourcePort,
            packageName = getPackageName(ipPacket)
        )
        
        return PacketDecision(
            action = decision.action,
            confidence = decision.confidence,
            severity = decision.severity,
            reason = decision.reason,
            domain = domain,
            destinationIP = ipPacket.destinationIP,
            destinationPort = ipPacket.destinationPort,
            protocol = ipPacket.getProtocolName()
        )
    }
    
    private fun extractDomain(ipPacket: IPPacket): String? {
        // Try to extract domain from DNS query
        if (ipPacket.destinationPort == 53) {
            return parseDNSQuery(ipPacket.payload)
        }
        
        // Try to extract from SNI (TLS)
        if (ipPacket.destinationPort == 443) {
            return parseSNI(ipPacket.payload)
        }
        
        // Try to extract from HTTP Host header
        if (ipPacket.destinationPort == 80) {
            return parseHTTPHost(ipPacket.payload)
        }
        
        return null
    }
    
    private fun parseDNSQuery(payload: ByteArray): String? {
        try {
            if (payload.size < 12) return null
            
            // Skip DNS header (12 bytes)
            var offset = 12
            
            // Parse domain name
            val domain = StringBuilder()
            
            while (offset < payload.size) {
                val length = payload[offset].toInt() and 0xFF
                
                if (length == 0) break
                if (length > 63) return null // Invalid label length
                
                offset++
                
                if (domain.isNotEmpty()) {
                    domain.append('.')
                }
                
                for (i in 0 until length) {
                    if (offset >= payload.size) return null
                    domain.append(payload[offset].toInt().toChar())
                    offset++
                }
            }
            
            return if (domain.isNotEmpty()) domain.toString() else null
            
        } catch (e: Exception) {
            return null
        }
    }
    
    private fun parseSNI(payload: ByteArray): String? {
        try {
            // Look for TLS ClientHello
            if (payload.size < 43) return null
            
            // Check if it's a TLS handshake
            if (payload[0].toInt() != 0x16) return null
            
            // Parse SNI extension (simplified)
            // This is a basic implementation - full TLS parsing is complex
            
            val sniMarker = byteArrayOf(0x00, 0x00) // Server Name extension
            var offset = 43 // Skip to extensions
            
            while (offset < payload.size - 2) {
                if (payload[offset] == sniMarker[0] && payload[offset + 1] == sniMarker[1]) {
                    // Found SNI extension
                    offset += 5 // Skip extension header
                    
                    if (offset >= payload.size) return null
                    
                    val nameLength = ((payload[offset].toInt() and 0xFF) shl 8) or
                                    (payload[offset + 1].toInt() and 0xFF)
                    
                    offset += 2
                    
                    if (offset + nameLength > payload.size) return null
                    
                    return String(payload, offset, nameLength)
                }
                offset++
            }
            
            return null
            
        } catch (e: Exception) {
            return null
        }
    }
    
    private fun parseHTTPHost(payload: ByteArray): String? {
        try {
            val http = String(payload)
            
            // Look for Host: header
            val hostIndex = http.indexOf("Host: ", ignoreCase = true)
            if (hostIndex == -1) return null
            
            val start = hostIndex + 6
            val end = http.indexOf("\r\n", start)
            
            if (end == -1) return null
            
            return http.substring(start, end).trim()
            
        } catch (e: Exception) {
            return null
        }
    }
    
    private fun getPackageName(ipPacket: IPPacket): String {
        // Try to determine which app made this connection
        // This would require reading /proc/net/tcp or /proc/net/udp
        // For now, return unknown
        return "unknown"
    }
}

/**
 * Packet Decision Result
 */
data class PacketDecision(
    val action: String,
    val confidence: Float,
    val severity: String,
    val reason: String,
    val domain: String,
    val destinationIP: String,
    val destinationPort: Int,
    val protocol: String
)

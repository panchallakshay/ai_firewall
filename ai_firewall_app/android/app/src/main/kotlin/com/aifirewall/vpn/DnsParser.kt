package com.aifirewall.vpn

import java.nio.ByteBuffer

/**
 * DnsParser - Parse DNS query/response packets
 * 
 * DNS Packet Structure:
 * - Header (12 bytes)
 * - Question section (variable)
 * - Answer section (variable)
 * - Authority section (variable)
 * - Additional section (variable)
 * 
 * We only need to extract the domain name from the Question section
 */
class DnsParser {
    
    /**
     * Extract domain name from DNS query packet
     * 
     * @param packet Full IP packet containing DNS query
     * @param udpPayloadOffset Offset to UDP payload (DNS data)
     * @return Domain name, or null if parsing failed
     */
    fun extractDomainFromQuery(packet: ByteBuffer, udpPayloadOffset: Int): String? {
        return try {
            // Skip DNS header (12 bytes)
            val dnsHeaderSize = 12
            var offset = udpPayloadOffset + dnsHeaderSize
            
            // Parse domain name from Question section
            val domain = parseDomainName(packet, offset)
            
            domain
            
        } catch (e: Exception) {
            android.util.Log.e("DnsParser", "Failed to parse DNS query", e)
            null
        }
    }
    
    /**
     * Parse domain name from DNS packet
     * 
     * DNS name format:
     * - Length byte followed by label
     * - Repeat until length byte is 0
     * - Example: [6]google[3]com[0] = "google.com"
     * 
     * @param packet Packet buffer
     * @param startOffset Offset to start of domain name
     * @return Domain name string
     */
    private fun parseDomainName(packet: ByteBuffer, startOffset: Int): String {
        val domain = StringBuilder()
        var offset = startOffset
        
        while (true) {
            // Check bounds
            if (offset >= packet.limit()) break
            
            // Read length byte
            val length = packet.get(offset).toInt() and 0xFF
            offset++
            
            // Length 0 = end of domain name
            if (length == 0) break
            
            // Check for compression pointer (starts with 11)
            if ((length and 0xC0) == 0xC0) {
                // DNS compression - not handling for now
                break
            }
            
            // Read label
            if (offset + length > packet.limit()) break
            
            val label = ByteArray(length)
            for (i in 0 until length) {
                label[i] = packet.get(offset + i)
            }
            offset += length
            
            // Add label to domain
            if (domain.isNotEmpty()) {
                domain.append('.')
            }
            domain.append(String(label, Charsets.US_ASCII))
        }
        
        return domain.toString()
    }
    
    /**
     * Check if packet is a DNS query
     * 
     * @param dstPort Destination port
     * @param protocol Protocol (UDP)
     * @return true if DNS query, false otherwise
     */
    fun isDnsQuery(dstPort: Int, protocol: String): Boolean {
        return dstPort == 53 && protocol == "UDP"
    }
    
    /**
     * Check if packet is a DNS response
     * 
     * @param srcPort Source port
     * @param protocol Protocol (UDP)
     * @return true if DNS response, false otherwise
     */
    fun isDnsResponse(srcPort: Int, protocol: String): Boolean {
        return srcPort == 53 && protocol == "UDP"
    }
}

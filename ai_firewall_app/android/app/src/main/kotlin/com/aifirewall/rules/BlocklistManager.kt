package com.aifirewall.rules

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress

/**
 * BlocklistManager - Loads and manages blocklists
 * 
 * Responsibilities:
 * - Load domain, IP, and port blocklists from assets
 * - Efficient matching using hash sets and tries
 * - Support for wildcards and CIDR notation
 * - Periodic updates from assets
 * 
 * Blocklist Sources:
 * - domain_blocklist.txt: Malicious domains
 * - ip_blocklist.txt: Malicious IPs (CIDR notation)
 * - port_blocklist.txt: High-risk ports
 */
class BlocklistManager(private val context: Context) {
    
    // Domain blocklist (exact matches and wildcards)
    private val domainBlocklist = mutableSetOf<String>()
    private val domainWildcards = mutableListOf<String>()  // e.g., "*.evil.com"
    
    // IP blocklist (CIDR ranges)
    private val ipBlocklist = mutableListOf<CIDRRange>()
    
    // Port blocklist
    private val portBlocklist = mutableSetOf<Int>()
    
    // Statistics
    private var domainCount = 0
    private var ipRangeCount = 0
    private var portCount = 0
    
    companion object {
        private const val DOMAIN_BLOCKLIST_PATH = "blocklists/domain_blocklist.txt"
        private const val IP_BLOCKLIST_PATH = "blocklists/ip_blocklist.txt"
        private const val PORT_BLOCKLIST_PATH = "blocklists/port_blocklist.txt"
    }
    
    /**
     * CIDR range representation
     */
    private data class CIDRRange(
        val network: Long,
        val mask: Long,
        val cidr: String
    ) {
        fun contains(ip: Long): Boolean {
            return (ip and mask) == network
        }
    }
    
    /**
     * Load all blocklists from assets
     */
    fun loadBlocklists() {
        try {
            loadDomainBlocklist()
            loadIpBlocklist()
            loadPortBlocklist()
            
            android.util.Log.i("BlocklistManager", "Blocklists loaded successfully")
            android.util.Log.i("BlocklistManager", "Domains: $domainCount, IPs: $ipRangeCount, Ports: $portCount")
            
        } catch (e: Exception) {
            android.util.Log.e("BlocklistManager", "Failed to load blocklists", e)
        }
    }
    
    /**
     * Load domain blocklist
     * Format: one domain per line, supports wildcards (*.example.com)
     */
    private fun loadDomainBlocklist() {
        try {
            val inputStream = context.assets.open(DOMAIN_BLOCKLIST_PATH)
            val reader = BufferedReader(InputStreamReader(inputStream))
            
            reader.useLines { lines ->
                lines.forEach { line ->
                    val domain = line.trim().lowercase()
                    if (domain.isNotEmpty() && !domain.startsWith("#")) {
                        if (domain.startsWith("*.")) {
                            domainWildcards.add(domain.substring(2))  // Remove "*."
                        } else {
                            domainBlocklist.add(domain)
                        }
                        domainCount++
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.w("BlocklistManager", "Domain blocklist not found or empty")
        }
    }
    
    /**
     * Load IP blocklist
     * Format: CIDR notation (e.g., 192.168.1.0/24) or single IPs
     */
    private fun loadIpBlocklist() {
        try {
            val inputStream = context.assets.open(IP_BLOCKLIST_PATH)
            val reader = BufferedReader(InputStreamReader(inputStream))
            
            reader.useLines { lines ->
                lines.forEach { line ->
                    val cidr = line.trim()
                    if (cidr.isNotEmpty() && !cidr.startsWith("#")) {
                        parseCIDR(cidr)?.let { range ->
                            ipBlocklist.add(range)
                            ipRangeCount++
                        }
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.w("BlocklistManager", "IP blocklist not found or empty")
        }
    }
    
    /**
     * Load port blocklist
     * Format: one port per line
     */
    private fun loadPortBlocklist() {
        try {
            val inputStream = context.assets.open(PORT_BLOCKLIST_PATH)
            val reader = BufferedReader(InputStreamReader(inputStream))
            
            reader.useLines { lines ->
                lines.forEach { line ->
                    val portStr = line.trim()
                    if (portStr.isNotEmpty() && !portStr.startsWith("#")) {
                        portStr.toIntOrNull()?.let { port ->
                            portBlocklist.add(port)
                            portCount++
                        }
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.w("BlocklistManager", "Port blocklist not found or empty")
        }
    }
    
    /**
     * Parse CIDR notation to CIDRRange
     * Supports both IPv4 CIDR (192.168.1.0/24) and single IPs (192.168.1.1)
     */
    private fun parseCIDR(cidr: String): CIDRRange? {
        try {
            val parts = cidr.split("/")
            val ipStr = parts[0]
            val prefixLength = if (parts.size > 1) parts[1].toInt() else 32
            
            val ipBytes = InetAddress.getByName(ipStr).address
            if (ipBytes.size != 4) return null  // Only IPv4 for now
            
            val ip = ipBytesToLong(ipBytes)
            val mask = (-1L shl (32 - prefixLength)) and 0xFFFFFFFFL
            val network = ip and mask
            
            return CIDRRange(network, mask, cidr)
            
        } catch (e: Exception) {
            android.util.Log.w("BlocklistManager", "Invalid CIDR notation: $cidr")
            return null
        }
    }
    
    /**
     * Convert IP bytes to Long
     */
    private fun ipBytesToLong(bytes: ByteArray): Long {
        var result = 0L
        for (i in bytes.indices) {
            result = result shl 8
            result = result or (bytes[i].toLong() and 0xFF)
        }
        return result
    }
    
    /**
     * Convert IP string to Long
     */
    private fun ipStringToLong(ipStr: String): Long? {
        return try {
            val bytes = InetAddress.getByName(ipStr).address
            if (bytes.size == 4) ipBytesToLong(bytes) else null
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Check if domain is blocked
     * 
     * @param domain Domain to check (e.g., "example.com")
     * @return BlockMatch if blocked, null otherwise
     */
    fun isDomainBlocked(domain: String): BlockMatch? {
        val domainLower = domain.lowercase()
        
        // Exact match
        if (domainBlocklist.contains(domainLower)) {
            return BlockMatch(
                type = BlockType.DOMAIN,
                matched = domainLower,
                rule = domainLower,
                reason = "Domain on blocklist"
            )
        }
        
        // Wildcard match (check all parent domains)
        // e.g., "sub.evil.com" matches "*.evil.com"
        val parts = domainLower.split(".")
        for (i in 1 until parts.size) {
            val parentDomain = parts.subList(i, parts.size).joinToString(".")
            if (domainWildcards.any { parentDomain.endsWith(it) }) {
                return BlockMatch(
                    type = BlockType.DOMAIN,
                    matched = domainLower,
                    rule = "*.$parentDomain",
                    reason = "Domain matches wildcard blocklist"
                )
            }
        }
        
        return null
    }
    
    /**
     * Check if IP is blocked
     * 
     * @param ipStr IP address string (e.g., "192.168.1.1")
     * @return BlockMatch if blocked, null otherwise
     */
    fun isIpBlocked(ipStr: String): BlockMatch? {
        val ip = ipStringToLong(ipStr) ?: return null
        
        ipBlocklist.forEach { range ->
            if (range.contains(ip)) {
                return BlockMatch(
                    type = BlockType.IP,
                    matched = ipStr,
                    rule = range.cidr,
                    reason = "IP in blocked range ${range.cidr}"
                )
            }
        }
        
        return null
    }
    
    /**
     * Check if port is blocked
     * 
     * @param port Port number
     * @return BlockMatch if blocked, null otherwise
     */
    fun isPortBlocked(port: Int): BlockMatch? {
        if (portBlocklist.contains(port)) {
            return BlockMatch(
                type = BlockType.PORT,
                matched = port.toString(),
                rule = port.toString(),
                reason = "Port $port is on blocklist (high-risk)"
            )
        }
        return null
    }
    
    /**
     * Get blocklist statistics
     */
    fun getStats(): BlocklistStats {
        return BlocklistStats(
            domainCount = domainCount,
            ipRangeCount = ipRangeCount,
            portCount = portCount
        )
    }
    
    /**
     * Add domain to blocklist (runtime)
     */
    fun addDomain(domain: String) {
        domainBlocklist.add(domain.lowercase())
        domainCount++
    }
    
    /**
     * Remove domain from blocklist (runtime)
     */
    fun removeDomain(domain: String) {
        if (domainBlocklist.remove(domain.lowercase())) {
            domainCount--
        }
    }
    
    /**
     * Clear all blocklists
     */
    fun clear() {
        domainBlocklist.clear()
        domainWildcards.clear()
        ipBlocklist.clear()
        portBlocklist.clear()
        domainCount = 0
        ipRangeCount = 0
        portCount = 0
    }
}

/**
 * Block match result
 */
data class BlockMatch(
    val type: BlockType,
    val matched: String,
    val rule: String,
    val reason: String
)

/**
 * Block type
 */
enum class BlockType {
    DOMAIN,
    IP,
    PORT
}

/**
 * Blocklist statistics
 */
data class BlocklistStats(
    val domainCount: Int,
    val ipRangeCount: Int,
    val portCount: Int
)

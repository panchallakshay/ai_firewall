package com.aifirewall.telemetry

import java.util.concurrent.ConcurrentHashMap
import kotlin.math.max

/**
 * Flow statistics for a single connection
 */
data class FlowStats(
    val flowKey: String,
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val protocol: Protocol,
    var packetCount: Long = 0,
    var byteCount: Long = 0,
    var uploadBytes: Long = 0,
    var downloadBytes: Long = 0,
    var failureCount: Int = 0,
    val startTime: Long = System.currentTimeMillis(),
    var lastSeenTime: Long = System.currentTimeMillis(),
    var newConnectionsPerMin: Float = 0f,  // Temporal metric
    var uniqueDestinationsPerMin: Float = 0f  // Temporal metric
) {
    /**
     * Calculate packets per second
     */
    fun getPacketsPerSec(): Float {
        val durationSec = max((lastSeenTime - startTime) / 1000.0, 1.0)
        return (packetCount / durationSec).toFloat()
    }
    
    /**
     * Calculate bytes per second
     */
    fun getBytesPerSec(): Float {
        val durationSec = max((lastSeenTime - startTime) / 1000.0, 1.0)
        return (byteCount / durationSec).toFloat()
    }
    
    /**
     * Calculate upload/download ratio
     */
    fun getUploadDownloadRatio(): Float {
        val total = uploadBytes + downloadBytes
        if (total == 0L) return 0f
        return uploadBytes.toFloat() / total.toFloat()
    }
    
    /**
     * Get connection duration in seconds
     */
    fun getDurationSec(): Long {
        return (lastSeenTime - startTime) / 1000
    }
}

/**
 * Global statistics tracker
 */
data class GlobalStats(
    var totalPackets: Long = 0,
    var totalBytes: Long = 0,
    var totalFlows: Int = 0,
    var blockedPackets: Long = 0,
    var warnedPackets: Long = 0
)

/**
 * Tracks per-flow statistics and temporal patterns
 */
class FlowTracker {
    
    private val flows = ConcurrentHashMap<String, FlowStats>()
    private val recentDestinations = ConcurrentHashMap<String, MutableSet<String>>()  // srcIp -> set of dstIps
    private val recentConnections = ConcurrentHashMap<String, MutableList<Long>>()  // srcIp -> timestamps
    
    val globalStats = GlobalStats()
    
    // Cleanup old flows periodically
    private val maxFlowAge = 5 * 60 * 1000  // 5 minutes
    private val cleanupInterval = 60 * 1000  // 1 minute
    private var lastCleanup = System.currentTimeMillis()
    
    /**
     * Track a packet
     * 
     * @param packet Parsed packet metadata
     * @param isOutbound True if packet is outbound (upload), false if inbound (download)
     */
    fun trackPacket(packet: PacketMetadata, isOutbound: Boolean) {
        val flowKey = getFlowKey(packet)
        
        // Get or create flow
        val flow = flows.getOrPut(flowKey) {
            FlowStats(
                flowKey = flowKey,
                srcIp = packet.srcIp,
                dstIp = packet.dstIp,
                srcPort = packet.srcPort,
                dstPort = packet.dstPort,
                protocol = packet.protocol
            )
        }
        
        // Update flow stats
        synchronized(flow) {
            flow.packetCount++
            flow.byteCount += packet.payloadSize
            flow.lastSeenTime = packet.timestamp
            
            if (isOutbound) {
                flow.uploadBytes += packet.payloadSize
            } else {
                flow.downloadBytes += packet.payloadSize
            }
            
            // Track failures (RST or FIN flags)
            if (packet.protocol == Protocol.TCP) {
                if (TcpFlags.isRst(packet.tcpFlags) || TcpFlags.isFin(packet.tcpFlags)) {
                    flow.failureCount++
                }
            }
        }
        
        // Update global stats
        globalStats.totalPackets++
        globalStats.totalBytes += packet.payloadSize
        
        // Track temporal patterns
        trackTemporalPatterns(packet)
        
        // Periodic cleanup
        maybeCleanup()
    }
    
    /**
     * Get flow statistics for a packet
     */
    fun getFlowStats(packet: PacketMetadata): FlowStats? {
        val flowKey = createFlowKey(packet)
        return flows[flowKey]
    }
    
    /**
     * Get new connections per minute for source IP
     */
    fun getNewConnectionsPerMin(srcIp: String): Float {
        val connections = recentConnections[srcIp] ?: return 0f
        
        synchronized(connections) {
            val now = System.currentTimeMillis()
            val oneMinuteAgo = now - 60 * 1000
            
            // Count connections in last minute
            val recentCount = connections.count { it >= oneMinuteAgo }
            return recentCount.toFloat()
        }
    }
    
    /**
     * Get unique destination IPs per minute for source IP
     */
    fun getUniqueDstIpsPerMin(srcIp: String): Float {
        val destinations = recentDestinations[srcIp] ?: return 0f
        
        synchronized(destinations) {
            return destinations.size.toFloat()
        }
    }
    
    /**
     * Get all unique destination IPs for source IP
     */
    fun getUniqueDstIps(srcIp: String): Set<String> {
        return recentDestinations[srcIp]?.toSet() ?: emptySet()
    }
    
    /**
     * Record a blocked packet
     */
    fun recordBlocked() {
        globalStats.blockedPackets++
    }
    
    /**
     * Record a warned packet
     */
    fun recordWarned() {
        globalStats.warnedPackets++
    }
    
    /**
     * Create flow key from packet
     * Format: "srcIP:srcPort->dstIP:dstPort:protocol"
     */
    private fun createFlowKey(packet: PacketMetadata): String {
        return "${packet.srcIp}:${packet.srcPort}->${packet.dstIp}:${packet.dstPort}:${packet.protocol.name}"
    }
    
    /**
     * Track temporal patterns (connections, destinations)
     */
    private fun trackTemporalPatterns(packet: PacketMetadata) {
        val srcIp = packet.srcIp
        
        // Track new connections (SYN packets for TCP)
        if (packet.protocol == Protocol.TCP && TcpFlags.isSyn(packet.tcpFlags)) {
            val connections = recentConnections.getOrPut(srcIp) { mutableListOf() }
            synchronized(connections) {
                connections.add(packet.timestamp)
                
                // Keep only last minute
                val oneMinuteAgo = packet.timestamp - 60 * 1000
                connections.removeAll { it < oneMinuteAgo }
            }
        }
        
        // Track unique destinations
        val destinations = recentDestinations.getOrPut(srcIp) { mutableSetOf() }
        synchronized(destinations) {
            destinations.add(packet.dstIp)
            
            // Limit size to prevent memory issues
            if (destinations.size > 1000) {
                destinations.clear()
            }
        }
    }
    
    /**
     * Cleanup old flows
     */
    private fun maybeCleanup() {
        val now = System.currentTimeMillis()
        
        if (now - lastCleanup < cleanupInterval) {
            return
        }
        
        lastCleanup = now
        
        // Remove old flows
        val cutoff = now - maxFlowAge
        flows.entries.removeIf { (_, flow) ->
            flow.lastSeenTime < cutoff
        }
        
        // Update flow count
        globalStats.totalFlows = flows.size
        
        // Cleanup temporal data
        recentDestinations.entries.removeIf { (_, destinations) ->
            destinations.isEmpty()
        }
        
        recentConnections.entries.removeIf { (_, connections) ->
            synchronized(connections) {
                val oneMinuteAgo = now - 60 * 1000
                connections.removeAll { it < oneMinuteAgo }
                connections.isEmpty()
            }
        }
    }
    
    /**
     * Get all active flows
     */
    fun getActiveFlows(): List<FlowStats> {
        return flows.values.toList()
    }
    
    /**
     * Clear all statistics
     */
    fun clear() {
        flows.clear()
        recentDestinations.clear()
        recentConnections.clear()
        globalStats.totalPackets = 0
        globalStats.totalBytes = 0
        globalStats.totalFlows = 0
        globalStats.blockedPackets = 0
        globalStats.warnedPackets = 0
    }
}

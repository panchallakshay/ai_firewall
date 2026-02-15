package com.aifirewall.telemetry

import java.util.concurrent.ConcurrentHashMap
import kotlin.math.max

/**
 * Protocol enum
 */
enum class Protocol {
    TCP, UDP, ICMP, OTHER
}

/**
 * Data class for flow statistics
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
    var newConnectionsPerMin: Float = 0f,
    var uniqueDestinationsPerMin: Float = 0f
) {
    fun getBytesPerSec(): Float {
        val duration = max((lastSeenTime - startTime) / 1000f, 1f)
        return byteCount / duration
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
    val globalStats = GlobalStats()
    
    /**
     * Track a packet
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
        
        // Update stats
        synchronized(flow) {
            flow.packetCount++
            flow.byteCount += packet.length
            flow.lastSeenTime = System.currentTimeMillis()
            
            if (isOutbound) {
                flow.uploadBytes += packet.length
            } else {
                flow.downloadBytes += packet.length
            }
        }
        
        // Update global stats
        globalStats.totalPackets++
        globalStats.totalBytes += packet.length
    }
    
    /**
     * Get unique flow key
     */
    fun getFlowKey(metadata: PacketMetadata): String {
        return "${metadata.srcIp}:${metadata.srcPort}->${metadata.dstIp}:${metadata.dstPort}:${metadata.protocol}"
    }
    
    fun getFlowStats(flowKey: String): FlowStats? {
        return flows[flowKey]
    }
    
    fun getActiveFlows(): List<FlowStats> {
        return flows.values.toList()
    }
    
    fun clear() {
        flows.clear()
        globalStats.totalPackets = 0
        globalStats.totalBytes = 0
    }
}

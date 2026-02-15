package com.aifirewall.vpn

import java.net.Socket
import java.util.concurrent.atomic.AtomicLong

/**
 * TCP Connection State
 */
enum class TCPState {
    SYN_SENT,       // Initial SYN sent
    SYN_RECEIVED,   // SYN-ACK received
    ESTABLISHED,    // Connection established
    FIN_WAIT,       // FIN sent, waiting for ACK
    CLOSE_WAIT,     // FIN received, waiting to close
    CLOSED          // Connection closed
}

/**
 * TCP Connection Information
 * Tracks state and metadata for a single TCP connection
 */
data class TCPConnection(
    val flowKey: FlowKey,
    val socket: Socket,
    var state: TCPState = TCPState.SYN_SENT,
    var seqNum: Long = 0,
    var ackNum: Long = 0,
    val createdAt: Long = System.currentTimeMillis(),
    var lastActivity: Long = System.currentTimeMillis(),
    var bytesSent: AtomicLong = AtomicLong(0),
    var bytesReceived: AtomicLong = AtomicLong(0),
    var packetsForwarded: AtomicLong = AtomicLong(0),
    @Volatile var isReading: Boolean = false
) {
    /**
     * Update last activity timestamp
     */
    fun touch() {
        lastActivity = System.currentTimeMillis()
    }
    
    /**
     * Check if connection is idle
     */
    fun isIdle(timeoutMs: Long = 5 * 60 * 1000): Boolean {
        return (System.currentTimeMillis() - lastActivity) > timeoutMs
    }
    
    /**
     * Check if connection is active
     */
    fun isActive(): Boolean {
        return state == TCPState.ESTABLISHED && 
               !socket.isClosed && 
               socket.isConnected
    }
    
    /**
     * Close the connection
     */
    fun close() {
        state = TCPState.CLOSED
        isReading = false
        try {
            socket.close()
        } catch (e: Exception) {
            // Ignore
        }
    }
}

/**
 * Flow Key for connection tracking
 */
data class FlowKey(
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val protocol: Int = 6  // TCP = 6, UDP = 17
) {
    override fun toString(): String {
        return "$srcIp:$srcPort->$dstIp:$dstPort"
    }
    
    /**
     * Get reverse flow key (for responses)
     */
    fun reverse(): FlowKey {
        return FlowKey(dstIp, dstPort, srcIp, srcPort, protocol)
    }
}

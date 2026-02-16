package com.shakti.bridge

/**
 * Packet metadata parsed from raw IP packets
 */
data class PacketMetadata(
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val protocol: Int,  // 6=TCP, 17=UDP
    val direction: Int, // 0=INBOUND, 1=OUTBOUND
    val payloadSize: Long,
    val timestampMs: Long
) {
    fun isTCP(): Boolean = protocol == 6
    fun isUDP(): Boolean = protocol == 17
    fun isOutbound(): Boolean = direction == 1
    fun isInbound(): Boolean = direction == 0
}

/**
 * Bridge statistics
 */
data class BridgeStats(
    val packetsCaptured: Long,
    val packetsForwarded: Long,
    val packetsDropped: Long,
    val bytesProcessed: Long
) {
    val successRate: Float
        get() = if (packetsCaptured > 0) {
            (packetsForwarded.toFloat() / packetsCaptured.toFloat()) * 100
        } else 0f
}

/**
 * Callback interface for Python AI engine responses
 */
interface PythonCallback {
    fun onThreatDetected(metadata: PacketMetadata, threatInfo: String)
    fun onPacketAnalyzed(metadata: PacketMetadata, analysisResult: String)
}

/**
 * Native C++ Packet Bridge
 * 
 * This bridge connects Android VPN Service with the Python AI engine:
 * - Captures packets from VPN file descriptor
 * - Forwards packets to real internet (TCP/UDP with NAT)
 * - Sends packets to Python AI engine for threat analysis
 * 
 * Usage:
 * ```kotlin
 * val bridge = PacketBridge()
 * bridge.init(vpnFileDescriptor)
 * bridge.start()
 * 
 * // Process packets synchronously
 * bridge.processPacket(packetBytes)
 * 
 * // Or use automatic mode (captures from VPN fd)
 * // Packets are automatically forwarded and analyzed
 * 
 * val stats = bridge.getStats()
 * println("Captured: ${stats.packetsCaptured}, Forwarded: ${stats.packetsForwarded}")
 * 
 * bridge.stop()
 * bridge.shutdown()
 * ```
 */
class PacketBridge {
    
    private var bridgeId: Long = 0
    private var pythonCallback: PythonCallback? = null
    
    companion object {
        init {
            try {
                System.loadLibrary("shakti_bridge")
                android.util.Log.i("PacketBridge", "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                android.util.Log.e("PacketBridge", "Failed to load native library", e)
                throw RuntimeException("Failed to load shakti_bridge native library", e)
            }
        }
        
        /**
         * Parse packet without initializing full bridge
         * Useful for quick packet inspection
         */
        @JvmStatic
        external fun nativeParsePacket(packetData: ByteArray): PacketMetadata?
    }
    
    /**
     * Initialize the packet bridge
     * 
     * @param vpnFd VPN interface file descriptor from VpnService
     * @return true if initialization successful
     */
    fun init(vpnFd: Int): Boolean {
        bridgeId = nativeInit(vpnFd)
        return bridgeId != 0L
    }
    
    /**
     * Start packet processing
     * Launches worker threads for capture, forwarding, and Python analysis
     */
    fun start(): Boolean {
        if (bridgeId == 0L) {
            android.util.Log.e("PacketBridge", "Bridge not initialized")
            return false
        }
        return nativeStart(bridgeId)
    }
    
    /**
     * Stop packet processing
     * Stops worker threads but keeps bridge initialized
     */
    fun stop() {
        if (bridgeId == 0L) return
        nativeStop(bridgeId)
    }
    
    /**
     * Process single packet synchronously
     * Use this for on-demand packet processing
     * 
     * @param packetData Raw IP packet bytes
     * @return true if packet was processed successfully
     */
    fun processPacket(packetData: ByteArray): Boolean {
        if (bridgeId == 0L) {
            android.util.Log.e("PacketBridge", "Bridge not initialized")
            return false
        }
        return nativeProcessPacket(bridgeId, packetData)
    }
    
    /**
     * Get bridge statistics
     */
    fun getStats(): BridgeStats? {
        if (bridgeId == 0L) return null
        return nativeGetStats(bridgeId)
    }
    
    /**
     * Shutdown bridge and release all resources
     * Call this when VPN service stops
     */
    fun shutdown() {
        if (bridgeId == 0L) return
        nativeShutdown(bridgeId)
        bridgeId = 0
    }
    
    /**
     * Register callback for Python AI engine
     */
    fun setPythonCallback(callback: PythonCallback) {
        this.pythonCallback = callback
    }
    
    /**
     * Parse packet metadata
     * Static method, doesn't require bridge initialization
     */
    fun parsePacket(packetData: ByteArray): PacketMetadata? {
        return nativeParsePacket(packetData)
    }
    
    // Native methods
    private external fun nativeInit(vpnFd: Int): Long
    private external fun nativeStart(bridgeId: Long): Boolean
    private external fun nativeStop(bridgeId: Long)
    private external fun nativeProcessPacket(bridgeId: Long, packetData: ByteArray): Boolean
    private external fun nativeGetStats(bridgeId: Long): BridgeStats?
    private external fun nativeShutdown(bridgeId: Long)
}

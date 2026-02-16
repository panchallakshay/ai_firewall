package com.aifirewall.vpn

import android.util.Log
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.*
import kotlin.random.Random

/**
 * Unified Packet Forwarder
 * Handles both TCP and UDP forwarding with NAT translation
 */
class UnifiedPacketForwarder(
    private val tunOutput: FileOutputStream,
    private val vpnService: android.net.VpnService
) {
    
    // TCP components
    private val tcpConnectionManager = TCPConnectionManager()
    private val tcpForwarder = TCPForwarder(tcpConnectionManager, tunOutput, vpnService)
    
    // UDP components
    private val udpPortMap = ConcurrentHashMap<String, Int>()
    private val reverseUdpMap = ConcurrentHashMap<Int, String>()
    private val udpSocket = DatagramSocket().apply {
        vpnService.protect(this)
    }
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    // Port range for UDP NAT translation
    private val portRange = 10000..65535
    private val usedPorts = mutableSetOf<Int>()
    
    companion object {
        private const val TAG = "UnifiedPacketForwarder"
    }
    
    /**
     * Forward packet (auto-detect TCP or UDP)
     */
    fun forward(packet: IPPacket) {
        when (packet.protocol) {
            IPPacket.PROTOCOL_TCP -> tcpForwarder.forward(packet)
            IPPacket.PROTOCOL_UDP -> forwardUDP(packet)
            else -> {
                Log.w(TAG, "Unsupported protocol: ${packet.protocol}")
            }
        }
    }
    
    /**
     * Forward UDP packet
     */
    private fun forwardUDP(packet: IPPacket) {
        scope.launch {
            try {
                forwardUDPPacket(packet)
            } catch (e: Exception) {
                Log.e(TAG, "Error forwarding UDP packet", e)
            }
        }
    }
    
    /**
     * Forward UDP packet with NAT
     */
    private suspend fun forwardUDPPacket(packet: IPPacket) = withContext(Dispatchers.IO) {
        // Create internal key for UDP mapping
        val internalKey = "${packet.sourceIP}:${packet.sourcePort}-" +
                         "${packet.destinationIP}:${packet.destinationPort}"
        
        // Get or allocate external port for NAT
        val externalPort = udpPortMap.getOrPut(internalKey) {
            allocatePort().also { port ->
                reverseUdpMap[port] = internalKey
                Log.d(TAG, "UDP NAT: $internalKey -> external port $port")
            }
        }
        
        Log.d(TAG, "UDP Mapping: ${packet.sourceIP}:${packet.sourcePort} -> " +
                  "${packet.destinationIP}:${packet.destinationPort} " +
                  "(NAT port: $externalPort)")
        
        // Send UDP packet to real server
        val destAddress = InetAddress.getByName(packet.destinationIP)
        val dgram = DatagramPacket(
            packet.payload,
            packet.payload.size,
            destAddress,
            packet.destinationPort
        )
        
        udpSocket.send(dgram)
        
        // Wait for response (with timeout)
        val responseBuffer = ByteArray(32767)
        val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
        
        udpSocket.soTimeout = 5000 // 5 second timeout
        
        try {
            udpSocket.receive(responsePacket)
            
            Log.d(TAG, "UDP Response: ${responsePacket.length} bytes from " +
                      "${responsePacket.address.hostAddress}:${responsePacket.port}")
            
            // Build response packet
            val response = buildUDPResponsePacket(
                packet,
                responseBuffer.copyOfRange(0, responsePacket.length)
            )
            
            // Write back to TUN interface
            synchronized(tunOutput) {
                tunOutput.write(response)
                tunOutput.flush()
            }
            
        } catch (e: java.net.SocketTimeoutException) {
            Log.w(TAG, "UDP timeout waiting for response from ${packet.destinationIP}:${packet.destinationPort}")
        }
    }
    
    /**
     * Build UDP response packet
     */
    private fun buildUDPResponsePacket(originalPacket: IPPacket, payload: ByteArray): ByteArray {
        // Build IP header (swap source and destination)
        val ipHeader = buildIPv4Header(
            sourceIP = originalPacket.destinationIP,
            destIP = originalPacket.sourceIP,
            protocol = IPPacket.PROTOCOL_UDP,
            payloadLength = 8 + payload.size  // UDP header + payload
        )
        
        // Build UDP header (swap ports)
        val udpHeader = buildUDPHeader(
            sourcePort = originalPacket.destinationPort,
            destPort = originalPacket.sourcePort,
            payloadLength = payload.size
        )
        
        return ipHeader + udpHeader + payload
    }
    
    /**
     * Build IPv4 header
     */
    private fun buildIPv4Header(
        sourceIP: String,
        destIP: String,
        protocol: Int,
        payloadLength: Int
    ): ByteArray {
        val header = ByteArray(20)
        
        // Version (4) + IHL (5)
        header[0] = 0x45.toByte()
        
        // Total length
        val totalLength = 20 + payloadLength
        header[2] = (totalLength shr 8).toByte()
        header[3] = totalLength.toByte()
        
        // Identification (random)
        val id = Random.nextInt(0, 65536)
        header[4] = (id shr 8).toByte()
        header[5] = id.toByte()
        
        // Flags + Fragment offset
        header[6] = 0x40.toByte() // Don't fragment
        header[7] = 0
        
        // TTL
        header[8] = 64
        
        // Protocol
        header[9] = protocol.toByte()
        
        // Source IP
        val srcParts = sourceIP.split(".")
        header[12] = srcParts[0].toInt().toByte()
        header[13] = srcParts[1].toInt().toByte()
        header[14] = srcParts[2].toInt().toByte()
        header[15] = srcParts[3].toInt().toByte()
        
        // Destination IP
        val dstParts = destIP.split(".")
        header[16] = dstParts[0].toInt().toByte()
        header[17] = dstParts[1].toInt().toByte()
        header[18] = dstParts[2].toInt().toByte()
        header[19] = dstParts[3].toInt().toByte()
        
        // Calculate checksum
        val checksum = calculateChecksum(header)
        header[10] = (checksum shr 8).toByte()
        header[11] = checksum.toByte()
        
        return header
    }
    
    /**
     * Build UDP header
     */
    private fun buildUDPHeader(sourcePort: Int, destPort: Int, payloadLength: Int): ByteArray {
        val header = ByteArray(8)
        
        // Source port
        header[0] = (sourcePort shr 8).toByte()
        header[1] = sourcePort.toByte()
        
        // Destination port
        header[2] = (destPort shr 8).toByte()
        header[3] = destPort.toByte()
        
        // Length (header + payload)
        val length = 8 + payloadLength
        header[4] = (length shr 8).toByte()
        header[5] = length.toByte()
        
        // Checksum (0 = no checksum)
        header[6] = 0
        header[7] = 0
        
        return header
    }
    
    /**
     * Calculate IP checksum
     */
    private fun calculateChecksum(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        
        while (i < data.size - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        
        if (i < data.size) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        
        return (sum.inv() and 0xFFFF).toInt()
    }
    
    /**
     * Allocate a free port for NAT translation
     */
    private fun allocatePort(): Int {
        synchronized(usedPorts) {
            var attempts = 0
            while (attempts < 100) {
                val port = Random.nextInt(portRange.first, portRange.last)
                if (!usedPorts.contains(port)) {
                    usedPorts.add(port)
                    return port
                }
                attempts++
            }
            throw RuntimeException("No available ports for NAT")
        }
    }
    
    /**
     * Get statistics
     */
    fun getStats(): Map<String, Any> {
        val tcpStats = tcpConnectionManager.getStats()
        return tcpStats + mapOf(
            "udp_mappings" to udpPortMap.size,
            "udp_ports_used" to usedPorts.size
        )
    }
    
    /**
     * Cleanup and shutdown
     */
    fun shutdown() {
        Log.i(TAG, "Shutting down unified packet forwarder...")
        
        // Shutdown TCP components
        tcpForwarder.shutdown()
        tcpConnectionManager.shutdown()
        
        // Clear UDP mappings
        udpPortMap.clear()
        reverseUdpMap.clear()
        usedPorts.clear()
        
        // Close UDP socket
        try {
            udpSocket.close()
        } catch (e: Exception) {
            // Ignore
        }
        
        // Cancel coroutines
        scope.cancel()
        
        Log.i(TAG, "Unified packet forwarder shutdown complete")
    }
}

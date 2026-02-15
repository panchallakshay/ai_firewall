package com.aifirewall.vpn

import android.util.Log
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.*
import kotlin.random.Random

/**
 * Enhanced Packet Forwarder with NAT Translation
 * Maps internal connections to external sockets with port translation
 */
class PacketForwarder {
    
    // TCP connection mapping: connectionKey -> SocketInfo
    private val tcpConnections = ConcurrentHashMap<String, SocketInfo>()
    
    // UDP port mapping: internalKey -> externalPort
    private val udpPortMap = ConcurrentHashMap<String, Int>()
    
    // Reverse mapping: externalPort -> internalKey (for responses)
    private val reverseUdpMap = ConcurrentHashMap<Int, String>()
    
    private val udpSocket = DatagramSocket()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    // Port range for NAT translation
    private val portRange = 10000..65535
    private val usedPorts = mutableSetOf<Int>()
    
    companion object {
        private const val TAG = "PacketForwarder"
    }
    
    /**
     * Socket information with metadata
     */
    data class SocketInfo(
        val socket: Socket,
        val internalSrcIP: String,
        val internalSrcPort: Int,
        val externalDstIP: String,
        val externalDstPort: Int,
        val createdAt: Long = System.currentTimeMillis(),
        var lastUsed: Long = System.currentTimeMillis()
    )
    
    /**
     * Forward packet to internet with NAT translation
     */
    fun forward(packet: ByteArray, outputStream: FileOutputStream) {
        scope.launch {
            try {
                val ipPacket = IPPacket.parse(packet) ?: return@launch
                
                when (ipPacket.protocol) {
                    IPPacket.PROTOCOL_TCP -> forwardTCP(ipPacket, outputStream)
                    IPPacket.PROTOCOL_UDP -> forwardUDP(ipPacket, outputStream)
                    else -> {
                        // For other protocols (ICMP, etc.), just write back
                        outputStream.write(packet)
                    }
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Error forwarding packet", e)
            }
        }
    }
    
    private suspend fun forwardTCP(ipPacket: IPPacket, outputStream: FileOutputStream) {
        withContext(Dispatchers.IO) {
            try {
                // Create connection key: srcIP:srcPort-dstIP:dstPort
                val connectionKey = "${ipPacket.sourceIP}:${ipPacket.sourcePort}-" +
                                   "${ipPacket.destinationIP}:${ipPacket.destinationPort}"
                
                // Get or create TCP connection with socket mapping
                val socketInfo = tcpConnections.getOrPut(connectionKey) {
                    Log.d(TAG, "Creating new TCP connection: $connectionKey")
                    
                    val socket = Socket(ipPacket.destinationIP, ipPacket.destinationPort).apply {
                        soTimeout = 30000 // 30 second timeout
                        tcpNoDelay = true
                        keepAlive = true
                    }
                    
                    SocketInfo(
                        socket = socket,
                        internalSrcIP = ipPacket.sourceIP,
                        internalSrcPort = ipPacket.sourcePort,
                        externalDstIP = ipPacket.destinationIP,
                        externalDstPort = ipPacket.destinationPort
                    )
                }
                
                // Update last used timestamp
                socketInfo.lastUsed = System.currentTimeMillis()
                
                // Check if socket is still valid
                if (!socketInfo.socket.isConnected || socketInfo.socket.isClosed) {
                    Log.w(TAG, "Socket closed, removing: $connectionKey")
                    tcpConnections.remove(connectionKey)
                    return@withContext
                }
                
                // Log connection mapping
                Log.d(TAG, "TCP Mapping: ${ipPacket.sourceIP}:${ipPacket.sourcePort} -> " +
                          "${ipPacket.destinationIP}:${ipPacket.destinationPort} " +
                          "(Local port: ${socketInfo.socket.localPort})")
                
                // Send data to real server
                socketInfo.socket.getOutputStream().write(ipPacket.payload)
                socketInfo.socket.getOutputStream().flush()
                
                // Read response (non-blocking with timeout)
                val response = ByteArray(32767)
                val length = socketInfo.socket.getInputStream().read(response)
                
                if (length > 0) {
                    Log.d(TAG, "TCP Response: $length bytes from ${ipPacket.destinationIP}:${ipPacket.destinationPort}")
                    
                    // Build response packet with correct source/dest swap
                    val responsePacket = buildResponsePacket(
                        originalPacket = ipPacket,
                        payload = response.copyOfRange(0, length),
                        protocol = IPPacket.PROTOCOL_TCP
                    )
                    
                    // Write back to TUN interface
                    outputStream.write(responsePacket)
                    outputStream.flush()
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "TCP forwarding error: ${e.message}", e)
            }
        }
    }
    
    private suspend fun forwardUDP(ipPacket: IPPacket, outputStream: FileOutputStream) {
        withContext(Dispatchers.IO) {
            try {
                // Create internal key for UDP mapping
                val internalKey = "${ipPacket.sourceIP}:${ipPacket.sourcePort}-" +
                                 "${ipPacket.destinationIP}:${ipPacket.destinationPort}"
                
                // Get or allocate external port for NAT
                val externalPort = udpPortMap.getOrPut(internalKey) {
                    allocatePort().also { port ->
                        reverseUdpMap[port] = internalKey
                        Log.d(TAG, "UDP NAT: $internalKey -> external port $port")
                    }
                }
                
                Log.d(TAG, "UDP Mapping: ${ipPacket.sourceIP}:${ipPacket.sourcePort} -> " +
                          "${ipPacket.destinationIP}:${ipPacket.destinationPort} " +
                          "(NAT port: $externalPort)")
                
                // Send UDP packet to real server
                val destAddress = InetAddress.getByName(ipPacket.destinationIP)
                val packet = DatagramPacket(
                    ipPacket.payload,
                    ipPacket.payload.size,
                    destAddress,
                    ipPacket.destinationPort
                )
                
                udpSocket.send(packet)
                
                // Wait for response (with timeout)
                val responseBuffer = ByteArray(32767)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                
                udpSocket.soTimeout = 5000 // 5 second timeout
                
                try {
                    udpSocket.receive(responsePacket)
                    
                    Log.d(TAG, "UDP Response: ${responsePacket.length} bytes from " +
                              "${responsePacket.address.hostAddress}:${responsePacket.port}")
                    
                    // Build response packet
                    val response = buildResponsePacket(
                        originalPacket = ipPacket,
                        payload = responseBuffer.copyOfRange(0, responsePacket.length),
                        protocol = IPPacket.PROTOCOL_UDP
                    )
                    
                    // Write back to TUN interface
                    outputStream.write(response)
                    outputStream.flush()
                    
                } catch (e: java.net.SocketTimeoutException) {
                    Log.w(TAG, "UDP timeout waiting for response from ${ipPacket.destinationIP}:${ipPacket.destinationPort}")
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "UDP forwarding error: ${e.message}", e)
            }
        }
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
     * Build response packet with swapped source/destination
     */
    private fun buildResponsePacket(
        originalPacket: IPPacket,
        payload: ByteArray,
        protocol: Int
    ): ByteArray {
        // Build IP header (swap source and destination)
        val ipHeader = buildIPv4Header(
            sourceIP = originalPacket.destinationIP,
            destIP = originalPacket.sourceIP,
            protocol = protocol,
            payloadLength = payload.size + if (protocol == IPPacket.PROTOCOL_TCP) 20 else 8
        )
        
        // Build transport header (swap ports)
        val transportHeader = when (protocol) {
            IPPacket.PROTOCOL_TCP -> buildTCPHeader(
                sourcePort = originalPacket.destinationPort,
                destPort = originalPacket.sourcePort
            )
            IPPacket.PROTOCOL_UDP -> buildUDPHeader(
                sourcePort = originalPacket.destinationPort,
                destPort = originalPacket.sourcePort,
                payloadLength = payload.size
            )
            else -> ByteArray(0)
        }
        
        return ipHeader + transportHeader + payload
    }
    
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
    
    private fun buildTCPHeader(sourcePort: Int, destPort: Int): ByteArray {
        val header = ByteArray(20)
        
        // Source port
        header[0] = (sourcePort shr 8).toByte()
        header[1] = sourcePort.toByte()
        
        // Destination port
        header[2] = (destPort shr 8).toByte()
        header[3] = destPort.toByte()
        
        // Sequence number (0)
        header[4] = 0
        header[5] = 0
        header[6] = 0
        header[7] = 0
        
        // Acknowledgment number (0)
        header[8] = 0
        header[9] = 0
        header[10] = 0
        header[11] = 0
        
        // Data offset (5 * 4 = 20 bytes) + flags (ACK)
        header[12] = 0x50.toByte()
        header[13] = 0x10.toByte() // ACK flag
        
        // Window size
        header[14] = 0xFF.toByte()
        header[15] = 0xFF.toByte()
        
        return header
    }
    
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
     * Clean up old connections
     */
    fun cleanupOldConnections() {
        scope.launch {
            val now = System.currentTimeMillis()
            val timeout = 5 * 60 * 1000 // 5 minutes
            
            // Clean TCP connections
            tcpConnections.entries.removeIf { (key, socketInfo) ->
                val isOld = (now - socketInfo.lastUsed) > timeout
                if (isOld) {
                    Log.d(TAG, "Cleaning up old TCP connection: $key")
                    try {
                        socketInfo.socket.close()
                    } catch (e: Exception) {
                        // Ignore
                    }
                }
                isOld
            }
            
            // Clean UDP mappings
            udpPortMap.entries.removeIf { (key, port) ->
                // Remove if not used recently (would need timestamp tracking)
                false // For now, keep all UDP mappings
            }
            
            Log.d(TAG, "Active connections: TCP=${tcpConnections.size}, UDP=${udpPortMap.size}")
        }
    }
    
    /**
     * Get connection statistics
     */
    fun getStats(): Map<String, Int> {
        return mapOf(
            "tcp_connections" to tcpConnections.size,
            "udp_mappings" to udpPortMap.size,
            "used_ports" to usedPorts.size
        )
    }
    
    /**
     * Cleanup all resources
     */
    fun cleanup() {
        // Close all TCP connections
        tcpConnections.values.forEach { socketInfo ->
            try {
                socketInfo.socket.close()
            } catch (e: Exception) {
                // Ignore
            }
        }
        tcpConnections.clear()
        
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
        
        // Cancel all coroutines
        scope.cancel()
        
        Log.i(TAG, "PacketForwarder cleaned up")
    }
}

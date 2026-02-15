package com.aifirewall.vpn

import android.util.Log
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.*

/**
 * TCP Forwarder
 * Handles forwarding of TCP packets to real destinations
 */
class TCPForwarder(
    private val connectionManager: TCPConnectionManager,
    private val tunOutput: FileOutputStream
) {
    
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    companion object {
        private const val TAG = "TCPForwarder"
        private const val SOCKET_TIMEOUT_MS = 30000  // 30 seconds
        private const val BUFFER_SIZE = 32767
        
        // TCP Flags
        const val TCP_FLAG_FIN = 0x01
        const val TCP_FLAG_SYN = 0x02
        const val TCP_FLAG_RST = 0x04
        const val TCP_FLAG_PSH = 0x08
        const val TCP_FLAG_ACK = 0x10
        const val TCP_FLAG_URG = 0x20
    }
    
    /**
     * Forward TCP packet to destination
     */
    fun forward(packet: IPPacket) {
        if (packet.protocol != IPPacket.PROTOCOL_TCP) {
            Log.w(TAG, "Not a TCP packet: protocol=${packet.protocol}")
            return
        }
        
        scope.launch {
            try {
                forwardTCP(packet)
            } catch (e: Exception) {
                Log.e(TAG, "Error forwarding TCP packet", e)
            }
        }
    }
    
    /**
     * Forward TCP packet
     */
    private suspend fun forwardTCP(packet: IPPacket) = withContext(Dispatchers.IO) {
        val flowKey = FlowKey(
            srcIp = packet.sourceIP,
            srcPort = packet.sourcePort,
            dstIp = packet.destinationIP,
            dstPort = packet.destinationPort,
            protocol = IPPacket.PROTOCOL_TCP
        )
        
        // Get or create connection
        val connection = connectionManager.getOrCreateConnection(flowKey) { key ->
            createSocket(key.dstIp, key.dstPort)
        }
        
        if (connection == null) {
            Log.w(TAG, "Failed to get connection for $flowKey")
            return@withContext
        }
        
        // Forward data if payload exists
        if (packet.payload.isNotEmpty()) {
            try {
                // Write to socket
                connection.socket.getOutputStream().write(packet.payload)
                connection.socket.getOutputStream().flush()
                
                // Record stats
                connectionManager.recordBytesSent(flowKey, packet.payload.size)
                
                Log.d(TAG, "Forwarded ${packet.payload.size} bytes to ${flowKey.dstIp}:${flowKey.dstPort}")
                
                // Start reading responses if not already reading
                if (!connection.isReading) {
                    connection.isReading = true
                    startResponseReader(connection)
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Error forwarding to $flowKey", e)
                connectionManager.removeConnection(flowKey)
            }
        }
    }
    
    /**
     * Create socket with timeout
     */
    private fun createSocket(dstIp: String, dstPort: Int): Socket {
        val socket = Socket()
        socket.soTimeout = SOCKET_TIMEOUT_MS
        socket.tcpNoDelay = true
        socket.keepAlive = true
        socket.connect(InetSocketAddress(dstIp, dstPort), SOCKET_TIMEOUT_MS)
        
        Log.d(TAG, "Created socket to $dstIp:$dstPort")
        return socket
    }
    
    /**
     * Start reading responses from socket
     */
    private fun startResponseReader(connection: TCPConnection) {
        scope.launch {
            try {
                readResponses(connection)
            } catch (e: Exception) {
                Log.e(TAG, "Error reading responses from ${connection.flowKey}", e)
            } finally {
                connection.isReading = false
                connectionManager.removeConnection(connection.flowKey)
            }
        }
    }
    
    /**
     * Read responses from socket and write to TUN
     */
    private suspend fun readResponses(connection: TCPConnection) = withContext(Dispatchers.IO) {
        val inputStream = connection.socket.getInputStream()
        val buffer = ByteArray(BUFFER_SIZE)
        
        Log.d(TAG, "Started reading responses from ${connection.flowKey}")
        
        while (connection.isActive()) {
            try {
                val bytesRead = inputStream.read(buffer)
                
                if (bytesRead <= 0) {
                    Log.d(TAG, "Connection closed by remote: ${connection.flowKey}")
                    break
                }
                
                // Build response packet
                val responsePacket = buildResponsePacket(
                    connection.flowKey,
                    buffer.copyOfRange(0, bytesRead)
                )
                
                // Write to TUN
                synchronized(tunOutput) {
                    tunOutput.write(responsePacket)
                    tunOutput.flush()
                }
                
                // Record stats
                connectionManager.recordBytesReceived(connection.flowKey, bytesRead)
                
                Log.d(TAG, "Sent $bytesRead bytes response to ${connection.flowKey.srcIp}:${connection.flowKey.srcPort}")
                
            } catch (e: java.net.SocketTimeoutException) {
                // Timeout is normal, continue reading
                continue
            } catch (e: Exception) {
                Log.e(TAG, "Error reading from ${connection.flowKey}", e)
                break
            }
        }
        
        Log.d(TAG, "Stopped reading responses from ${connection.flowKey}")
    }
    
    /**
     * Build TCP response packet
     */
    private fun buildResponsePacket(flowKey: FlowKey, payload: ByteArray): ByteArray {
        // Build IP header (swap source and destination)
        val ipHeader = buildIPv4Header(
            sourceIP = flowKey.dstIp,
            destIP = flowKey.srcIp,
            protocol = IPPacket.PROTOCOL_TCP,
            payloadLength = 20 + payload.size  // TCP header + payload
        )
        
        // Build TCP header (swap ports)
        val tcpHeader = buildTCPHeader(
            sourcePort = flowKey.dstPort,
            destPort = flowKey.srcPort,
            flags = TCP_FLAG_ACK or TCP_FLAG_PSH,  // ACK + PSH
            payloadLength = payload.size
        )
        
        return ipHeader + tcpHeader + payload
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
        
        // Version (4) + IHL (5) = 0x45
        header[0] = 0x45.toByte()
        
        // Type of Service
        header[1] = 0
        
        // Total Length
        val totalLength = 20 + payloadLength
        header[2] = (totalLength shr 8).toByte()
        header[3] = totalLength.toByte()
        
        // Identification (random)
        val id = (Math.random() * 65536).toInt()
        header[4] = (id shr 8).toByte()
        header[5] = id.toByte()
        
        // Flags + Fragment Offset (Don't Fragment)
        header[6] = 0x40.toByte()
        header[7] = 0
        
        // TTL
        header[8] = 64
        
        // Protocol
        header[9] = protocol.toByte()
        
        // Checksum (calculated later)
        header[10] = 0
        header[11] = 0
        
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
        
        // Calculate and set checksum
        val checksum = calculateChecksum(header)
        header[10] = (checksum shr 8).toByte()
        header[11] = checksum.toByte()
        
        return header
    }
    
    /**
     * Build TCP header
     */
    private fun buildTCPHeader(
        sourcePort: Int,
        destPort: Int,
        flags: Int,
        payloadLength: Int
    ): ByteArray {
        val header = ByteArray(20)
        
        // Source Port
        header[0] = (sourcePort shr 8).toByte()
        header[1] = sourcePort.toByte()
        
        // Destination Port
        header[2] = (destPort shr 8).toByte()
        header[3] = destPort.toByte()
        
        // Sequence Number (simplified - use 0)
        header[4] = 0
        header[5] = 0
        header[6] = 0
        header[7] = 0
        
        // Acknowledgment Number (simplified - use 0)
        header[8] = 0
        header[9] = 0
        header[10] = 0
        header[11] = 0
        
        // Data Offset (5 * 4 = 20 bytes) + Reserved
        header[12] = 0x50.toByte()
        
        // Flags
        header[13] = flags.toByte()
        
        // Window Size (max)
        header[14] = 0xFF.toByte()
        header[15] = 0xFF.toByte()
        
        // Checksum (0 for now - should calculate properly)
        header[16] = 0
        header[17] = 0
        
        // Urgent Pointer
        header[18] = 0
        header[19] = 0
        
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
     * Shutdown forwarder
     */
    fun shutdown() {
        Log.i(TAG, "Shutting down TCP forwarder...")
        scope.cancel()
        Log.i(TAG, "TCP forwarder shutdown complete")
    }
}

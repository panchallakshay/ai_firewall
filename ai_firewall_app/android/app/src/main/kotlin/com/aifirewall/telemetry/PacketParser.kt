package com.aifirewall.telemetry

import java.nio.ByteBuffer

/**
 * Network protocol types
 */
enum class Protocol(val value: Int) {
    TCP(6),
    UDP(17),
    UNKNOWN(-1);

    companion object {
        fun fromValue(value: Int): Protocol {
            return values().find { it.value == value } ?: UNKNOWN
        }
    }
}

/**
 * Parsed packet metadata
 */
data class PacketMetadata(
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val protocol: Protocol,
    val payloadSize: Int,
    val timestamp: Long = System.currentTimeMillis(),
    val tcpFlags: Int = 0  // For TCP: SYN, ACK, RST, FIN flags
)

/**
 * Packet parser for IPv4/TCP/UDP
 */
class PacketParser {
    
    /**
     * Parse raw IP packet from VPN tunnel
     * 
     * @param buffer ByteBuffer containing raw packet data
     * @return PacketMetadata or null if parsing fails
     */
    fun parse(buffer: ByteBuffer): PacketMetadata? {
        try {
            // Ensure we have at least IP header (20 bytes minimum)
            if (buffer.remaining() < 20) {
                return null
            }
            
            val startPosition = buffer.position()
            
            // Parse IP header
            val versionAndIHL = buffer.get().toInt() and 0xFF
            val version = (versionAndIHL shr 4) and 0x0F
            val ihl = (versionAndIHL and 0x0F) * 4  // Header length in bytes
            
            // Only support IPv4
            if (version != 4) {
                return null
            }
            
            // Skip TOS
            buffer.get()
            
            // Total length
            val totalLength = buffer.short.toInt() and 0xFFFF
            
            // Skip ID, flags, fragment offset
            buffer.getShort()
            buffer.getShort()
            
            // TTL
            buffer.get()
            
            // Protocol
            val protocolValue = buffer.get().toInt() and 0xFF
            val protocol = Protocol.fromValue(protocolValue)
            
            // Skip checksum
            buffer.getShort()
            
            // Source IP
            val srcIp = parseIpAddress(buffer)
            
            // Destination IP
            val dstIp = parseIpAddress(buffer)
            
            // Skip IP options if present
            val optionsLength = ihl - 20
            if (optionsLength > 0) {
                buffer.position(buffer.position() + optionsLength)
            }
            
            // Parse transport layer (TCP/UDP)
            val (srcPort, dstPort, tcpFlags) = when (protocol) {
                Protocol.TCP -> parseTcpHeader(buffer)
                Protocol.UDP -> parseUdpHeader(buffer)
                else -> Triple(0, 0, 0)
            }
            
            // Calculate payload size
            val headerSize = buffer.position() - startPosition
            val payloadSize = totalLength - headerSize
            
            return PacketMetadata(
                srcIp = srcIp,
                dstIp = dstIp,
                srcPort = srcPort,
                dstPort = dstPort,
                protocol = protocol,
                payloadSize = payloadSize,
                tcpFlags = tcpFlags
            )
            
        } catch (e: Exception) {
            // Parsing error - return null
            return null
        }
    }
    
    /**
     * Parse IP address from buffer
     */
    private fun parseIpAddress(buffer: ByteBuffer): String {
        val bytes = ByteArray(4)
        buffer.get(bytes)
        return bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }
    
    /**
     * Parse TCP header
     * Returns: (srcPort, dstPort, flags)
     */
    private fun parseTcpHeader(buffer: ByteBuffer): Triple<Int, Int, Int> {
        if (buffer.remaining() < 20) {
            return Triple(0, 0, 0)
        }
        
        val srcPort = buffer.short.toInt() and 0xFFFF
        val dstPort = buffer.short.toInt() and 0xFFFF
        
        // Skip sequence and ack numbers
        buffer.getInt()
        buffer.getInt()
        
        // Data offset and flags
        val offsetAndFlags = buffer.short.toInt() and 0xFFFF
        val flags = offsetAndFlags and 0xFF
        
        return Triple(srcPort, dstPort, flags)
    }
    
    /**
     * Parse UDP header
     * Returns: (srcPort, dstPort, 0)
     */
    private fun parseUdpHeader(buffer: ByteBuffer): Triple<Int, Int, Int> {
        if (buffer.remaining() < 8) {
            return Triple(0, 0, 0)
        }
        
        val srcPort = buffer.short.toInt() and 0xFFFF
        val dstPort = buffer.short.toInt() and 0xFFFF
        
        return Triple(srcPort, dstPort, 0)
    }
}

/**
 * TCP flags
 */
object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
    const val URG = 0x20
    
    fun hasFlag(flags: Int, flag: Int): Boolean {
        return (flags and flag) != 0
    }
    
    fun isSyn(flags: Int) = hasFlag(flags, SYN)
    fun isAck(flags: Int) = hasFlag(flags, ACK)
    fun isRst(flags: Int) = hasFlag(flags, RST)
    fun isFin(flags: Int) = hasFlag(flags, FIN)
}

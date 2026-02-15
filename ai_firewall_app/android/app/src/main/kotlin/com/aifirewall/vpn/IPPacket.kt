package com.aifirewall.vpn

import java.nio.ByteBuffer

/**
 * IP Packet Parser
 * Parses IPv4 and IPv6 packets from TUN interface
 */
class IPPacket(
    val version: Int,
    val protocol: Int,
    val sourceIP: String,
    val destinationIP: String,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray,
    val rawPacket: ByteArray
) {
    
    companion object {
        const val PROTOCOL_TCP = 6
        const val PROTOCOL_UDP = 17
        const val PROTOCOL_ICMP = 1
        
        fun parse(packet: ByteArray): IPPacket? {
            if (packet.isEmpty()) return null
            
            val buffer = ByteBuffer.wrap(packet)
            
            // Read IP version (first 4 bits)
            val versionAndIHL = buffer.get(0).toInt() and 0xFF
            val version = (versionAndIHL shr 4) and 0x0F
            
            return when (version) {
                4 -> parseIPv4(packet, buffer)
                6 -> parseIPv6(packet, buffer)
                else -> null
            }
        }
        
        private fun parseIPv4(packet: ByteArray, buffer: ByteBuffer): IPPacket? {
            try {
                // IP Header Length (in 32-bit words)
                val ihl = (buffer.get(0).toInt() and 0x0F) * 4
                
                // Protocol
                val protocol = buffer.get(9).toInt() and 0xFF
                
                // Source IP
                val srcIP = "${buffer.get(12).toInt() and 0xFF}." +
                           "${buffer.get(13).toInt() and 0xFF}." +
                           "${buffer.get(14).toInt() and 0xFF}." +
                           "${buffer.get(15).toInt() and 0xFF}"
                
                // Destination IP
                val dstIP = "${buffer.get(16).toInt() and 0xFF}." +
                           "${buffer.get(17).toInt() and 0xFF}." +
                           "${buffer.get(18).toInt() and 0xFF}." +
                           "${buffer.get(19).toInt() and 0xFF}"
                
                // Parse transport layer
                var srcPort = 0
                var dstPort = 0
                
                if (protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP) {
                    // Source port (2 bytes)
                    srcPort = ((buffer.get(ihl).toInt() and 0xFF) shl 8) or
                             (buffer.get(ihl + 1).toInt() and 0xFF)
                    
                    // Destination port (2 bytes)
                    dstPort = ((buffer.get(ihl + 2).toInt() and 0xFF) shl 8) or
                             (buffer.get(ihl + 3).toInt() and 0xFF)
                }
                
                // Payload
                val payload = packet.copyOfRange(ihl, packet.size)
                
                return IPPacket(
                    version = 4,
                    protocol = protocol,
                    sourceIP = srcIP,
                    destinationIP = dstIP,
                    sourcePort = srcPort,
                    destinationPort = dstPort,
                    payload = payload,
                    rawPacket = packet
                )
                
            } catch (e: Exception) {
                return null
            }
        }
        
        private fun parseIPv6(packet: ByteArray, buffer: ByteBuffer): IPPacket? {
            try {
                // Next Header (protocol)
                val protocol = buffer.get(6).toInt() and 0xFF
                
                // Source IP (16 bytes)
                val srcIP = formatIPv6(packet.copyOfRange(8, 24))
                
                // Destination IP (16 bytes)
                val dstIP = formatIPv6(packet.copyOfRange(24, 40))
                
                // Parse transport layer
                var srcPort = 0
                var dstPort = 0
                
                if (protocol == PROTOCOL_TCP || protocol == PROTOCOL_UDP) {
                    // IPv6 header is always 40 bytes
                    srcPort = ((buffer.get(40).toInt() and 0xFF) shl 8) or
                             (buffer.get(41).toInt() and 0xFF)
                    
                    dstPort = ((buffer.get(42).toInt() and 0xFF) shl 8) or
                             (buffer.get(43).toInt() and 0xFF)
                }
                
                // Payload
                val payload = packet.copyOfRange(40, packet.size)
                
                return IPPacket(
                    version = 6,
                    protocol = protocol,
                    sourceIP = srcIP,
                    destinationIP = dstIP,
                    sourcePort = srcPort,
                    destinationPort = dstPort,
                    payload = payload,
                    rawPacket = packet
                )
                
            } catch (e: Exception) {
                return null
            }
        }
        
        private fun formatIPv6(bytes: ByteArray): String {
            val parts = mutableListOf<String>()
            for (i in 0 until 16 step 2) {
                val value = ((bytes[i].toInt() and 0xFF) shl 8) or
                           (bytes[i + 1].toInt() and 0xFF)
                parts.add(value.toString(16))
            }
            return parts.joinToString(":")
        }
    }
    
    fun getProtocolName(): String {
        return when (protocol) {
            PROTOCOL_TCP -> "TCP"
            PROTOCOL_UDP -> "UDP"
            PROTOCOL_ICMP -> "ICMP"
            else -> "Unknown($protocol)"
        }
    }
}

/**
 * TCP Packet Builder
 */
object TCPPacket {
    
    fun createRST(ipPacket: IPPacket): ByteArray {
        // Create TCP RST packet to notify app that connection is blocked
        
        // Build IP header
        val ipHeader = buildIPv4Header(
            sourceIP = ipPacket.destinationIP,
            destIP = ipPacket.sourceIP,
            protocol = IPPacket.PROTOCOL_TCP,
            payloadLength = 20 // TCP header only
        )
        
        // Build TCP header with RST flag
        val tcpHeader = buildTCPHeader(
            sourcePort = ipPacket.destinationPort,
            destPort = ipPacket.sourcePort,
            flags = 0x04 // RST flag
        )
        
        return ipHeader + tcpHeader
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
    
    private fun buildTCPHeader(
        sourcePort: Int,
        destPort: Int,
        flags: Int
    ): ByteArray {
        val header = ByteArray(20)
        
        // Source port
        header[0] = (sourcePort shr 8).toByte()
        header[1] = sourcePort.toByte()
        
        // Destination port
        header[2] = (destPort shr 8).toByte()
        header[3] = destPort.toByte()
        
        // Data offset (5 * 4 = 20 bytes) + flags
        header[12] = 0x50.toByte() // Data offset
        header[13] = flags.toByte()
        
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
}

/**
 * ICMP Packet Builder
 */
object ICMPPacket {
    
    fun createUnreachable(ipPacket: IPPacket): ByteArray {
        // Create ICMP Destination Unreachable packet
        
        // Build IP header
        val ipHeader = buildIPv4Header(
            sourceIP = ipPacket.destinationIP,
            destIP = ipPacket.sourceIP,
            protocol = IPPacket.PROTOCOL_ICMP,
            payloadLength = 8 + 20 // ICMP header + original IP header
        )
        
        // Build ICMP header
        val icmpHeader = ByteArray(8)
        icmpHeader[0] = 3 // Type: Destination Unreachable
        icmpHeader[1] = 3 // Code: Port Unreachable
        
        // Calculate checksum
        val checksum = TCPPacket.calculateChecksum(icmpHeader)
        icmpHeader[2] = (checksum shr 8).toByte()
        icmpHeader[3] = checksum.toByte()
        
        // Include original IP header
        val originalHeader = ipPacket.rawPacket.copyOfRange(0, 20.coerceAtMost(ipPacket.rawPacket.size))
        
        return ipHeader + icmpHeader + originalHeader
    }
    
    private fun buildIPv4Header(
        sourceIP: String,
        destIP: String,
        protocol: Int,
        payloadLength: Int
    ): ByteArray {
        return TCPPacket.buildIPv4Header(sourceIP, destIP, protocol, payloadLength)
    }
}

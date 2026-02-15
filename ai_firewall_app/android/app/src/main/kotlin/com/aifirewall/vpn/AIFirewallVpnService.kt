package com.aifirewall.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import kotlinx.coroutines.*

/**
 * Complete Local VPN Service with TUN Interface
 * Captures ALL network traffic, analyzes with AI, and forwards if safe
 */
class AIFirewallVpnService : VpnService() {
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    // Packet processing
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null
    
    // AI and Decision Engine
    private lateinit var packetAnalyzer: PacketAnalyzer
    private lateinit var unifiedForwarder: UnifiedPacketForwarder
    
    companion object {
        private const val TAG = "AIFirewallVPN"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "ai_firewall_vpn"
        
        const val ACTION_START = "com.aifirewall.START_VPN"
        const val ACTION_STOP = "com.aifirewall.STOP_VPN"
    }
    
    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "VPN Service created")
        
        // Initialize components
        packetAnalyzer = PacketAnalyzer(this)
        
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVPN()
            ACTION_STOP -> stopVPN()
        }
        return START_STICKY
    }
    
    private fun startVPN() {
        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return
        }
        
        try {
            // Create TUN interface
            vpnInterface = createTunInterface()
            
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to create TUN interface")
                stopSelf()
                return
            }
            
            // Get input/output streams
            inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
            outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            
            // Initialize unified forwarder with output stream
            unifiedForwarder = UnifiedPacketForwarder(outputStream!!)
            
            isRunning = true
            
            // Start foreground notification
            startForeground(NOTIFICATION_ID, createNotification())
            
            // Start packet processing
            startPacketProcessing()
            
            Log.i(TAG, "VPN started successfully")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN", e)
            stopVPN()
        }
    }
    
    private fun createTunInterface(): ParcelFileDescriptor? {
        return Builder()
            // Set VPN address (local)
            .addAddress("10.0.0.2", 24)
            
            // Set DNS servers
            .addDnsServer("1.1.1.1")  // Cloudflare
            .addDnsServer("8.8.8.8")  // Google
            
            // Route all traffic through VPN
            .addRoute("0.0.0.0", 0)
            
            // Set MTU (Maximum Transmission Unit)
            .setMtu(1500)
            
            // Set session name
            .setSession("AI Firewall")
            
            // Block traffic until VPN is ready
            .setBlocking(false)
            
            // Configure split tunneling (optional - exclude certain apps)
            // .addDisallowedApplication("com.android.vending") // Exclude Play Store
            
            .establish()
    }
    
    private fun startPacketProcessing() {
        // Launch packet reader
        scope.launch {
            readPackets()
        }
        
        Log.i(TAG, "Packet processing started")
    }
    
    private suspend fun readPackets() {
        val buffer = ByteBuffer.allocate(32767) // Max IP packet size
        val channel = FileChannel.open(
            java.nio.file.Paths.get("/proc/self/fd/${vpnInterface!!.fd}"),
            java.nio.file.StandardOpenOption.READ
        )
        
        try {
            while (isRunning && !Thread.currentThread().isInterrupted) {
                buffer.clear()
                
                // Read packet from TUN interface
                val length = channel.read(buffer)
                
                if (length > 0) {
                    buffer.flip()
                    
                    // Extract packet data
                    val packet = ByteArray(length)
                    buffer.get(packet)
                    
                    // Process packet
                    processPacket(packet)
                }
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e(TAG, "Error reading packets", e)
            }
        }
    }
    
    private suspend fun processPacket(packet: ByteArray) {
        try {
            // Parse IP packet
            val ipPacket = IPPacket.parse(packet)
            
            if (ipPacket == null) {
                Log.w(TAG, "Failed to parse IP packet")
                return
            }
            
            // Analyze packet with AI and rules
            val decision = packetAnalyzer.analyze(ipPacket)
            
            // Log decision
            Log.d(TAG, "Packet ${ipPacket.destinationIP}:${ipPacket.destinationPort} -> ${decision.action}")
            
            // Handle based on decision
            when (decision.action) {
                "ALLOW" -> {
                    // Forward packet to internet
                    forwardPacket(ipPacket)
                }
                "WARN" -> {
                    // Forward but log warning
                    forwardPacket(ipPacket)
                    logThreat(decision, "WARN")
                }
                "BLOCK_SOFT", "BLOCK_HARD" -> {
                    // Block packet (don't forward)
                    logThreat(decision, "BLOCKED")
                    
                    // Optionally send RST/ICMP unreachable
                    sendBlockResponse(ipPacket)
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet", e)
        }
    }
    
    private fun forwardPacket(ipPacket: IPPacket) {
        try {
            // Forward packet to real network interface (TCP or UDP)
            unifiedForwarder.forward(ipPacket)
        } catch (e: Exception) {
            Log.e(TAG, "Error forwarding packet", e)
        }
    }
    
    private fun sendBlockResponse(ipPacket: IPPacket) {
        // Send TCP RST or ICMP unreachable to notify app
        when (ipPacket.protocol) {
            IPPacket.PROTOCOL_TCP -> {
                val rst = TCPPacket.createRST(ipPacket)
                writePacket(rst)
            }
            IPPacket.PROTOCOL_UDP -> {
                val icmp = ICMPPacket.createUnreachable(ipPacket)
                writePacket(icmp)
            }
        }
    }
    
    private fun writePacket(packet: ByteArray) {
        try {
            outputStream?.write(packet)
        } catch (e: Exception) {
            Log.e(TAG, "Error writing packet", e)
        }
    }
    
    private fun logThreat(decision: PacketDecision, status: String) {
        // Log to database for activity log
        scope.launch {
            try {
                val db = FirewallDatabase.getInstance(this@AIFirewallVpnService)
                db.activityLogDao().insert(
                    ActivityLogEntity(
                        timestamp = System.currentTimeMillis(),
                        action = decision.action,
                        domain = decision.domain ?: "",
                        ipAddress = decision.destinationIP,
                        port = decision.destinationPort,
                        protocol = decision.protocol,
                        reason = decision.reason,
                        appName = "Unknown", // Placeholder
                        dataUsage = 0 // Placeholder
                    )
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error logging threat", e)
            }
        }
    }
    
    private fun stopVPN() {
        if (!isRunning) return
        
        isRunning = false
        
        try {
            // Shutdown unified forwarder
            if (::unifiedForwarder.isInitialized) {
                unifiedForwarder.shutdown()
            }
            
            // Close streams
            inputStream?.close()
            outputStream?.close()
            
            // Close VPN interface
            vpnInterface?.close()
            
            // Cancel all coroutines
            scope.cancel()
            
            // Stop foreground
            stopForeground(true)
            
            Log.i(TAG, "VPN stopped")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping VPN", e)
        } finally {
            stopSelf()
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        stopVPN()
        Log.i(TAG, "VPN Service destroyed")
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "AI Firewall VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "AI Firewall is protecting your device"
                setShowBadge(false)
            }
            
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        val stopIntent = Intent(this, AIFirewallVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AI Firewall Active")
            .setContentText("Your device is protected")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .addAction(
                android.R.drawable.ic_delete,
                "Stop",
                stopPendingIntent
            )
            .build()
    }
}

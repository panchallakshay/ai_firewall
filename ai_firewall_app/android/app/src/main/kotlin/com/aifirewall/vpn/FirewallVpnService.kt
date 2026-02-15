package com.aifirewall.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.aifirewall.decision.FirewallDecisionEngine
import com.aifirewall.telemetry.PacketParser
import com.aifirewall.telemetry.FlowTracker
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * FirewallVpnService - Main VPN service for AI Firewall
 * 
 * Architecture:
 * 1. Create TUN interface (virtual network device)
 * 2. Route ALL traffic through TUN (0.0.0.0/0)
 * 3. Read packets from TUN interface
 * 4. Parse and analyze packets
 * 5. Make firewall decision (AI + Rules)
 * 6. Forward allowed packets to real network
 * 7. Drop blocked packets
 * 
 * Why VPN?
 * - Only way to intercept ALL network traffic on Android
 * - No root required
 * - Works for all apps
 * - User-controlled (can enable/disable)
 * 
 * IMPORTANT: This is a LOCAL VPN
 * - Does NOT route through external VPN server
 * - Does NOT change IP address or location
 * - Only inspects and filters traffic locally
 */
class FirewallVpnService : VpnService() {
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private val isRunning = AtomicBoolean(false)
    
    // Core components
    private lateinit var decisionEngine: FirewallDecisionEngine
    private lateinit var packetParser: PacketParser
    private lateinit var flowTracker: FlowTracker
    private lateinit var dnsParser: DnsParser
    
    // Packet I/O
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null
    
    // Statistics
    private var packetsProcessed = 0L
    private var packetsBlocked = 0L
    private var packetsAllowed = 0L
    
    companion object {
        private const val NOTIFICATION_CHANNEL_ID = "firewall_vpn_channel"
        private const val NOTIFICATION_ID = 1
        private const val MTU = 1500  // Maximum Transmission Unit
        
        // VPN configuration
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"  // Route all traffic
        private const val VPN_ROUTE_PREFIX = 0   // /0 = all IPs
    }
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize components
        decisionEngine = FirewallDecisionEngine(this)
        decisionEngine.initialize()
        
        packetParser = PacketParser()
        flowTracker = FlowTracker()
        dnsParser = DnsParser()
        
        android.util.Log.i("FirewallVpnService", "VPN Service created")
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP_VPN") {
            stopVpn()
            return START_NOT_STICKY
        }
        
        startVpn()
        return START_STICKY
    }
    
    /**
     * Start VPN service
     */
    private fun startVpn() {
        if (isRunning.get()) {
            android.util.Log.w("FirewallVpnService", "VPN already running")
            return
        }
        
        try {
            // Create notification channel (required for foreground service)
            createNotificationChannel()
            
            // Start foreground service with notification
            val notification = createNotification()
            startForeground(NOTIFICATION_ID, notification)
            
            // Establish VPN connection
            vpnInterface = establishVpn()
            
            if (vpnInterface == null) {
                android.util.Log.e("FirewallVpnService", "Failed to establish VPN")
                stopSelf()
                return
            }
            
            // Get input/output streams
            inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
            outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            
            isRunning.set(true)
            
            // Start packet processing thread
            thread(name = "PacketProcessor") {
                processPackets()
            }
            
            android.util.Log.i("FirewallVpnService", "VPN started successfully")
            
        } catch (e: Exception) {
            android.util.Log.e("FirewallVpnService", "Failed to start VPN", e)
            stopSelf()
        }
    }
    
    /**
     * Establish VPN connection
     * Creates TUN interface and routes all traffic through it
     */
    private fun establishVpn(): ParcelFileDescriptor? {
        return Builder()
            // Set VPN address (our local VPN endpoint)
            .addAddress(VPN_ADDRESS, 32)
            
            // Route ALL traffic through VPN (0.0.0.0/0)
            .addRoute(VPN_ROUTE, VPN_ROUTE_PREFIX)
            
            // Set MTU (Maximum Transmission Unit)
            .setMtu(MTU)
            
            // Set session name (shown in Android VPN settings)
            .setSession("AI Firewall")
            
            // Configure DNS (use system DNS)
            .addDnsServer("8.8.8.8")  // Google DNS as fallback
            .addDnsServer("8.8.4.4")
            
            // Allow all apps by default (can be configured later)
            // .addAllowedApplication("com.example.app")  // Whitelist specific apps
            // .addDisallowedApplication("com.example.app")  // Blacklist specific apps
            
            // Set blocking mode (true = block connections when VPN is down)
            .setBlocking(false)
            
            // Establish connection
            .establish()
    }
    
    /**
     * Main packet processing loop
     * Reads packets from TUN, analyzes them, and forwards/drops based on decision
     */
    private fun processPackets() {
        val packet = ByteBuffer.allocate(MTU)
        
        android.util.Log.i("FirewallVpnService", "Packet processing started")
        
        while (isRunning.get()) {
            try {
                // Clear buffer for next packet
                packet.clear()
                
                // Read packet from TUN interface
                val length = inputStream?.read(packet.array()) ?: -1
                
                if (length <= 0) {
                    // No data or error
                    Thread.sleep(10)
                    continue
                }
                
                // Set buffer limit to actual packet size
                packet.limit(length)
                
                // Process packet
                handlePacket(packet)
                
                packetsProcessed++
                
            } catch (e: InterruptedException) {
                android.util.Log.i("FirewallVpnService", "Packet processing interrupted")
                break
            } catch (e: Exception) {
                android.util.Log.e("FirewallVpnService", "Error processing packet", e)
            }
        }
        
        android.util.Log.i("FirewallVpnService", "Packet processing stopped")
    }
    
    /**
     * Handle individual packet
     * 
     * Flow:
     * 1. Parse packet (extract metadata)
     * 2. Track flow statistics
     * 3. Make firewall decision (AI + Rules)
     * 4. Forward or drop packet
     */
    private fun handlePacket(packet: ByteBuffer) {
        try {
            // Parse packet
            val metadata = packetParser.parse(packet) ?: return
            
            // Determine if packet is outbound or inbound
            val isOutbound = metadata.srcIp.startsWith("10.0.0.")  // From our VPN address
            
            // Track flow statistics
            flowTracker.trackPacket(metadata, isOutbound)
            val flowKey = flowTracker.getFlowKey(metadata)
            val flowStats = flowTracker.getFlowStats(flowKey) ?: return
            
            // Extract domain if DNS query
            val domain = if (dnsParser.isDnsQuery(metadata.dstPort, metadata.protocol.toString())) {
                // Calculate UDP payload offset (IP header + UDP header)
                val ipHeaderLength = (packet.get(0).toInt() and 0x0F) * 4
                val udpPayloadOffset = ipHeaderLength + 8  // UDP header is 8 bytes
                dnsParser.extractDomainFromQuery(packet, udpPayloadOffset)
            } else null
            
            // Make firewall decision
            val decision = decisionEngine.evaluate(
                domain = domain,
                flowStats = flowStats,
                dstIp = metadata.dstIp
            )
            
            // Apply decision
            when {
                decision.shouldBlock() -> {
                    // Drop packet
                    packetsBlocked++
                    
                    android.util.Log.d("FirewallVpnService", 
                        "BLOCKED: ${metadata.dstIp}:${metadata.dstPort} - ${decision.reason}")
                    
                    // TODO: Show notification for BLOCK_SOFT
                    // TODO: Log decision for activity log
                }
                decision.shouldWarn() -> {
                    // Allow but warn
                    forwardPacket(packet)
                    packetsAllowed++
                    
                    android.util.Log.d("FirewallVpnService", 
                        "WARNED: ${metadata.dstIp}:${metadata.dstPort} - ${decision.reason}")
                    
                    // TODO: Show warning notification
                }
                else -> {
                    // Allow
                    forwardPacket(packet)
                    packetsAllowed++
                }
            }
            
        } catch (e: Exception) {
            android.util.Log.e("FirewallVpnService", "Error handling packet", e)
            // On error, allow packet (fail-open)
            forwardPacket(packet)
        }
    }
    
    /**
     * Forward packet to real network
     * Writes packet back to TUN interface for delivery
     */
    private fun forwardPacket(packet: ByteBuffer) {
        try {
            outputStream?.write(packet.array(), 0, packet.limit())
        } catch (e: Exception) {
            android.util.Log.e("FirewallVpnService", "Error forwarding packet", e)
        }
    }
    
    /**
     * Extract domain from DNS query packet
     * TODO: Implement proper DNS parsing
     */
    private fun extractDomainFromDnsQuery(packet: ByteBuffer): String? {
        // Simplified DNS parsing - implement full parser later
        return null
    }
    
    /**
     * Stop VPN service
     */
    private fun stopVpn() {
        android.util.Log.i("FirewallVpnService", "Stopping VPN...")
        
        isRunning.set(false)
        
        // Close streams
        try {
            inputStream?.close()
            outputStream?.close()
        } catch (e: Exception) {
            android.util.Log.e("FirewallVpnService", "Error closing streams", e)
        }
        
        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            android.util.Log.e("FirewallVpnService", "Error closing VPN interface", e)
        }
        
        // Cleanup
        decisionEngine.shutdown()
        
        // Log statistics
        android.util.Log.i("FirewallVpnService", 
            "VPN stopped. Stats: Processed=$packetsProcessed, Allowed=$packetsAllowed, Blocked=$packetsBlocked")
        
        stopForeground(true)
        stopSelf()
    }
    
    /**
     * Create notification channel (required for Android O+)
     */
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "AI Firewall VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "AI Firewall VPN Service"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    /**
     * Create foreground service notification
     */
    private fun createNotification(): Notification {
        // TODO: Create proper MainActivity intent
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(),  // TODO: Replace with MainActivity intent
            PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("AI Firewall Active")
            .setContentText("Protecting your device from threats")
            .setSmallIcon(android.R.drawable.ic_dialog_info)  // TODO: Replace with app icon
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
    
    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
        android.util.Log.i("FirewallVpnService", "VPN Service destroyed")
    }
    
    override fun onRevoke() {
        super.onRevoke()
        android.util.Log.i("FirewallVpnService", "VPN permission revoked")
        stopVpn()
    }
}

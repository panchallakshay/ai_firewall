# Code Examples - Shakti Packet Bridge

Practical examples for integrating the C++ packet bridge.

## Example 1: Basic VPN Service Integration

```kotlin
package com.shakti.firewall

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.shakti.bridge.PacketBridge
import com.shakti.bridge.PacketMetadata
import com.shakti.bridge.PythonCallback

class BasicVpnService : VpnService() {
    
    private lateinit var packetBridge: PacketBridge
    private var vpnInterface: ParcelFileDescriptor? = null
    
    companion object {
        private const val TAG = "BasicVpnService"
    }
    
    override fun onCreate() {
        super.onCreate()
        packetBridge = PacketBridge()
        Log.i(TAG, "VPN Service created")
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startVpn()
        return START_STICKY
    }
    
    private fun startVpn() {
        // Build VPN interface
        vpnInterface = Builder()
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .setSession("Shakti Firewall")
            .setMtu(1500)
            .establish()
        
        if (vpnInterface == null) {
            Log.e(TAG, "Failed to establish VPN")
            stopSelf()
            return
        }
        
        // Initialize packet bridge
        val vpnFd = vpnInterface!!.fileDescriptor.fd
        if (!packetBridge.init(vpnFd)) {
            Log.e(TAG, "Failed to initialize packet bridge")
            stopSelf()
            return
        }
        
        // Start packet processing
        if (!packetBridge.start()) {
            Log.e(TAG, "Failed to start packet bridge")
            stopSelf()
            return
        }
        
        Log.i(TAG, "VPN started with packet bridge")
    }
    
    override fun onDestroy() {
        Log.i(TAG, "Stopping VPN service")
        
        // Cleanup bridge
        packetBridge.stop()
        packetBridge.shutdown()
        
        // Close VPN interface
        vpnInterface?.close()
        
        super.onDestroy()
    }
}
```

---

## Example 2: VPN Service with AI Threat Detection

```kotlin
class AiFirewallVpnService : VpnService() {
    
    private lateinit var packetBridge: PacketBridge
    private val blockedIps = mutableSetOf<String>()
    
    override fun onCreate() {
        super.onCreate()
        
        packetBridge = PacketBridge()
        
        // Register Python AI callback
        packetBridge.setPythonCallback(object : PythonCallback {
            override fun onThreatDetected(metadata: PacketMetadata, threatInfo: String) {
                handleThreat(metadata, threatInfo)
            }
            
            override fun onPacketAnalyzed(metadata: PacketMetadata, result: String) {
                logPacketAnalysis(metadata, result)
            }
        })
    }
    
    private fun handleThreat(metadata: PacketMetadata, info: String) {
        Log.w(TAG, "THREAT DETECTED: ${metadata.dstIp} - $info")
        
        // Block malicious IP
        blockedIps.add(metadata.dstIp)
        
        // Show notification
        showThreatNotification(
            title = "Threat Blocked",
            message = "Blocked connection to ${metadata.dstIp}\n$info"
        )
        
        // Log to database
        saveThreatToDatabase(metadata, info)
    }
    
    private fun showThreatNotification(title: String, message: String) {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        
        NotificationManagerCompat.from(this)
            .notify(THREAT_NOTIFICATION_ID, notification)
    }
    
    private fun saveThreatToDatabase(metadata: PacketMetadata, info: String) {
        // Save to Room database for activity log
        CoroutineScope(Dispatchers.IO).launch {
            database.threatDao().insert(
                ThreatEntity(
                    timestamp = metadata.timestampMs,
                    sourceIp = metadata.srcIp,
                    destIp = metadata.dstIp,
                    destPort = metadata.dstPort,
                    protocol = if (metadata.isTCP()) "TCP" else "UDP",
                    threatInfo = info
                )
            )
        }
    }
}
```

---

## Example 3: Manual Packet Processing

```kotlin
class ManualPacketProcessor(private val vpnFd: Int) {
    
    private val bridge = PacketBridge()
    private val buffer = ByteArray(32767)
    
    fun init() {
        bridge.init(vpnFd)
        // Don't call start() - we'll process manually
    }
    
    fun processNextPacket(inputStream: FileInputStream): Boolean {
        val length = inputStream.read(buffer)
        if (length <= 0) return false
        
        // Process packet through bridge
        val packet = buffer.copyOf(length)
        return bridge.processPacket(packet)
    }
    
    fun runProcessingLoop(inputStream: FileInputStream) {
        Thread {
            while (true) {
                try {
                    processNextPacket(inputStream)
                } catch (e: Exception) {
                    Log.e(TAG, "Error processing packet", e)
                    break
                }
            }
        }.start()
    }
    
    fun shutdown() {
        bridge.shutdown()
    }
}
```

---

## Example 4: Packet Analysis Dashboard

```kotlin
class PacketDashboardActivity : AppCompatActivity() {
    
    private lateinit var bridge: PacketBridge
    private val handler = Handler(Looper.getMainLooper())
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_dashboard)
        
        // Assume bridge is already running in VPN service
        // This is just for displaying stats
        
        startStatsMonitoring()
    }
    
    private fun startStatsMonitoring() {
        handler.postDelayed(object : Runnable {
            override fun run() {
                updateStats()
                handler.postDelayed(this, 1000) // Update every second
            }
        }, 1000)
    }
    
    private fun updateStats() {
        val stats = bridge.getStats() ?: return
        
        binding.apply {
            tvPacketsCaptured.text = stats.packetsCaptured.toString()
            tvPacketsForwarded.text = stats.packetsForwarded.toString()
            tvPacketsDropped.text = stats.packetsDropped.toString()
            tvBytesProcessed.text = formatBytes(stats.bytesProcessed)
            tvSuccessRate.text = String.format("%.1f%%", stats.successRate)
            
            // Update progress bar
            progressSuccess.progress = stats.successRate.toInt()
        }
    }
    
    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "${bytes / 1024} KB"
            bytes < 1024 * 1024 * 1024 -> "${bytes / (1024 * 1024)} MB"
            else -> "${bytes / (1024 * 1024 * 1024)} GB"
        }
    }
}
```

---

## Example 5: Packet Inspection Tool

```kotlin
object PacketInspector {
    
    fun analyzePacket(packetBytes: ByteArray): PacketInfo {
        val metadata = PacketBridge.nativeParsePacket(packetBytes)
            ?: return PacketInfo.Invalid
        
        return PacketInfo(
            protocol = when (metadata.protocol) {
                6 -> "TCP"
                17 -> "UDP"
                1 -> "ICMP"
                else -> "Unknown"
            },
            source = "${metadata.srcIp}:${metadata.srcPort}",
            destination = "${metadata.dstIp}:${metadata.dstPort}",
            size = metadata.payloadSize,
            direction = if (metadata.isOutbound()) "Outbound" else "Inbound",
            timestamp = Date(metadata.timestampMs)
        )
    }
    
    fun isHttps(metadata: PacketMetadata): Boolean {
        return metadata.isTCP() && (metadata.dstPort == 443 || metadata.srcPort == 443)
    }
    
    fun isDns(metadata: PacketMetadata): Boolean {
        return metadata.isUDP() && (metadata.dstPort == 53 || metadata.srcPort == 53)
    }
    
    data class PacketInfo(
        val protocol: String,
        val source: String,
        val destination: String,
        val size: Long,
        val direction: String,
        val timestamp: Date
    ) {
        companion object {
            val Invalid = PacketInfo("", "", "", 0, "", Date())
        }
    }
}
```

---

## Example 6: Connection Tracking

```kotlin
class ConnectionTracker {
    
    private val connections = ConcurrentHashMap<String, ConnectionInfo>()
    
    fun trackPacket(metadata: PacketMetadata) {
        val key = "${metadata.srcIp}:${metadata.srcPort}->${metadata.dstIp}:${metadata.dstPort}"
        
        connections.compute(key) { _, existing ->
            if (existing == null) {
                ConnectionInfo(
                    firstSeen = metadata.timestampMs,
                    lastSeen = metadata.timestampMs,
                    packetCount = 1,
                    totalBytes = metadata.payloadSize
                )
            } else {
                existing.copy(
                    lastSeen = metadata.timestampMs,
                    packetCount = existing.packetCount + 1,
                    totalBytes = existing.totalBytes + metadata.payloadSize
                )
            }
        }
    }
    
    fun getActiveConnections(): List<ConnectionSummary> {
        val now = System.currentTimeMillis()
        val timeout = 60_000 // 1 minute
        
        return connections
            .filter { (_, info) -> now - info.lastSeen < timeout }
            .map { (key, info) ->
                val parts = key.split("->")
                ConnectionSummary(
                    source = parts[0],
                    destination = parts[1],
                    duration = info.lastSeen - info.firstSeen,
                    packetCount = info.packetCount,
                    totalBytes = info.totalBytes,
                    avgBytesPerSecond = info.totalBytes * 1000 / (info.lastSeen - info.firstSeen + 1)
                )
            }
    }
    
    data class ConnectionInfo(
        val firstSeen: Long,
        val lastSeen: Long,
        val packetCount: Long,
        val totalBytes: Long
    )
    
    data class ConnectionSummary(
        val source: String,
        val destination: String,
        val duration: Long,
        val packetCount: Long,
        val totalBytes: Long,
        val avgBytesPerSecond: Long
    )
}
```

---

## Example 7: Error Handling

```kotlin
class RobustVpnService : VpnService() {
    
    private lateinit var bridge: PacketBridge
    private var retryCount = 0
    private val maxRetries = 3
    
    private fun startVpnWithRetry() {
        try {
            val vpnInterface = establishVpn()
            if (vpnInterface == null) {
                throw VpnException("Failed to establish VPN interface")
            }
            
            if (!bridge.init(vpnInterface.fileDescriptor.fd)) {
                throw VpnException("Failed to initialize packet bridge")
            }
            
            if (!bridge.start()) {
                throw VpnException("Failed to start packet bridge")
            }
            
            retryCount = 0
            Log.i(TAG, "VPN started successfully")
            
        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed", e)
            
            if (retryCount < maxRetries) {
                retryCount++
                Log.i(TAG, "Retrying... ($retryCount/$maxRetries)")
                
                Handler(Looper.getMainLooper()).postDelayed({
                    startVpnWithRetry()
                }, 2000)
            } else {
                Log.e(TAG, "Max retries reached, giving up")
                showErrorNotification("VPN Failed", "Max retries exceeded")
                stopSelf()
            }
        }
    }
    
    class VpnException(message: String) : Exception(message)
}
```

---

## Example 8: Performance Monitoring

```kotlin
class PerformanceMonitor(private val bridge: PacketBridge) {
    
    private val samples = mutableListOf<StatsSample>()
    
    fun startMonitoring() {
        Timer().scheduleAtFixedRate(object : TimerTask() {
            override fun run() {
                val stats = bridge.getStats() ?: return
                samples.add(StatsSample(System.currentTimeMillis(), stats))
                
                if (samples.size > 60) {
                    samples.removeAt(0) // Keep last 60 samples (1 minute)
                }
                
                analyzePerformance()
            }
        }, 0, 1000)
    }
    
    private fun analyzePerformance() {
        if (samples.size < 2) return
        
        val latest = samples.last()
        val previous = samples[samples.size - 2]
        
        val pps = latest.stats.packetsCaptured - previous.stats.packetsCaptured
        val bps = (latest.stats.bytesProcessed - previous.stats.bytesProcessed) * 8
        
        Log.d(TAG, "Performance: $pps packets/s, ${bps / 1000} Kbps")
        
        // Alert if drop rate is high
        if (latest.stats.successRate < 90) {
            Log.w(TAG, "WARNING: High packet drop rate: ${100 - latest.stats.successRate}%")
        }
    }
    
    data class StatsSample(
        val timestamp: Long,
        val stats: BridgeStats
    )
}
```

---

For more details, see:
- [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) - Setup and integration instructions
- [API_REFERENCE.md](API_REFERENCE.md) - Complete API documentation

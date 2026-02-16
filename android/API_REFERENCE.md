# API Reference - Shakti Packet Bridge

Complete API documentation for the C++ JNI packet bridge.

## Kotlin API

### PacketBridge

Main class for interacting with the native packet bridge.

#### Methods

##### `init(vpnFd: Int): Boolean`

Initialize the packet bridge with a VPN file descriptor.

**Parameters:**
- `vpnFd`: File descriptor from `VpnService.Builder().establish()`

**Returns:** `true` if successful, `false` otherwise

**Example:**
```kotlin
val bridge = PacketBridge()
val success = bridge.init(vpnInterface.fileDescriptor.fd)
```

---

##### `start(): Boolean`

Start automatic packet processing with worker threads.

**Returns:** `true` if started successfully

**Behavior:**
- Launches 3 worker threads:
  - Capture thread: Reads packets from VPN FD
  - Forward thread: Sends packets to internet
  - Python thread: Analyzes packets with AI engine

**Example:**
```kotlin
if (bridge.start()) {
    Log.i(TAG, "Bridge started")
}
```

---

##### `stop()`

Stop packet processing threads.

**Note:** Bridge remains initialized. Call `start()` again to resume.

**Example:**
```kotlin
bridge.stop()
```

---

##### `processPacket(packetData: ByteArray): Boolean`

Process a single packet synchronously.

**Parameters:**
- `packetData`: Raw IP packet bytes

**Returns:** `true` if packet was processed

**Use Case:** When you want manual control instead of automatic processing

**Example:**
```kotlin
val packet = ByteArray(1500)
val length = inputStream.read(packet)
bridge.processPacket(packet.copyOf(length))
```

---

##### `getStats(): BridgeStats?`

Get current bridge statistics.

**Returns:** Statistics object or `null` if not initialized

**Example:**
```kotlin
val stats = bridge.getStats()
println("Captured: ${stats?.packetsCaptured}")
println("Success rate: ${stats?.successRate}%")
```

---

##### `shutdown()`

Shutdown bridge and release all resources.

**Important:** Always call this in `onDestroy()` to prevent resource leaks.

**Example:**
```kotlin
override fun onDestroy() {
    bridge.shutdown()
    super.onDestroy()
}
```

---

##### `setPythonCallback(callback: PythonCallback)`

Register callback for Python AI engine responses.

**Parameters:**
- `callback`: Implementation of `PythonCallback` interface

**Example:**

```kotlin
bridge.setPythonCallback(object : PythonCallback {
    override fun onThreatDetected(metadata: PacketMetadata, threatInfo: String) {
        showNotification("Threat detected: $threatInfo")
    }
    
    override fun onPacketAnalyzed(metadata: PacketMetadata, result: String) {
        logAnalysis(metadata, result)
    }
})
```

---

##### `parsePacket(packetData: ByteArray): PacketMetadata?` (Static)

Parse packet metadata without bridge initialization.

**Parameters:**
- `packetData`: Raw IP packet bytes

**Returns:** Parsed metadata or `null` if parsing failed

**Example:**
```kotlin
val metadata = PacketBridge.nativeParsePacket(packet)
if (metadata != null) {
    Log.d(TAG, "${metadata.srcIp} -> ${metadata.dstIp}:${metadata.dstPort}")
}
```

---

### Data Classes

#### PacketMetadata

Parsed packet information.

**Properties:**
```kotlin
data class PacketMetadata(
    val srcIp: String,           // Source IP address (e.g., "192.168.1.1")
    val dstIp: String,           // Destination IP address
    val srcPort: Int,            // Source port (0-65535)
    val dstPort: Int,            // Destination port
    val protocol: Int,           // 6=TCP, 17=UDP, 1=ICMP
    val direction: Int,          // 0=INBOUND, 1=OUTBOUND
    val payloadSize: Long,       // Payload size in bytes
    val timestampMs: Long        // Unix timestamp in milliseconds
)
```

**Helper Methods:**
- `isTCP(): Boolean` - Returns `true` if protocol is TCP
- `isUDP(): Boolean` - Returns `true` if protocol is UDP
- `isOutbound(): Boolean` - Returns `true` if packet is outbound
- `isInbound(): Boolean` - Returns `true` if packet is inbound

---

#### BridgeStats

Bridge performance statistics.

**Properties:**
```kotlin
data class BridgeStats(
    val packetsCaptured: Long,   // Total packets captured
    val packetsForwarded: Long,  // Packets forwarded to internet
    val packetsDropped: Long,    // Packets that failed to forward
    val bytesProcessed: Long     // Total bytes processed
)
```

**Computed Property:**
- `successRate: Float` - Forwarding success rate (0-100%)

---

### Interfaces

#### PythonCallback

Interface for receiving AI engine analysis results.

```kotlin
interface PythonCallback {
    fun onThreatDetected(metadata: PacketMetadata, threatInfo: String)
    fun onPacketAnalyzed(metadata: PacketMetadata, analysisResult: String)
}
```

**Methods:**
- `onThreatDetected`: Called when AI engine detects a threat
- `onPacketAnalyzed`: Called after every packet analysis

---

## C++ API (Native Layer)

### PacketBridge Class

#### `bool init(int vpn_fd)`

Initialize bridge with VPN file descriptor.

**Thread-safe:** Yes

---

#### `bool start()`

Start worker threads for packet processing.

**Threads Created:**
- Capture worker: Reads from VPN FD → capture queue
- Forward worker: capture queue → Internet
- Python worker: capture queue → Python AI

---

#### `void stop()`

Stop all worker threads gracefully.

**Blocks:** Until all threads complete

---

#### `bool process_packet(const uint8_t* data, size_t size)`

Process single packet synchronously.

**Thread-safe:** Yes (uses mutex)

**Returns:** `true` if forwarded successfully

---

#### `Stats get_stats() const`

Get current statistics.

**Thread-safe:** Yes

---

### PacketCaptureEngine Class

#### `bool init(int vpn_fd)`

Initialize with VPN file descriptor.

---

#### `bool capture_packet(Packet& packet)`

Capture one packet from VPN interface.

**Blocking:** No (returns immediately if no data)

---

#### `static bool parse_packet(const uint8_t* data, size_t size, PacketMetadata& metadata)`

Parse raw packet into metadata structure.

**Supported:** IPv4, TCP, UDP, ICMP

---

### PacketForwarder Class

#### `bool forward_tcp(const Packet& packet)`

Forward TCP packet to destination.

**Features:**
- Automatic connection pooling
- NAT translation
- 30-second socket timeout

---

#### `bool forward_udp(const Packet& packet)`

Forward UDP packet to destination.

**Features:**
- Port mapping for responses
- 5-second receive timeout

---

#### `void cleanup_connections()`

Remove inactive connections (>5 min idle).

**Call Frequency:** Every minute recommended

---

## Error Codes

| Error | Meaning | Solution |
|-------|---------|----------|
| `init() returns false` | Invalid VPN FD or already initialized | Check FD is valid (>0) |
| `start() returns false` | Already running or not initialized | Call `init()` first |
| `process_packet() returns false` | Packet parsing or forwarding failed | Check packet format |
| `parsePacket() returns null` | Invalid packet data | Verify packet is IPv4 |

---

## Thread Safety

| Method | Thread-Safe | Notes |
|--------|-------------|-------|
| `init()` | Yes | Uses mutex |
| `start()` | Yes | |
| `stop()` | Yes | Blocks until threads finish |
| `process_packet()` | Yes | Uses mutex |
| `getStats()` | Yes | Stats protected by mutex |

---

## Performance Characteristics

| Operation | Latency | Throughput |
|-----------|---------|-----------|
| Packet capture | <1ms | 10,000 pps |
| Packet forwarding (TCP) | 5-20ms | 5,000 pps |
| Packet forwarding (UDP) | 2-5ms | 8,000 pps |
| Python AI analysis | 50-100ms | 100 pps |

**Bottleneck:** Python AI analysis (can be async)

**Memory Usage:** ~50 MB (includes packet queues)

---

## Best Practices

1. **Always call `shutdown()`** in `onDestroy()` to prevent leaks
2. **Check return values** from `init()` and `start()`
3. **Use callbacks** for AI results instead of polling
4. **Monitor stats** to detect forwarding failures
5. **Handle Python errors gracefully** if AI engine fails
6. **Limit logging** in production for performance

---

## Example: Full Integration

```kotlin
class MyVpnService : VpnService() {
    private lateinit var bridge: PacketBridge
    
    override fun onCreate() {
        super.onCreate()
        bridge = PacketBridge()
        bridge.setPythonCallback(MyCallback())
    }
    
    private fun startVpn() {
        val vpnInterface = Builder()
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .establish() ?: return
        
        // Initialize bridge
        if (!bridge.init(vpnInterface.fileDescriptor.fd)) {
            Log.e(TAG, "Failed to init bridge")
            return
        }
        
        // Start processing
        if (!bridge.start()) {
            Log.e(TAG, "Failed to start bridge")
            return
        }
        
        // Monitor stats
        Handler(Looper.getMainLooper()).postDelayed({
            val stats = bridge.getStats()
            Log.i(TAG, "Stats: $stats")
        }, 5000)
    }
    
    override fun onDestroy() {
        bridge.stop()
        bridge.shutdown()
        super.onDestroy()
    }
    
    inner class MyCallback : PythonCallback {
        override fun onThreatDetected(metadata: PacketMetadata, info: String) {
            showThreatNotification(metadata, info)
        }
        
        override fun onPacketAnalyzed(metadata: PacketMetadata, result: String) {
            // Log or store for analytics
        }
    }
}
```

---

For integration guide, see [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)

For code examples, see [EXAMPLES.md](EXAMPLES.md)

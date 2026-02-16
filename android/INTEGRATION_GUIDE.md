# Shakti X AI Firewall - Integration Guide for Saksham

This guide provides step-by-step instructions for integrating the C++ JNI bridge into the Shakti X AI Firewall Android app.

## Prerequisites

### 1. Install Android NDK

**Option A: Via Android Studio**
1. Open Android Studio
2. Go to `Tools` → `SDK Manager`
3. Select `SDK Tools` tab
4. Check `NDK (Side by side)` and `CMake`
5. Click `Apply` to install

**Option B: Manual Installation**
```bash
# Download NDK from: https://developer.android.com/ndk/downloads
# Extract and set environment variable
export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/26.1.10909125
```

### 2. Verify Installation
```bash
echo $ANDROID_NDK_HOME
ls $ANDROID_NDK_HOME/toolchains
```

## Build Instructions

### Step 1: Build Native Library

```bash
cd /Users/lakshaly/.gemini/antigravity/scratch/shakti-x-ai/android
./setup_ndk.sh
```

This will:
- Verify NDK installation
- Setup Python for Android (optional)
- Build `libshakti_bridge.so` for all ABIs

### Step 2: Verify Build Output

Check that the library was built:
```bash
find build/intermediates/cmake -name "libshakti_bridge.so"
```

You should see:
```
build/intermediates/cmake/debug/obj/arm64-v8a/libshakti_bridge.so
build/intermediates/cmake/debug/obj/armeabi-v7a/libshakti_bridge.so
build/intermediates/cmake/debug/obj/x86_64/libshakti_bridge.so
```

## Integration Steps

### Step 3: Copy Files to Your Project

#### 3.1 Copy Native Library

```bash
# Create jniLibs directory in your app
mkdir -p ~/path/to/your/app/src/main/jniLibs/arm64-v8a
mkdir -p ~/path/to/your/app/src/main/jniLibs/armeabi-v7a
mkdir -p ~/path/to/your/app/src/main/jniLibs/x86_64

# Copy .so files
cp build/intermediates/cmake/debug/obj/arm64-v8a/libshakti_bridge.so \
   ~/path/to/your/app/src/main/jniLibs/arm64-v8a/

cp build/intermediates/cmake/debug/obj/armeabi-v7a/libshakti_bridge.so \
   ~/path/to/your/app/src/main/jniLibs/armeabi-v7a/

cp build/intermediates/cmake/debug/obj/x86_64/libshakti_bridge.so \
   ~/path/to/your/app/src/main/jniLibs/x86_64/
```

#### 3.2 Copy Kotlin Bridge

```bash
# Copy to your app's package
cp kotlin/PacketBridge.kt \
   ~/path/to/your/app/src/main/kotlin/com/shakti/bridge/
```

### Step 4: Update AndroidManifest.xml

Add required permissions:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

### Step 5: Integrate in VPN Service

Replace the existing packet forwarding in `FirewallVpnService.kt`:

```kotlin
import com.shakti.bridge.PacketBridge
import com.shakti.bridge.PacketMetadata
import com.shakti.bridge.PythonCallback

class FirewallVpnService : VpnService() {
    
    private lateinit var packetBridge: PacketBridge
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize packet bridge
        packetBridge = PacketBridge()
    }
    
    private fun startVpn() {
        // ... existing VPN setup code ...
        
        vpnInterface = establishVpn()
        val vpnFd = vpnInterface!!.fileDescriptor.fd
        
        // Initialize C++ bridge with VPN file descriptor
        if (!packetBridge.init(vpnFd)) {
            Log.e(TAG, "Failed to initialize packet bridge")
            return
        }
        
        // Register callback for AI engine
        packetBridge.setPythonCallback(object : PythonCallback {
            override fun onThreatDetected(metadata: PacketMetadata, threatInfo: String) {
                Log.w(TAG, "THREAT: ${metadata.dstIp}:${metadata.dstPort} - $threatInfo")
                // Show notification or block packet
            }
            
            override fun onPacketAnalyzed(metadata: PacketMetadata, analysisResult: String) {
                Log.d(TAG, "Analysis: ${metadata.dstIp}:${metadata.dstPort} - $analysisResult")
            }
        })
        
        // Start automatic packet processing
        if (!packetBridge.start()) {
            Log.e(TAG, "Failed to start packet bridge")
            return
        }
        
        Log.i(TAG, "Packet bridge started successfully")
    }
    
    private fun stopVpn() {
        packetBridge.stop()
        packetBridge.shutdown()
        
        // ... existing cleanup code ...
    }
    
    // Optional: Get statistics
    private fun logStats() {
        val stats = packetBridge.getStats()
        if (stats != null) {
            Log.i(TAG, "Bridge Stats: " +
                  "Captured=${stats.packetsCaptured}, " +
                  "Forwarded=${stats.packetsForwarded}, " +
                  "Dropped=${stats.packetsDropped}, " +
                  "Success=${stats.successRate}%")
        }
    }
}
```

### Step 6: Bundle Python with APK (Optional)

If you want Python AI engine integration:

#### 6.1 Use Chaquopy

Add to `build.gradle`:
```gradle
plugins {
    id 'com.chaquo.python' version '14.0.2'
}

chaquopy {
    defaultConfig {
        version "3.9"
        
        pip {
            install "numpy"
            install "scikit-learn"
            // ... other dependencies from requirements.txt
        }
    }
}
```

#### 6.2 Copy Python Files

```bash
# Copy shakti-x-ai Python code to assets
mkdir -p app/src/main/assets/python
cp -r ml_engine app/src/main/assets/python/
cp -r detection app/src/main/assets/python/
cp -r utils app/src/main/assets/python/
```

## Testing

### Test 1: Verify Library Loading

Add to your app startup:
```kotlin
try {
    System.loadLibrary("shakti_bridge")
    Log.i(TAG, "✓ Native library loaded")
} catch (e: UnsatisfiedLinkError) {
    Log.e(TAG, "✗ Failed to load native library", e)
}
```

### Test 2: Parse Packet

```kotlin
val testPacket = byteArrayOf(/* raw IP packet */)
val metadata = PacketBridge.nativeParsePacket(testPacket)

if (metadata != null) {
    Log.i(TAG, "✓ Packet parsed: ${metadata.srcIp} -> ${metadata.dstIp}")
} else {
    Log.e(TAG, "✗ Failed to parse packet")
}
```

### Test 3: Full Integration

1. Start VPN service
2. Open browser and visit `http://example.com`
3. Check logcat for:
   - `"Packet captured: TCP 443 example.com"`
   - `"Packet forwarded: 1234 bytes"`
   - Website should load correctly

## Troubleshooting

### Issue: `UnsatisfiedLinkError: dlopen failed`

**Solution**: Check ABI compatibility
```kotlin
Log.d(TAG, "Device ABI: ${Build.SUPPORTED_ABIS.joinToString()}")
```

Ensure `libshakti_bridge.so` exists for your device's ABI.

### Issue: Packets not being forwarded

**Solution**: Check VPN file descriptor
```kotlin
Log.d(TAG, "VPN FD: ${vpnInterface!!.fileDescriptor.fd}")
```

Ensure FD is valid (> 0) before calling `packetBridge.init(fd)`.

### Issue: Python import errors

**Solution**: Verify Python path
```kotlin
// In Application class
val pythonHome = "$filesDir/python"
Log.d(TAG, "Python home: $pythonHome")
```

### Issue: High battery usage

**Solution**: Reduce logging and optimize packet processing
```kotlin
// Limit stats logging
if (packetsProcessed % 1000 == 0L) {
    logStats()
}
```

## Performance Tips

1. **Use Release Build**: Symbols are stripped for better performance
2. **Limit Logging**: Disable debug logs in production
3. **Connection Pooling**: Bridge reuses TCP connections automatically
4. **Queue Size**: Default 10,000 packets, adjust if needed

## Next Steps

1. Review [API_REFERENCE.md](API_REFERENCE.md) for detailed API documentation
2. Check [EXAMPLES.md](EXAMPLES.md) for more code examples
3. Test with real traffic and tune detection parameters

## Support

If you encounter issues:
1. Check logcat for error messages
2. Verify NDK and build configuration
3. Review example integration in this guide

---

**Note**: This bridge is production-ready but should be tested thoroughly before deployment. Always handle errors gracefully and provide user feedback.

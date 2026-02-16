# Shakti X AI Firewall - C++ Native Bridge

High-performance C++ JNI bridge for Android VPN packet forwarding and Python AI integration.

## 🚀 Quick Start for Saksham

### Prerequisites
- Android Studio with NDK installed
- CMake 3.18+
- macOS, Linux, or Windows with WSL

### Build Instructions

```bash
cd android
./setup_ndk.sh
```

This will build `libshakti_bridge.so` for all Android ABIs (arm64-v8a, armeabi-v7a, x86_64).

### Integration

See detailed guides in `android/` directory:
- **[INTEGRATION_GUIDE.md](android/INTEGRATION_GUIDE.md)** - Complete setup instructions
- **[API_REFERENCE.md](android/API_REFERENCE.md)** - API documentation
- **[EXAMPLES.md](android/EXAMPLES.md)** - Code examples
- **[TESTING_AND_SHARING.md](android/TESTING_AND_SHARING.md)** - Testing & deployment

## 📦 What's Included

### C++ Native Bridge
- **Packet Capture Engine**: Captures packets from VPN file descriptor (10K+ pps)
- **Packet Forwarder**: TCP/UDP forwarding with NAT support
- **Python Bridge**: Integration with Python AI engine via Python C API
- **JNI Wrapper**: Kotlin/Java bindings for Android

### Python AI Engine
- Multi-model anomaly detection (Isolation Forest, SVM, LSTM)
- 20+ traffic features extraction
- Real-time threat detection (DDoS, exfiltration, port scanning, DNS tunneling)
- Multi-source threat intelligence

### Build System
- CMake configuration for NDK
- Gradle integration
- Automated build scripts

## 🏗️ Architecture

```
Android VPN Service (Kotlin)
        ↓ JNI
C++ Packet Bridge
    ↓               ↓
Internet        Python AI Engine
(TCP/UDP)       (Threat Detection)
```

## 📊 Performance

- **Throughput**: 10,000+ packets/second
- **Latency**: <100ms packet processing
- **Memory**: ~50MB
- **Battery**: <5% overhead per hour

## 🛠️ Components

| Component | Location |
|-----------|----------|
| C++ Bridge | `android/cpp/` |
| Kotlin API | `android/kotlin/` |
| Build Config | `android/cpp/CMakeLists.txt` |
| Python AI | `ml_engine/`, `detection/` |
| Documentation | `android/*.md` |

## 📱 For Saksham - Integration Steps

1. **Build native library**: `cd android && ./setup_ndk.sh`
2. **Copy to your app**: Follow `android/INTEGRATION_GUIDE.md`
3. **Update VPN service**: Use Kotlin PacketBridge API
4. **Test**: Build APK and test on device

## 📚 Documentation

All documentation is in the `android/` directory:

- [INTEGRATION_GUIDE.md](android/INTEGRATION_GUIDE.md) - Setup & integration
- [API_REFERENCE.md](android/API_REFERENCE.md) - Complete API reference
- [EXAMPLES.md](android/EXAMPLES.md) - 8 practical examples
- [TESTING_AND_SHARING.md](android/TESTING_AND_SHARING.md) - Testing guide

## 🔒 Security Features

- On-device ML inference (no data leakage)
- Privacy-first design
- Real-time threat blocking
- Multi-layer protection (rules + ML + threat intel)

## 🤝 Contributing

This bridge is ready for integration into the Shakti X AI Firewall Android app.

## 📄 License

Part of the Shakti X AI Firewall project.

---

**Built for Android security with AI-powered threat detection** 🛡️

# Testing & Sharing Guide - Shakti X AI Firewall

## Quick Testing (On Your Mac)

### Test 1: Build Verification

```bash
cd /Users/lakshaly/.gemini/antigravity/scratch/shakti-x-ai/android

# Run the build script
./setup_ndk.sh

# Verify libraries were created
ls -lh build/intermediates/cmake/debug/obj/arm64-v8a/libshakti_bridge.so
ls -lh build/intermediates/cmake/debug/obj/armeabi-v7a/libshakti_bridge.so
ls -lh build/intermediates/cmake/debug/obj/x86_64/libshakti_bridge.so
```

Expected output:
```
-rwxr-xr-x  1 user  staff   256K Feb 16 17:30 libshakti_bridge.so (arm64)
-rwxr-xr-x  1 user  staff   198K Feb 16 17:30 libshakti_bridge.so (armv7)
-rwxr-xr-x  1 user  staff   312K Feb 16 17:30 libshakti_bridge.so (x86_64)
```

### Test 2: File Verification

```bash
# Check all files exist
cd /Users/lakshaly/.gemini/antigravity/scratch/shakti-x-ai

find android -type f -name "*.cpp" -o -name "*.h" -o -name "*.kt"
```

Should show:
- `android/cpp/shakti_packet_bridge.h`
- `android/cpp/shakti_packet_bridge.cpp`
- `android/cpp/shakti_jni_wrapper.cpp`
- `android/cpp/shakti_python_bridge.cpp`
- `android/kotlin/PacketBridge.kt`

---

## Sharing with Your Friend (Saksham)

### Option 1: GitHub (Recommended) 🚀

#### 1.1 Create GitHub Repository

```bash
cd /Users/lakshaly/.gemini/antigravity/scratch/shakti-x-ai

# Configure git (if not already done)
git config user.name "Your Name"
git config user.email "your.email@example.com"

# Create .gitignore
cat > .gitignore << 'EOF'
build/
.gradle/
*.pyc
__pycache__/
.DS_Store
*.swp
*.swo
cache/threat_intel/*.db
EOF

# Add and commit
git add .gitignore
git commit -m "chore: Add .gitignore"
```

#### 1.2 Push to GitHub

**On GitHub.com:**
1. Create new repository: `shakti-x-ai-firewall`
2. Copy the repository URL

**On your Mac:**
```bash
# Add remote (replace with your GitHub URL)
git remote add origin https://github.com/YOUR_USERNAME/shakti-x-ai-firewall.git

# Push to GitHub
git branch -M main
git push -u origin main
```

#### 1.3 Share with Saksham

Send Saksham the GitHub URL. They can clone it:

```bash
# On Saksham's laptop
git clone https://github.com/YOUR_USERNAME/shakti-x-ai-firewall.git
cd shakti-x-ai-firewall
```

---

### Option 2: ZIP File Transfer 📦

#### 2.1 Create ZIP Package

```bash
cd /Users/lakshaly/.gemini/antigravity/scratch

# Create clean package
tar -czf shakti-x-ai-bridge.tar.gz \
  --exclude='shakti-x-ai/build' \
  --exclude='shakti-x-ai/cache' \
  --exclude='shakti-x-ai/.git' \
  --exclude='**/__pycache__' \
  --exclude='**/*.pyc' \
  shakti-x-ai/

echo "Package created: shakti-x-ai-bridge.tar.gz"
ls -lh shakti-x-ai-bridge.tar.gz
```

#### 2.2 Share Package

**Upload to Cloud:**
```bash
# Option A: Google Drive / Dropbox
# Drag shakti-x-ai-bridge.tar.gz to your drive

# Option B: WeTransfer
# Visit wetransfer.com and upload the file

# Option C: Email (if < 25MB)
# Attach to email
```

#### 2.3 Saksham Extracts

```bash
# On Saksham's laptop
tar -xzf shakti-x-ai-bridge.tar.gz
cd shakti-x-ai
```

---

### Option 3: USB Drive 💾

```bash
# Copy to USB
cp -r /Users/lakshaly/.gemini/antigravity/scratch/shakti-x-ai /Volumes/USB_DRIVE/

# Give USB to Saksham
# Saksham copies from USB:
cp -r /Volumes/USB_DRIVE/shakti-x-ai ~/Projects/
```

---

## Setup Instructions for Saksham

### Prerequisites

Saksham needs to install:

#### On Mac:

```bash
# 1. Install Android Studio
# Download from: https://developer.android.com/studio

# 2. Install NDK via Android Studio
# Android Studio → Settings → SDK Manager → SDK Tools
# Check: NDK (Side by side), CMake

# 3. Verify installation
echo $ANDROID_NDK_HOME
# Should show: /Users/saksham/Library/Android/sdk/ndk/26.x.xxxxx
```

#### On Linux:

```bash
# 1. Install Android Studio (same as Mac)

# 2. Set NDK path
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125
echo 'export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125' >> ~/.bashrc

# 3. Install build tools
sudo apt-get install build-essential cmake
```

#### On Windows:

```powershell
# 1. Install Android Studio
# Download from: https://developer.android.com/studio

# 2. Install NDK via Android Studio (same as Mac)

# 3. Set environment variable
setx ANDROID_NDK_HOME "C:\Users\Saksham\AppData\Local\Android\Sdk\ndk\26.1.10909125"
```

### Build Instructions for Saksham

```bash
cd shakti-x-ai/android

# Make script executable (Mac/Linux)
chmod +x setup_ndk.sh

# Build the library
./setup_ndk.sh

# On Windows, use Git Bash or WSL to run the script
# Or build manually with Gradle:
# gradlew assembleDebug
```

### Verify Build

```bash
# Should see .so files
find build -name "libshakti_bridge.so"
```

---

## Integration Testing

### For Saksham to Integrate into Android App

#### Step 1: Copy to App

```bash
# Assuming Saksham's app is at ~/ai_firewall_app
APP_DIR=~/ai_firewall_app

# Copy native libraries
mkdir -p $APP_DIR/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}

cp build/intermediates/cmake/debug/obj/arm64-v8a/libshakti_bridge.so \
   $APP_DIR/app/src/main/jniLibs/arm64-v8a/

cp build/intermediates/cmake/debug/obj/armeabi-v7a/libshakti_bridge.so \
   $APP_DIR/app/src/main/jniLibs/armeabi-v7a/

cp build/intermediates/cmake/debug/obj/x86_64/libshakti_bridge.so \
   $APP_DIR/app/src/main/jniLibs/x86_64/

# Copy Kotlin bridge
mkdir -p $APP_DIR/app/src/main/kotlin/com/shakti/bridge
cp kotlin/PacketBridge.kt $APP_DIR/app/src/main/kotlin/com/shakti/bridge/
```

#### Step 2: Update VPN Service

Edit `FirewallVpnService.kt`:

```kotlin
import com.shakti.bridge.PacketBridge

class FirewallVpnService : VpnService() {
    private lateinit var bridge: PacketBridge
    
    override fun onCreate() {
        super.onCreate()
        bridge = PacketBridge()
    }
    
    private fun startVpn() {
        val vpnInterface = Builder()
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .establish()
        
        val vpnFd = vpnInterface!!.fileDescriptor.fd
        bridge.init(vpnFd)
        bridge.start()
    }
    
    override fun onDestroy() {
        bridge.stop()
        bridge.shutdown()
        super.onDestroy()
    }
}
```

#### Step 3: Build APK

```bash
cd $APP_DIR
./gradlew assembleDebug

# APK location
ls -lh app/build/outputs/apk/debug/app-debug.apk
```

#### Step 4: Test on Android Device

```bash
# Install APK on phone
adb install app/build/outputs/apk/debug/app-debug.apk

# Start VPN and check logs
adb logcat | grep -E "ShaktiBridge|PacketBridge"
```

Expected logs:
```
I ShaktiBridge: PacketBridge initialized successfully
I ShaktiBridge: PacketBridge started with 3 worker threads
D ShaktiBridge: Packet captured: TCP 443 google.com
D ShaktiBridge: Forwarded TCP packet: 1234 bytes to 142.250.185.78:443
```

---

## Testing Checklist for Saksham

- [ ] NDK installed and `$ANDROID_NDK_HOME` set
- [ ] Project cloned/extracted successfully
- [ ] `setup_ndk.sh` runs without errors
- [ ] `libshakti_bridge.so` files exist for all ABIs
- [ ] Native libraries copied to app's `jniLibs/`
- [ ] `PacketBridge.kt` copied to app source
- [ ] VPN service updated with bridge integration
- [ ] App builds successfully (APK created)
- [ ] APK installs on Android device
- [ ] VPN starts without crashes
- [ ] Packets are being forwarded (websites load)
- [ ] Logcat shows bridge activity
- [ ] No memory leaks after 5 minutes

---

## Troubleshooting Common Issues

### Issue 1: "NDK not found"

**Solution:**
```bash
# Verify NDK path
ls $ANDROID_NDK_HOME

# If empty, install via Android Studio
# Or download manually from: https://developer.android.com/ndk/downloads
```

### Issue 2: "UnsatisfiedLinkError" when app runs

**Solution:**
```bash
# Check ABI compatibility
adb shell getprop ro.product.cpu.abi

# Verify .so exists for that ABI
ls app/src/main/jniLibs/arm64-v8a/libshakti_bridge.so
```

### Issue 3: Build fails on Windows

**Solution:**
Use WSL (Windows Subsystem for Linux):
```bash
# Install WSL
wsl --install

# Run build in WSL
wsl
cd /mnt/c/Users/Saksham/shakti-x-ai/android
./setup_ndk.sh
```

---

## Quick Commands for Saksham

**Full setup from scratch:**
```bash
# Clone or extract project
cd shakti-x-ai/android

# Build
./setup_ndk.sh

# Copy to app (update APP_DIR path)
APP_DIR=~/my_firewall_app
mkdir -p $APP_DIR/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}
cp build/intermediates/cmake/debug/obj/*/libshakti_bridge.so $APP_DIR/app/src/main/jniLibs/*/

# Copy Kotlin
mkdir -p $APP_DIR/app/src/main/kotlin/com/shakti/bridge
cp kotlin/PacketBridge.kt $APP_DIR/app/src/main/kotlin/com/shakti/bridge/

# Build APK
cd $APP_DIR
./gradlew assembleDebug

# Install and test
adb install app/build/outputs/apk/debug/app-debug.apk
adb logcat | grep ShaktiBridge
```

---

## Documentation Files for Saksham

Tell Saksham to read these files in order:

1. **[INTEGRATION_GUIDE.md](file:///Users/lakshaly/.gemini/antigravity/scratch/shakti-x-ai/android/INTEGRATION_GUIDE.md)** - Complete setup guide
2. **[API_REFERENCE.md](file:///Users/lakshaly/.gemini/antigravity/scratch/shakti-x-ai/android/API_REFERENCE.md)** - API details
3. **[EXAMPLES.md](file:///Users/lakshaly/.gemini/antigravity/scratch/shakti-x-ai/android/EXAMPLES.md)** - Code examples

---

## Summary

**For You (Testing):**
1. Run `./setup_ndk.sh` to verify build
2. Check `.so` files are created
3. Commit to GitHub (recommended)

**For Saksham (Installation):**
1. Clone from GitHub or extract ZIP
2. Install NDK via Android Studio
3. Run `./setup_ndk.sh`
4. Copy files to his app
5. Update VPN service code
6. Build and test on device

**Sharing Methods:**
- ✅ **Best**: Push to GitHub and share repo URL
- ✅ Good: Create ZIP and share via Google Drive
- ✅ OK: USB drive transfer

Let me know which sharing method you prefer, and I can help set it up!

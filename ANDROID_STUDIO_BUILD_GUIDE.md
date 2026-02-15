# 🚀 Android Studio Build Guide - ShaktiX APK

## Step 1: Download Android Studio

**Download from**: https://developer.android.com/studio

- Click **"Download Android Studio"**
- Choose **Mac with Apple chip** or **Mac with Intel chip** (depending on your Mac)
- Download size: ~1.1 GB
- Install time: ~5-10 minutes

---

## Step 2: Install Android Studio

1. **Open the downloaded DMG file**
2. **Drag Android Studio** to Applications folder
3. **Open Android Studio** from Applications
4. **First launch setup**:
   - Click "Next" through the setup wizard
   - Choose "Standard" installation
   - Accept licenses
   - Wait for SDK download (~2-3 GB, 5-10 min)

---

## Step 3: Open the Project

1. **Launch Android Studio**
2. Click **"Open"** (or File → Open)
3. Navigate to and select:
   ```
   /Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_firewall_app/android
   ```
4. Click **"Open"**

---

## Step 4: Wait for Gradle Sync

**This happens automatically!**

You'll see at the bottom:
```
Gradle sync in progress...
```

**Wait 2-5 minutes** for:
- ✅ Downloading dependencies
- ✅ Configuring project
- ✅ Indexing files

**When done**, you'll see: `Gradle sync finished`

---

## Step 5: Build the APK

### Method A: Using Menu (Easiest)

1. **Build** → **Build Bundle(s) / APK(s)** → **Build APK(s)**
2. Wait 2-5 minutes
3. When done, you'll see a notification: **"APK(s) generated successfully"**
4. Click **"locate"** in the notification

### Method B: Using Build Variants

1. **Build** → **Select Build Variant**
2. Change to **"release"**
3. **Build** → **Build APK(s)**

---

## Step 6: Find Your APK

**Location**:
```
/Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_firewall_app/android/app/build/outputs/apk/release/ShaktiX-release.apk
```

**Or** click the **"locate"** link in the success notification.

---

## Step 7: Upload to GitHub Release

1. Go to: https://github.com/panchallakshay/ai_firewall/releases/new
2. **Tag**: `v1.0.0`
3. **Title**: `ShaktiX v1.0.0 - AI Firewall`
4. **Upload**: Drag `ShaktiX-release.apk` to the upload area
5. Click **"Publish release"**

**Done!** Users can now download from:
https://github.com/panchallakshay/ai_firewall/releases

---

## 🔧 Troubleshooting

### If Gradle Sync Fails:

1. **File** → **Invalidate Caches** → **Invalidate and Restart**
2. Wait for restart
3. Try opening project again

### If Build Fails with Kotlin Errors:

1. **File** → **Project Structure**
2. **Project** → Change **Gradle version** to `8.3`
3. Click **OK**
4. **File** → **Sync Project with Gradle Files**
5. Try building again

### If "SDK not found":

1. **Tools** → **SDK Manager**
2. Install **Android SDK Platform 34** (or latest)
3. Install **Android SDK Build-Tools**
4. Click **OK**
5. Try building again

---

## ⏱️ Timeline

| Step | Time |
|------|------|
| Download Android Studio | 5-10 min |
| Install + First Setup | 10-15 min |
| Open Project | 1 min |
| Gradle Sync | 2-5 min |
| Build APK | 2-5 min |
| **Total** | **20-36 min** |

---

## 📱 What You'll Get

**File**: `ShaktiX-release.apk`  
**Size**: ~15-25 MB  
**Name on phone**: "ShaktiX"  
**Everything included**:
- ✅ Saksham's UI
- ✅ AI firewall backend
- ✅ VPN service
- ✅ AI models
- ✅ All features working

---

## 🎉 After Building

**Test it**:
1. Copy APK to your Android phone
2. Enable "Unknown Sources"
3. Install APK
4. Open ShaktiX
5. Grant VPN permission
6. Test the firewall!

**Share it**:
- Upload to GitHub Releases
- Share download link
- Users install directly

---

## 💡 Pro Tips

1. **Keep Android Studio open** - useful for future updates
2. **Save the APK location** - you'll need it for releases
3. **Test on real device** - emulator might not support VPN
4. **Check logcat** - if app crashes, use Android Studio's Logcat to debug

---

## 🆘 Need Help?

If you encounter any errors:
1. Take a screenshot
2. Copy the error message
3. Share with me - I'll help you fix it!

**Let's build ShaktiX! 🚀**

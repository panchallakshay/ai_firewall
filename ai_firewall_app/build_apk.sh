#!/bin/bash

echo "🔄 Downgrading Flutter to 3.24.5..."
cd ~/development/flutter
git checkout 3.24.5
flutter doctor

echo ""
echo "🏗️ Building APK with integrated UI..."
cd /Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_firewall_app
flutter build apk --release

echo ""
echo "✅ Done! APK location:"
echo "📱 /Users/lakshaly/.gemini/antigravity/scratch/ai_firewall/ai_firewall_app/build/app/outputs/flutter-apk/app-release.apk"
echo ""
echo "Install with: adb install build/app/outputs/flutter-apk/app-release.apk"

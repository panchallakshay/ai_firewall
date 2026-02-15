#!/bin/bash

echo "🚀 Setting up ShaktiX AI Firewall for GitHub"
echo "=============================================="
echo ""

cd /Users/lakshaly/.gemini/antigravity/scratch/ai_firewall

# Initialize git if not already
if [ ! -d ".git" ]; then
    echo "📦 Initializing Git repository..."
    git init
    git branch -M main
fi

# Add all files
echo "📝 Adding files to Git..."
git add .

# Commit
echo "💾 Creating commit..."
git commit -m "ShaktiX AI Firewall - Complete Integration with Saksham's UI

Features:
- AI-powered threat detection (DNS 99.98% + Flow 92.93%)
- Beautiful ShaktiX UI with glassmorphic design
- VPN tunnel with TCP/UDP forwarding
- Real-time threat blocking and notifications
- MethodChannel integration (Flutter ↔ Kotlin)
- Automated APK builds via GitHub Actions

App branded as 'ShaktiX' - APK downloads as ShaktiX-release.apk"

# Add remote (update if already exists)
echo "🔗 Setting up GitHub remote..."
git remote remove origin 2>/dev/null
git remote add origin https://github.com/panchallakshay/ai_firewall.git

echo ""
echo "✅ Git setup complete!"
echo ""
echo "📤 Next steps:"
echo "1. Create repository on GitHub: https://github.com/new"
echo "   - Name: ai_firewall"
echo "   - Description: AI-powered VPN firewall for Android"
echo "   - Public or Private (your choice)"
echo ""
echo "2. Push code:"
echo "   git push -u origin main"
echo ""
echo "3. Wait 5-10 minutes for GitHub Actions to build ShaktiX.apk"
echo ""
echo "4. Download APK from:"
echo "   https://github.com/panchallakshay/ai_firewall/actions"
echo ""
echo "5. Create first release:"
echo "   git tag -a v1.0.0 -m 'ShaktiX v1.0.0 - First Release'"
echo "   git push origin v1.0.0"
echo ""
echo "📱 Users will download: ShaktiX-release.apk"
echo "🎨 App name on phone: ShaktiX"
echo ""

# 🔧 Fix Java/Gradle Compatibility in Codespaces

The error is: **Java 21 is incompatible with Gradle 8.3**

## Quick Fix - Run These Commands:

```bash
# Update Gradle wrapper to 8.5 (supports Java 21)
cd /workspaces/ai_firewall/ai_firewall_app/android
./gradlew wrapper --gradle-version=8.5

# Go back and build
cd /workspaces/ai_firewall/ai_firewall_app
flutter build apk --release
```

## Or Update Manually:

Edit the file in Codespaces:
`android/gradle/wrapper/gradle-wrapper.properties`

Change line 5 from:
```
distributionUrl=https\://services.gradle.org/distributions/gradle-8.3-all.zip
```

To:
```
distributionUrl=https\://services.gradle.org/distributions/gradle-8.5-all.zip
```

Then run:
```bash
flutter build apk --release
```

---

**Copy-paste this single command:**

```bash
cd /workspaces/ai_firewall/ai_firewall_app/android && ./gradlew wrapper --gradle-version=8.5 && cd /workspaces/ai_firewall/ai_firewall_app && flutter build apk --release
```

This will:
1. Upgrade Gradle to 8.5 (compatible with Java 21)
2. Build the APK

**Paste it in Codespaces terminal now!** 🚀

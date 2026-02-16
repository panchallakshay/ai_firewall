#!/bin/bash

# Setup script for building Shakti X AI Firewall native bridge
# This script prepares the build environment and compiles the C++ bridge

set -e  # Exit on error

echo "=================================================="
echo "Shakti X AI Firewall - Native Bridge Setup"
echo "=================================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if NDK is installed
check_ndk() {
    echo -e "${YELLOW}Checking for Android NDK...${NC}"
    
    if [ -z "$ANDROID_NDK_HOME" ]; then
        if [ -d "$HOME/Library/Android/sdk/ndk" ]; then
            # Find latest NDK version
            export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/$(ls -1 $HOME/Library/Android/sdk/ndk | sort -V | tail -1)"
            echo -e "${GREEN}✓ Found NDK: $ANDROID_NDK_HOME${NC}"
        else
            echo -e "${RED}✗ Android NDK not found!${NC}"
            echo "Please install NDK via Android Studio SDK Manager"
            echo "Or set ANDROID_NDK_HOME environment variable"
            exit 1
        fi
    else
        echo -e "${GREEN}✓ NDK found: $ANDROID_NDK_HOME${NC}"
    fi
}

# Download Python for Android (if needed)
setup_python() {
    echo -e "${YELLOW}Setting up Python for Android...${NC}"
    
    PYTHON_DIR="$(pwd)/python"
    
    if [ -d "$PYTHON_DIR" ]; then
        echo -e "${GREEN}✓ Python directory already exists${NC}"
        return
    fi
    
    echo "Python for Android not found. You need to:"
    echo "1. Download Python for Android from: https://github.com/kivy/python-for-android"
    echo "2. Or use Chaquopy: https://chaquo.com/chaquopy/"
    echo "3. Extract to: $PYTHON_DIR"
    echo ""
    echo "For now, skipping Python integration (bridge will build without Python support)"
    
    # Create dummy Python directories to allow build to proceed
    mkdir -p "$PYTHON_DIR/include/python3.9"
    mkdir -p "$PYTHON_DIR/lib/arm64-v8a"
    mkdir -p "$PYTHON_DIR/lib/armeabi-v7a"
    mkdir -p "$PYTHON_DIR/lib/x86_64"
}

# Build native library
build_native() {
    echo -e "${YELLOW}Building native library...${NC}"
    
    cd "$(dirname "$0")"
    
    # Clean previous build
    if [ -d "build" ]; then
        echo "Cleaning previous build..."
        rm -rf build
    fi
    
    # Use Gradle to build (recommended)
    if [ -f "gradlew" ]; then
        echo "Building with Gradle..."
        chmod +x gradlew
        ./gradlew assembleDebug
        echo -e "${GREEN}✓ Build complete!${NC}"
        
        # Find and display the library
        echo ""
        echo "Native library location:"
        find build/intermediates/cmake -name "libshakti_bridge.so" -exec ls -lh {} \;
    else
        echo -e "${RED}✗ gradlew not found${NC}"
        echo "Please run this script from the android/ directory"
        exit 1
    fi
}

# Main setup flow
main() {
    check_ndk
    setup_python
    build_native
    
    echo ""
    echo -e "${GREEN}=================================================="
    echo "Setup Complete!"
    echo "==================================================${NC}"
    echo ""
    echo "Next steps for Saksham:"
    echo "1. Copy libshakti_bridge.so to your app's jniLibs/"
    echo "2. Copy PacketBridge.kt to your app's source"
    echo "3. See INTEGRATION_GUIDE.md for detailed instructions"
    echo ""
}

# Run main function
main

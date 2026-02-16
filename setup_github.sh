#!/bin/bash

# Quick GitHub setup script for Shakti X AI Firewall

echo "🚀 Setting up GitHub repository for Shakti X AI Firewall"
echo ""

cd "$(dirname "$0")"

# Configure git user (update these!)
echo "📝 Configuring git..."
git config user.name "Lakshay"
git config user.email "lakshaly@example.com"

# Create .gitignore
echo "📄 Creating .gitignore..."
cat > .gitignore << 'EOF'
# Build files
build/
.gradle/
*.iml
.idea/
local.properties

# Python
*.pyc
__pycache__/
*.egg-info/
.pytest_cache/

# Cache
cache/threat_intel/*.db

# OS files
.DS_Store
*.swp
*.swo
Thumbs.db

# NDK/CMake
.cxx/
.externalNativeBuild/
EOF

git add .gitignore
git commit -m "chore: Add .gitignore" 2>/dev/null || echo "Already committed"

echo ""
echo "✅ Git configured!"
echo ""
echo "Next steps:"
echo "1. Create repository on GitHub: https://github.com/new"
echo "   Name it: shakti-x-ai-firewall"
echo "2. Run these commands (replace USERNAME):"
echo ""
echo "   git remote add origin https://github.com/USERNAME/shakti-x-ai-firewall.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "3. Share the GitHub URL with Saksham!"

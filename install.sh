#!/bin/bash

# SecureFlow CLI Installation Script
# This script sets up the SecureFlow CLI for demonstration purposes

echo "🔒 SecureFlow CLI Installation"
echo "=============================="
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed."
    echo "   Please install Node.js 14+ from https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 14 ]; then
    echo "❌ Node.js version 14+ is required. Current version: $(node --version)"
    exit 1
fi

echo "✅ Node.js $(node --version) detected"

# Check npm
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed."
    exit 1
fi

echo "✅ npm $(npm --version) detected"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Make executable
echo "🔧 Making secureflow executable..."
chmod +x secureflow

# Test installation
echo "🧪 Testing installation..."
./secureflow --version

if [ $? -ne 0 ]; then
    echo "❌ Installation test failed"
    exit 1
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Quick Start:"
echo "   ./secureflow --help"
echo "   ./secureflow challenges"
echo "   ./secureflow --demo-mode"
echo ""
echo "⚠️  Remember: This is intentionally vulnerable software for educational purposes only!"
echo "   Never use in production environments."
echo ""
echo "📚 For full documentation, see README.md"

#!/bin/bash

# Simple publish script for go-validatorx v1.1.1
# Run this script to publish the current code as version v1.1.1

echo "🚀 Publishing go-validatorx v1.1.1"
echo "=================================="

# Make release script executable
chmod +x release.sh

# Run the release script
./release.sh

echo ""
echo "🎉 Release v1.1.1 is ready!"
echo ""
echo "📋 Manual steps to complete the release:"
echo "1. Go to GitHub: https://github.com/seasbee/go-validatorx"
echo "2. Click 'Releases' → 'Create a new release'"
echo "3. Choose tag: v1.1.1"
echo "4. Release title: 'Enhanced Duration Validation'"
echo "5. Copy content from RELEASE_NOTES.md"
echo "6. Publish the release"
echo ""
echo "✅ Your users can now install with:"
echo "   go get github.com/seasbee/go-validatorx@v1.1.1"

#!/bin/bash

# Release script for go-validatorx v1.1.1
# This script helps publish the current code as version v1.1.1

set -e

VERSION="v1.1.1"
PROJECT_NAME="go-validatorx"

echo "🚀 Publishing $PROJECT_NAME $VERSION"

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "📦 Initializing git repository..."
    git init
    git add .
    git commit -m "Initial commit: $PROJECT_NAME $VERSION"
fi

# Check if there are uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "📝 Committing changes..."
    git add .
    git commit -m "feat: Enhanced duration validation with human-readable strings

- Added support for duration strings like '1s', '30s', '5m', '1h'
- Added decimal duration support (1.5s, 0.5s)
- Maintained backward compatibility with nanosecond values
- Improved error messages for duration validation
- Added comprehensive test coverage (40+ test cases)
- Updated examples to use human-readable duration strings

Fixes duration validation confusion with nanosecond values."
fi

# Create and push the tag
echo "🏷️  Creating tag $VERSION..."
git tag -a "$VERSION" -m "Release $VERSION: Enhanced duration validation

Key Features:
- Human-readable duration strings in validation tags
- Support for 1s, 30s, 5m, 1h, 100ms, 24h formats
- Decimal duration support (1.5s, 0.5s)
- Backward compatibility with nanosecond values
- Comprehensive test coverage
- Improved error messages

Breaking Changes: None (fully backward compatible)"

# Push to remote (if configured)
if git remote | grep -q origin; then
    echo "📤 Pushing to remote repository..."
    git push origin main
    git push origin "$VERSION"
else
    echo "⚠️  No remote repository configured. To push to GitHub:"
    echo "   git remote add origin https://github.com/seasbee/go-validatorx.git"
    echo "   git push -u origin main"
    echo "   git push origin $VERSION"
fi

echo "✅ Successfully published $PROJECT_NAME $VERSION!"
echo ""
echo "📋 Next steps:"
echo "1. Create a GitHub release with the tag $VERSION"
echo "2. Update documentation if needed"
echo "3. Announce the release to users"
echo ""
echo "🎉 Release $VERSION is ready!"

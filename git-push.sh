#!/bin/bash

# Git commit and push script for tlsx API

echo "=========================================="
echo "Committing and pushing tlsx API changes"
echo "=========================================="
echo ""

# Check git status
echo "Checking git status..."
git status
echo ""

# Add all changes
echo "Adding all changes..."
git add .
echo "✓ Files staged"
echo ""

# Commit with message
echo "Committing changes..."
git commit -m "Fix tlsx API to use library directly instead of CLI binary

- Removed dependency on tlsx CLI binary
- API now uses tlsx.Service directly via library
- Simplified Dockerfile.api (single binary build)
- Added proper PORT handling for Cloud Run
- Added verbose logging for deployment
- Fixed CORS configuration
- Self-contained deployment ready"

if [ $? -eq 0 ]; then
    echo "✓ Commit successful"
else
    echo "⚠ Commit failed or no changes to commit"
fi
echo ""

# Push to origin main
echo "Pushing to origin main..."
git push origin main

if [ $? -eq 0 ]; then
    echo "✓ Push successful"
else
    echo "✗ Push failed"
    exit 1
fi
echo ""

echo "=========================================="
echo "Git push complete!"
echo "=========================================="
echo ""
echo "Changes have been pushed to GitHub"
echo "Ready to deploy to Cloud Run with: ./deploy-api.sh"

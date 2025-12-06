#!/bin/bash

# Google Cloud SDK Installation Script (Non-interactive)

echo "Installing Google Cloud SDK..."

# Download and install with all prompts disabled
curl -fsSL https://sdk.cloud.google.com | bash -s -- --disable-prompts --install-dir=$HOME

# Add gcloud to PATH and enable completion
echo 'source $HOME/google-cloud-sdk/completion.bash.inc' >> ~/.bashrc
echo 'source $HOME/google-cloud-sdk/path.bash.inc' >> ~/.bashrc

# Load for current session
source ~/.bashrc 2>/dev/null || true
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

echo ""
echo "Installation complete!"
echo ""
echo "Run these commands to finish setup:"
echo "  source ~/.bashrc"
echo "  gcloud --version"
echo "  gcloud auth login"

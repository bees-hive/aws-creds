#!/bin/bash

DOWNLOAD_URL="https://raw.githubusercontent.com/bees-hive/aws-creds/main/aws-creds.py"
read -r -p "Enter the installation directory (leave blank for '/usr/local/bin'): " INSTALL_DIR
if [ -z "$INSTALL_DIR" ]; then
  INSTALL_DIR="/usr/local/bin"
fi
mkdir -p "$INSTALL_DIR"
INSTALLATION="$INSTALL_DIR/aws-creds"
curl -sSLo "$INSTALLATION" "$DOWNLOAD_URL"
chmod +x "$INSTALLATION"

echo "Installation complete. Please re-start the shell to use 'aws-creds'."

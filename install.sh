#!/usr/bin/env bash

# Exit if any command fails
set -e

echo "=== Detecting Operating System..."

OS=$(uname -s)

if [[ "$OS" == "Linux" ]]; then
  echo "=== Detected Linux"
  # Check if apt-get is available
  if command -v apt-get &> /dev/null; then
    echo "=== Installing TShark using apt-get..."
    sudo apt-get update
    sudo apt-get install -y tshark
  else
    echo "!!! 'apt-get' not found. Please install TShark manually."
  fi
elif [[ "$OS" == "Darwin" ]]; then
  echo "=== Detected macOS"
  # Check if Homebrew is available
  if command -v brew &> /dev/null; then
    echo "=== Installing Wireshark (includes TShark) via Homebrew..."
    brew install wireshark
  else
    echo "!!! Homebrew not found. Please install Homebrew, then run:"
    echo "    brew install wireshark"
  fi
else
  echo "!!! Unsupported OS: $OS"
  echo "!!! Please install TShark manually."
fi

echo "=== Installing Python dependencies from requirements.txt..."
pip install -r requirements.txt

echo "=== Installation complete!"
echo "You can now run your log collector script, for example:"
echo "  python3 all_in_one_log_collector.py"

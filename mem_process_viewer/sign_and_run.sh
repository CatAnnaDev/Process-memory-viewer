#!/bin/bash

# === Configuration ===
APP_NAME="mem_process_viewer"
ENTITLEMENTS="entitlements.plist"
TARGET="target/release/$APP_NAME"

# Check SIP status
csrutil status | grep -q "disabled" || {
  echo "❌ SIP is enabled. Please reboot into recovery mode and run: csrutil disable"
  exit 1
}

# === Step 1: Check entitlements file existence ===
if [ ! -f "$ENTITLEMENTS" ]; then
  echo "❌ $ENTITLEMENTS file not found. Please create it before running this script."
  exit 1
fi

# === Step 2: Build release ===
echo "🚧 Building project..."
cargo build --release || exit 1

# === Step 3: Remove previous signature (if any) ===
echo "🔄 Removing previous code signature..."
codesign --remove-signature "$TARGET" 2>/dev/null

# === Step 4: Code sign the binary ===
echo "🔏 Signing with certificate: $CERT_NAME"
codesign --entitlements "$ENTITLEMENTS" \
         --sign - \
         --force \
         --timestamp \
         "$TARGET" || exit 1

# === Step 5: Verify the signature ===
echo "🔍 Verifying code signature..."
codesign -dvvv "$TARGET"

# === Step 6: Run the signed app with sudo ===
echo "🚀 Launching signed application with sudo..."
sudo "$TARGET"

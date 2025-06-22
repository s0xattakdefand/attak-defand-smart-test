#!/bin/bash

echo "🔍 Running Foundry Preflight Check..."

# 1. Check for forge-std
if [ ! -f "lib/forge-std/src/Test.sol" ]; then
  echo "❌ forge-std not found. Installing..."
  forge install foundry-rs/forge-std || {
    echo "🔥 Failed to install forge-std. Exiting."
    exit 1
  }
else
  echo "✅ forge-std is present."
fi

# 2. Ensure foundry.toml exists
if [ ! -f "foundry.toml" ]; then
  echo "❌ foundry.toml not found. Please create one and define remappings."
  exit 1
fi

# 3. Ensure remappings are present
if ! grep -q 'remappings' foundry.toml; then
  echo "⚠️ No remappings found. Adding default remapping to foundry.toml..."
  echo 'remappings = ["forge-std=lib/forge-std/src"]' >> foundry.toml
elif ! grep -q 'forge-std=lib/forge-std/src' foundry.toml; then
  echo "⚠️ forge-std remapping missing. Appending..."
  sed -i '/remappings/ s/]$/, "forge-std=lib\/forge-std\/src"]/' foundry.toml
else
  echo "✅ Remapping for forge-std is present."
fi

# 4. Try building
echo "🔧 Running forge build..."
if forge build; then
  echo "✅ Build succeeded."
else
  echo "❌ Build failed. Check your remappings and contract imports."
  exit 1
fi

echo "🎉 Preflight check completed successfully."

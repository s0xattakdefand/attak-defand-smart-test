#!/bin/bash

echo "🔧 Inserting forge-std imports..."

# Handle test files
find test -name '*.t.sol' | while read file; do
  if ! grep -q 'forge-std/Test.sol' "$file"; then
    echo "➕ Adding Test.sol import to $file"
    sed -i '1iimport {Test, console} from "forge-std/Test.sol";\n' "$file"
  fi
done

# Handle script files
find script -name '*.s.sol' | while read file; do
  if ! grep -q 'forge-std/Script.sol' "$file"; then
    echo "➕ Adding Script.sol import to $file"
    sed -i '1iimport {Script, console} from "forge-std/Script.sol";\n' "$file"
  fi
done

echo "✅ All done!"

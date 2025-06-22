for file in $(find . -name '*.sol'); do
  echo "Linting $file"
  solhint "$file" || echo "❌ Failed: $file"
done

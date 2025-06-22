#!/bin/bash
set -e

VERSION=$1

if [[ -z "$VERSION" ]]; then
  echo "Usage: ./tag-release.sh v1.0.0 or testnet-0.1.0"
  exit 1
fi

git tag $VERSION
git push origin $VERSION
echo "✅ Pushed tag $VERSION"

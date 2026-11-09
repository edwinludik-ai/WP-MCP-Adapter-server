#!/usr/bin/env bash
# Builds dist/mcp-api-keys.zip: an installable WordPress plugin (Plugins > Add New > Upload).
# Only the runtime files below go in; tests, docs and CI stay out. The zip has one top-level
# folder named after the plugin slug, which is what WordPress expects.
set -euo pipefail
cd "$(dirname "$0")/.."

slug=mcp-api-keys
files=(mcp-api-keys.php uninstall.php README.md)

rm -rf dist
mkdir -p "dist/$slug"
cp "${files[@]}" "dist/$slug/"
# -X drops extra file attributes so the same input gives the same zip.
(cd dist && zip -qrX "$slug.zip" "$slug" && rm -rf "$slug")

unzip -l "dist/$slug.zip"
echo "dist/$slug.zip"

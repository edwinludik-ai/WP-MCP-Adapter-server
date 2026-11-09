#!/usr/bin/env bash
# Builds dist/mcp-api-keys.zip: an installable WordPress plugin (Plugins > Add New > Upload), and the
# package that is submitted to and deployed on WordPress.org. Only the runtime files below go in;
# tests, docs and CI stay out. The zip has one top-level folder named after the plugin slug.
set -euo pipefail
cd "$(dirname "$0")/.."

slug=mcp-api-keys
files=(mcp-api-keys.php uninstall.php readme.txt)

# The plugin header and the readme.txt Stable tag must agree, or WordPress.org shows the wrong version.
header=$(sed -n 's/^ \* Version: *//p' mcp-api-keys.php | head -n1)
stable=$(sed -n 's/^Stable tag: *//p' readme.txt | head -n1)
if [ -z "$header" ] || [ "$header" != "$stable" ]; then
  echo "Version mismatch: plugin header '$header' vs readme.txt Stable tag '$stable'" >&2
  exit 1
fi

rm -rf dist
mkdir -p "dist/$slug"
cp "${files[@]}" "dist/$slug/"
# -X drops extra file attributes so the same input gives the same zip.
(cd dist && zip -qrX "$slug.zip" "$slug" && rm -rf "$slug")

unzip -l "dist/$slug.zip"
echo "dist/$slug.zip (version $header)"

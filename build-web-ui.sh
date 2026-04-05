#!/bin/bash
# Copyright (C) 2026 Joyous Rebellion LLC
# Licensed under AGPL-3.0-or-later
#
# Build the React web client and copy the output to JR Local.
# The web UI at ../joyous-rebellion-web/ is the primary interface;
# the vanilla JS in src/ serves as a fallback if this script hasn't been run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_DIR="$SCRIPT_DIR/../joyous-rebellion-web"
OUTPUT_DIR="$SCRIPT_DIR/web-ui"

if [ ! -d "$WEB_DIR" ]; then
    echo "ERROR: Web client not found at $WEB_DIR"
    echo "Clone joyous-rebellion-web alongside joyous-rebellion-local."
    exit 1
fi

echo "Building React web client..."
cd "$WEB_DIR"
npm run build

echo "Copying build output to JR Local..."
rm -rf "$OUTPUT_DIR"
cp -r dist "$OUTPUT_DIR"

echo "Web UI built and copied to web-ui/"

#!/bin/sh
# Renders review.html to review.pdf with headless Chrome.
set -e
cd "$(dirname "$0")"
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$PWD/review.pdf" "file://$PWD/review.html" 2>/dev/null
echo "wrote $PWD/review.pdf"

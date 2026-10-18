#!/bin/sh
# GhostScope demo: pack the high-blast-radius fixture as a git range.
# Local only. Exits with a clear message if the core is not installed yet.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FIX="$HERE/../tests/fixtures/high_blast_radius"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cp -R "$FIX/base/." "$WORK/proj" 2>/dev/null || { mkdir -p "$WORK/proj"; cp -R "$FIX/base/." "$WORK/proj/"; }
cd "$WORK/proj"
git init -q .
git config user.email demo@example.com
git config user.name "GhostScope Demo"
git add -A && git commit -qm base
cp "$FIX/change/shared.py" shared.py
cp "$FIX/change/isolated.py" isolated.py
git add -A && git commit -qm change

if PYTHONPATH="$HERE/../src" python3 -c "import ghostscope" 2>/dev/null || command -v ghostscope >/dev/null 2>&1; then
  if command -v ghostscope >/dev/null 2>&1; then
    ghostscope pack . --base HEAD~1 --head HEAD -o "$WORK/pack"
  else
    PYTHONPATH="$HERE/../src" python3 -m ghostscope pack . --base HEAD~1 --head HEAD -o "$WORK/pack"
  fi
  echo "Pack written to $WORK/pack (temp dir, removed on exit in this demo script context)"
  cat "$WORK/pack/REVIEW.md" 2>/dev/null || find "$WORK/pack" -name REVIEW.md -exec cat {} \;
else
  echo "GhostScope core not installed yet: nothing to run."
  echo "The fixture repo was built at $WORK/proj and the expected outcome is:"
  echo "compute_total (1-line change, 6 callers) ranks above isolated.py (220-line change, 0 callers)."
  exit 3
fi

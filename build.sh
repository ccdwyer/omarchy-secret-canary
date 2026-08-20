#!/bin/sh
# Build canaryd. The plugin QML degrades to compat/canaryd.sh when
# bin/canaryd is missing, so a failed build is not fatal at runtime.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SRC="$ROOT/src/canaryd"
OUT="$ROOT/bin"

mkdir -p "$OUT"
chmod +x "$ROOT/compat/canaryd.sh" 2>/dev/null || true

if ! command -v cargo >/dev/null 2>&1; then
  echo "build.sh: cargo not found; leaving bin/canaryd unset so QML uses compat/canaryd.sh" >&2
  rm -f "$OUT/canaryd"
  exit 0
fi

if ! cargo build --release --manifest-path "$SRC/Cargo.toml"; then
  echo "build.sh: cargo build failed; leaving bin/canaryd unset so QML uses compat/canaryd.sh" >&2
  rm -f "$OUT/canaryd"
  exit 1
fi

BIN="$SRC/target/release/canaryd"
if [ ! -x "$BIN" ]; then
  echo "build.sh: release binary missing after cargo build" >&2
  exit 1
fi
cp "$BIN" "$OUT/canaryd"
chmod +x "$OUT/canaryd"
echo "build.sh: wrote $OUT/canaryd"

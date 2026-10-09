#!/bin/sh
# Test only G.711 companding, not a real mobile speech call.
set -eu
cd "$(dirname "$0")/.."
command -v sox >/dev/null || { echo 'SoX required'; exit 1; }
TMPDIR_RUN=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RUN"' EXIT INT TERM
node modem.js encode --in examples/hello.txt --out "$TMPDIR_RUN/original.wav" --baud 100 >/dev/null
for CODEC in mu-law a-law; do
  sox -q "$TMPDIR_RUN/original.wav" -r 8000 -c 1 -e "$CODEC" "$TMPDIR_RUN/encoded.wav"
  sox -q "$TMPDIR_RUN/encoded.wav" -r 8000 -c 1 -b 16 -e signed-integer "$TMPDIR_RUN/decoded.wav"
  node modem.js decode --in "$TMPDIR_RUN/decoded.wav" --out "$TMPDIR_RUN/output.bin" --baud 100 >/dev/null
  cmp examples/hello.txt "$TMPDIR_RUN/output.bin"
  echo "PASS simulated G.711 $CODEC companding at 100 bit/s"
done

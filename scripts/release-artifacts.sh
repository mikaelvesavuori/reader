#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

npm run build

rm -rf release
mkdir -p release

cp dist/worker.js release/worker.js
cp README.md LICENSE package.json wrangler.toml release/

rm -f reader_release.zip worker.js.sha256 reader_release.zip.sha256

(
  cd release
  zip -r ../reader_release.zip .
)

shasum -a 256 dist/worker.js > worker.js.sha256
shasum -a 256 reader_release.zip > reader_release.zip.sha256

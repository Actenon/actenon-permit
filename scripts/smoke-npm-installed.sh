#!/usr/bin/env bash
# Install an npm package exactly as a consumer would — from a packed tarball or
# from the registry (name@version) — into an empty project, and import it under
# plain Node.js (no Bun, no TypeScript loader).
#
#   scripts/smoke-npm-installed.sh <tarball-or-name@version> <package-name> <export> [<export> ...]
#
# Used before publishing (on the exact tarball that will be published) and after
# publishing (on the version the registry serves).
set -euo pipefail
spec=$1
name=$2
shift 2
case "$spec" in
  /*|./*|../*) spec=$(cd "$(dirname "$spec")" && pwd)/$(basename "$spec") ;;
esac
exports_json=$(printf '%s\n' "$@" | node -e 'console.log(JSON.stringify(require("fs").readFileSync(0,"utf8").split("\n").filter(Boolean)))')
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
npm init -y >/dev/null
npm install --silent --no-audit --no-fund "$spec" >/dev/null
node --input-type=module -e "
const m = await import('$name');
const missing = $exports_json.filter((k) => !(k in m));
if (missing.length) throw new Error('missing exports: ' + missing.join(', '));
console.log('node ' + process.version + ': import(\"$name\") OK from $spec (' + Object.keys(m).length + ' exports)');
"

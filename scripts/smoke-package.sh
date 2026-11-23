#!/usr/bin/env bash
#
# Pack the built package, install the tarball in a clean directory, and
# exercise the entries consumers load:
#
#   - CommonJS require() of the root, subpaths and a deep module
#   - Node ESM import, which must resolve to the CommonJS build; bundlers keep
#     the ESM build (see scripts/browser-smoke.mjs)
#   - a browser bundle, which must inline the npm Buffer polyfill with no Node
#     builtin left external
#
# Run after `npm run build`.

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

npm pack --silent --pack-destination "$tmp" >/dev/null
tarball=$(find "$tmp" -maxdepth 1 -name 'xpi-ts-*.tgz' -print -quit)
[ -n "$tarball" ] || {
    echo "error: npm pack produced no tarball" >&2
    exit 1
}

contents=$(tar -tzf "$tarball")
for required in \
    package/package.json \
    package/dist/cjs/index.js \
    package/dist/esm/index.js \
    package/dist/esm/package.json \
    package/dist/types/index.d.ts; do
    if ! grep -qx "$required" <<<"$contents"; then
        echo "error: tarball is missing $required" >&2
        exit 1
    fi
done
# Sources, tests and build configuration must not ship.
if leaked=$(
    grep -E \
        '^package/(scripts/|test/|gulpfile\.js|jest\.config\.js|tsconfig[^/]*\.json|eslint\.config\.mjs|release\.sh|RELEASE\.md)' \
        <<<"$contents"
); then
    echo "error: development files leaked into the tarball:" >&2
    echo "$leaked" >&2
    exit 1
fi

mkdir "$tmp/smoke"
cd "$tmp/smoke"
npm init -y >/dev/null 2>&1
npm install "$tarball" --ignore-scripts --silent >/dev/null

cat >cjs-smoke.cjs <<'JS'
const assert = require('node:assert/strict')

const root = require('xpi-ts')
assert.equal(root.CHAIN_FORK_ID, 0x4c4f54)
const bitcore = require('xpi-ts/lib/bitcore')
assert.equal(bitcore.CHAIN_FORK_ID, 0x4c4f54)
const rank = require('xpi-ts/lib/rank')
assert.equal(rank.LOKAD_PREFIX_RANK, 0x52414e4b)
const address = require('xpi-ts/lib/bitcore/address')
assert.equal(typeof address.Address, 'function')

for (const specifier of [
  'xpi-ts',
  'xpi-ts/lib/bitcore',
  'xpi-ts/lib/rank',
  'xpi-ts/lib/bitcore/address',
]) {
  assert.match(require.resolve(specifier), /[/\\]dist[/\\]cjs[/\\]/)
}
require.resolve('xpi-ts/package.json')
JS
node cjs-smoke.cjs

cat >esm-smoke.mjs <<'JS'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import * as root from 'xpi-ts'
import * as bitcore from 'xpi-ts/lib/bitcore'
import * as rank from 'xpi-ts/lib/rank'
import { Address } from 'xpi-ts/lib/bitcore/address'

const require = createRequire(import.meta.url)

assert.equal(root.CHAIN_FORK_ID, 0x4c4f54)
assert.equal(bitcore.CHAIN_FORK_ID, 0x4c4f54)
assert.equal(rank.LOKAD_PREFIX_RANK, 0x52414e4b)
assert.equal(typeof Address, 'function')

// The exports map sends Node to dist/cjs. Proving it by identity: an ESM
// namespace built from the same CommonJS module shares its object exports,
// while dist/esm would be a separate module instance.
assert.equal(root.Bitcore, require('xpi-ts').Bitcore)
assert.equal(bitcore.Hash, require('xpi-ts/lib/bitcore').Hash)
assert.equal(
  rank.SCRIPT_CHUNK_LOKAD,
  require('xpi-ts/lib/rank').SCRIPT_CHUNK_LOKAD,
)
assert.equal(Address, require('xpi-ts/lib/bitcore/address').Address)
JS
node esm-smoke.mjs

node "$root/scripts/browser-smoke.mjs" "$tmp/smoke"

echo "package smoke test passed"

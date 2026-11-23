/**
 * Browser bundling smoke test.
 *
 * Bundles the installed tarball the way a browser bundler resolves it and
 * checks that the exports map still serves the ESM build, that the npm
 * `buffer` polyfill is inlined, and that nothing is left external (which is
 * how a Node builtin would leak into a browser bundle).
 *
 * Usage: node scripts/browser-smoke.mjs <directory-with-installed-xpi-ts>
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { writeFile } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { build } from 'esbuild'

const dir = process.argv[2]
assert.ok(dir, 'usage: browser-smoke.mjs <directory-with-installed-xpi-ts>')

const entry = path.join(dir, 'browser-entry.mjs')
await writeFile(
  entry,
  `import { CHAIN_FORK_ID, Bitcore } from 'xpi-ts'
import { LOKAD_PREFIX_RANK } from 'xpi-ts/lib/rank'
import { Address } from 'xpi-ts/lib/bitcore/address'

const fail = message => {
  throw new Error(message)
}

if (CHAIN_FORK_ID !== 0x4c4f54) fail('browser bundle fork id: ' + CHAIN_FORK_ID)
if (!Bitcore || Bitcore.CHAIN_FORK_ID !== 0x4c4f54) {
  fail('browser bundle is missing the Bitcore namespace')
}
if (LOKAD_PREFIX_RANK !== 0x52414e4b) {
  fail('browser bundle rank prefix: ' + LOKAD_PREFIX_RANK)
}
if (typeof Address !== 'function') fail('browser bundle is missing Address')
`,
)

const outfile = path.join(dir, 'browser-bundle.mjs')
const result = await build({
  absWorkingDir: dir,
  entryPoints: [entry],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  outfile,
  metafile: true,
  logLevel: 'silent',
})

const inputs = Object.keys(result.metafile.inputs)
const hasInput = suffix => inputs.some(input => input.endsWith(suffix))

assert.ok(
  hasInput('xpi-ts/dist/esm/index.js'),
  'a browser bundle must resolve the ESM build through the exports map',
)
assert.ok(
  !inputs.some(input => input.includes('xpi-ts/dist/cjs/')),
  'a browser bundle must not take the CommonJS build',
)
assert.ok(
  hasInput('node_modules/buffer/index.js'),
  'the npm buffer polyfill must be bundled',
)

const outputs = Object.values(result.metafile.outputs)
assert.equal(outputs.length, 1, 'expected exactly one bundle output')
assert.deepEqual(
  outputs[0].imports,
  [],
  'the bundle must not leave imports external',
)

// Running in Node only proves the bundle is self-contained; the entry above
// asserts the exported values.
execFileSync(process.execPath, [outfile], { stdio: 'inherit' })

process.stdout.write('browser bundle smoke test passed\n')

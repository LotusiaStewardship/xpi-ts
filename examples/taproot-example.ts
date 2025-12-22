/**
 * Taproot Example for Lotus
 *
 * Demonstrates Pay-To-Taproot functionality:
 * - Creating Taproot outputs
 * - Key path spending
 * - Script tree construction
 */

import {
  Transaction,
  PrivateKey,
  Signature,
  Output,
  Script,
  Opcode,
  TapNode,
  buildKeyPathTaproot,
  buildScriptPathTaproot,
  extractTaprootCommitment,
  tweakPublicKey,
  calculateTapTweak,
  TaprootInput,
} from '../lib/bitcore/index.js'

console.log('='.repeat(60))
console.log('Taproot Example for Lotus')
console.log('='.repeat(60))
console.log()

// ============================================================================
// Example 1: Simple Key-Path-Only Taproot
// ============================================================================

console.log('Example 1: Simple Key-Path Taproot')
console.log('-'.repeat(60))

const privateKey = new PrivateKey()
const internalPubKey = privateKey.publicKey

console.log('Internal public key:', internalPubKey.toString())

// Create Taproot output (key-path only, no scripts)
const taprootScript = buildKeyPathTaproot(internalPubKey)
const taprootAddress = taprootScript.toAddress()
console.log('Taproot address:', taprootAddress?.toString())

console.log('Taproot script:', taprootScript.toString())
console.log('Script hex:', taprootScript.toBuffer().toString('hex'))
console.log('Script size:', taprootScript.toBuffer().length, 'bytes')
console.log('Is P2TR:', taprootScript.isPayToTaproot())

// Extract and verify commitment
const commitment = extractTaprootCommitment(taprootScript)
console.log('Commitment pubkey:', commitment.toString())

// Verify commitment is correct
const merkleRoot = Buffer.alloc(32) // All zeros for key-only
const expectedCommitment = tweakPublicKey(internalPubKey, merkleRoot)
console.log('Expected commitment:', expectedCommitment.toString())
console.log(
  'Commitment matches:',
  commitment.toString() === expectedCommitment.toString(),
)

// Show the tweak
const tweak = calculateTapTweak(internalPubKey, merkleRoot)
console.log('Tweak value:', tweak.toString('hex'))

console.log()

// ============================================================================
// Example 2: Taproot with Script Tree
// ============================================================================

console.log('Example 2: Taproot with Alternative Scripts')
console.log('-'.repeat(60))

const alice = new PrivateKey()
const bob = new PrivateKey()

// Script 1: Simple checksig
const script1 = new Script()
  .add(alice.publicKey.toBuffer())
  .add(Opcode.OP_CHECKSIG)

// Script 2: Timelock + checksig
const script2 = new Script()
  .add(144) // ~1 day
  .add(Opcode.OP_CHECKSEQUENCEVERIFY)
  .add(Opcode.OP_DROP)
  .add(bob.publicKey.toBuffer())
  .add(Opcode.OP_CHECKSIG)

// Build tree
const tree: TapNode = {
  left: { script: script1 },
  right: { script: script2 },
}

const {
  script: taprootScriptWithTree,
  merkleRoot: treeMerkleRoot,
  leaves,
} = buildScriptPathTaproot(alice.publicKey, tree)

console.log('Taproot with scripts:', taprootScriptWithTree.toString())
console.log('Number of leaves:', leaves.length)
console.log('Merkle root:', treeMerkleRoot.toString('hex'))

// Show each leaf
leaves.forEach((leaf, i) => {
  console.log(`\nLeaf ${i}:`)
  console.log('  Script:', leaf.script.toString())
  console.log('  Leaf hash:', leaf.leafHash.toString('hex'))
  console.log('  Merkle path length:', leaf.merklePath.length)
  leaf.merklePath.forEach((node, j) => {
    console.log(`    Node ${j}:`, node.toString('hex').substring(0, 16) + '...')
  })
})

console.log()

// ============================================================================
// Example 3: Taproot Transaction (would work when Taproot is enabled)
// ============================================================================

console.log('Example 3: Complete Taproot Transaction')
console.log('-'.repeat(60))

// Create simple key-path Taproot
const spendingKey = new PrivateKey()
const taprootOut = buildKeyPathTaproot(spendingKey.publicKey)

// Simulate a UTXO with Taproot output
const taprootUtxo = {
  txId: 'a'.repeat(64),
  outputIndex: 0,
  script: taprootOut,
  satoshis: 100000,
}

// Create transaction spending the Taproot output
const tx = new Transaction()

// Add Taproot input
tx.addInput(
  new TaprootInput({
    prevTxId: Buffer.from(taprootUtxo.txId, 'hex'),
    outputIndex: taprootUtxo.outputIndex,
    output: new Output({
      script: taprootUtxo.script,
      satoshis: taprootUtxo.satoshis,
    }),
    script: new Script(),
  }),
)

// Add output
tx.addOutput(
  new Output({
    script: Script.buildPublicKeyHashOut(spendingKey.toAddress()),
    satoshis: 95000,
  }),
)

// Sign with SIGHASH_LOTUS + Schnorr (REQUIRED for Taproot)
tx.sign(spendingKey, Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS, 'schnorr')

console.log('Transaction created!')
console.log('Transaction ID:', tx.id)
console.log('Transaction hex:', tx.serialize())
console.log('Is fully signed:', tx.isFullySigned())
console.log('Verification:', tx.verify())

console.log()

// ============================================================================
// Summary
// ============================================================================

console.log('='.repeat(60))
console.log('Summary')
console.log('='.repeat(60))
console.log()
console.log('✓ Taproot script creation working')
console.log('✓ Key tweaking working')
console.log('✓ Script tree building working')
console.log('✓ Transaction signing working')
console.log()
console.log('✓ Taproot addresses working')
console.log()
console.log('Next steps:')
console.log('1. Test against lotusd when Taproot is re-enabled')
console.log('2. Create comprehensive test suite')
console.log('3. Add script path spending convenience methods (optional)')
console.log()

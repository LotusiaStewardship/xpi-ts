/**
 * MuSig2Signer Wrapper Example
 *
 * Demonstrates the simplified MuSig2Signer API for easy multi-signature implementation
 */

import {
  PrivateKey,
  MuSig2Signer,
  createMuSig2Signer,
  Schnorr,
  Hash,
} from '../lib/bitcore/index.js'

console.log('═══════════════════════════════════════════════════')
console.log('  MuSig2Signer - Simplified API Example')
console.log('═══════════════════════════════════════════════════')
console.log()

// ============================================================================
// Example 1: Simple Message Signing
// ============================================================================

console.log('Example 1: Simple 2-of-2 Message Signing')
console.log('──────────────────────────────────────────────────')
console.log()

const alice = new PrivateKey()
const bob = new PrivateKey()

// Create signers
const aliceSigner = new MuSig2Signer({
  signers: [alice.publicKey, bob.publicKey],
  myPrivateKey: alice,
})

const bobSigner = new MuSig2Signer({
  signers: [alice.publicKey, bob.publicKey],
  myPrivateKey: bob,
})

console.log('Signers:')
console.log('  Alice:', alice.publicKey.toString().slice(0, 40) + '...')
console.log('  Bob:  ', bob.publicKey.toString().slice(0, 40) + '...')
console.log()

// Message to sign
const messageText = 'Transfer 1000 LOTUS'
const message = Hash.sha256(Buffer.from(messageText, 'utf8'))

console.log('Message:', messageText)
console.log('  Hash:', message.toString('hex').slice(0, 32) + '...')
console.log()

// Round 1: Prepare (generate nonces)
console.log('Round 1: Prepare')
const alicePrepare = aliceSigner.prepare(message)
const bobPrepare = bobSigner.prepare(message)

console.log('  ✓ Alice generated nonces')
console.log('  ✓ Bob generated nonces')
console.log('  (Signers exchange public nonces)')
console.log()

// Round 2: Create partial signatures
console.log('Round 2: Partial Signatures')
const allNonces = [alicePrepare.myPublicNonces, bobPrepare.myPublicNonces]

const alicePartial = aliceSigner.createPartialSignature(
  alicePrepare,
  allNonces,
  message,
)
const bobPartial = bobSigner.createPartialSignature(
  bobPrepare,
  allNonces,
  message,
)

console.log('  ✓ Alice created partial signature')
console.log('  ✓ Bob created partial signature')
console.log('  (Signers exchange partial signatures)')
console.log()

// Verify partial signatures
const aliceValid = aliceSigner.verifyPartialSignature(
  bobPartial,
  bobPrepare.myPublicNonces,
  bob.publicKey,
  1,
  alicePrepare,
  allNonces,
  message,
)
console.log("  Alice verified Bob's signature:", aliceValid ? '✓' : '✗')

const bobValid = bobSigner.verifyPartialSignature(
  alicePartial,
  alicePrepare.myPublicNonces,
  alice.publicKey,
  0,
  bobPrepare,
  allNonces,
  message,
)
console.log("  Bob verified Alice's signature:", bobValid ? '✓' : '✗')
console.log()

// Round 3: Aggregate
console.log('Round 3: Aggregate Final Signature')
const allPartialSigs = [alicePartial, bobPartial]
const result = aliceSigner.sign(
  alicePrepare,
  allNonces,
  message,
  allPartialSigs,
)

console.log('  ✓ Signature aggregated')
console.log(
  '  Final signature:',
  result.signature.toString().slice(0, 40) + '...',
)
console.log()

// Verify final signature
console.log('Verification')
const verified = Schnorr.verify(
  message,
  result.signature,
  result.aggregatedPubKey,
  'big',
)
console.log('  Signature valid:', verified ? '✓ VALID' : '✗ INVALID')
console.log()

// ============================================================================
// Example 2: Using Helper Function
// ============================================================================

console.log()
console.log('Example 2: Using createMuSig2Signer() Helper')
console.log('──────────────────────────────────────────────────')
console.log()

const carol = new PrivateKey()
const dave = new PrivateKey()

// Quick creation using helper
const carolSigner = createMuSig2Signer([carol.publicKey, dave.publicKey], carol)

const testMessage = Hash.sha256(Buffer.from('test', 'utf8'))
const carolPrepare = carolSigner.prepare(testMessage)

console.log('  Created signer:', carolSigner.myIndex === 0 ? '✓' : '✗')
console.log(
  '  My public key:',
  carolSigner.myPublicKey.toString().slice(0, 40) + '...',
)
console.log('  All signers:', carolSigner.allSigners.length, 'signers')
console.log()

console.log('═══════════════════════════════════════════════════')
console.log('Summary')
console.log('═══════════════════════════════════════════════════')
console.log()
console.log('Benefits of MuSig2Signer:')
console.log('  ✓ Simplified API (3 methods vs 6+ low-level functions)')
console.log('  ✓ Automatic message normalization (32-byte hash)')
console.log('  ✓ Type-safe interfaces')
console.log('  ✓ Built-in validation')
console.log('  ✓ Taproot integration helpers')
console.log('  ✓ Session management support')
console.log()

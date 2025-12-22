/**
 * MuSig2 Session Manager Example
 *
 * Demonstrates how to use the MuSigSessionManager for coordinated multi-party signing
 */

import {
  PrivateKey,
  MuSigSessionManager,
  MuSigSessionPhase,
  Schnorr,
  Hash,
} from '../lib/bitcore/index.js'

console.log('═══════════════════════════════════════════════════')
console.log('  MuSig2 Session Manager Example')
console.log('═══════════════════════════════════════════════════')
console.log()

// Scenario: 2-of-2 multisig for a shared account
console.log('Scenario: Alice and Bob co-signing a message')
console.log('──────────────────────────────────────────────────')
console.log()

// Setup: Create private keys for Alice and Bob
const alice = new PrivateKey()
const bob = new PrivateKey()

console.log('Participants:')
console.log('  Alice:', alice.publicKey.toString().slice(0, 40) + '...')
console.log('  Bob:  ', bob.publicKey.toString().slice(0, 40) + '...')
console.log()

// Message to sign (MUST be 32 bytes for Schnorr!)
// In practice, this would be a transaction sighash
const messageText = 'Transfer 1000 LOTUS from shared account'
const message = Buffer.from(Hash.sha256(Buffer.from(messageText, 'utf8')))

console.log('Message to sign:')
console.log(' ', messageText)
console.log('  Hash:', message.toString('hex').slice(0, 32) + '...')
console.log()

// Create session manager
const manager = new MuSigSessionManager()

// Both participants create their view of the session
// NOTE: They must agree on the signer order!
const signers = [alice.publicKey, bob.publicKey]

console.log('Step 1: Create Sessions')
const aliceSession = manager.createSession(signers, alice, message)
const bobSession = manager.createSession(signers, bob, message)

console.log('  ✓ Alice created session:', aliceSession.sessionId)
console.log('  ✓ Bob created session:  ', bobSession.sessionId)
console.log(
  '  ✓ Aggregated key:',
  aliceSession.keyAggContext.aggregatedPubKey.toString().slice(0, 40) + '...',
)
console.log()

// Round 1: Nonce Exchange
console.log('Step 2: Round 1 - Nonce Exchange')
const aliceNonces = manager.generateNonces(aliceSession, alice)
const bobNonces = manager.generateNonces(bobSession, bob)

console.log('  ✓ Alice generated nonces')
console.log('  ✓ Bob generated nonces')
console.log('  (Participants exchange public nonces)')
console.log()

// Participants receive each other's nonces
manager.receiveNonces(aliceSession, 1, bobNonces)
manager.receiveNonces(bobSession, 0, aliceNonces)

console.log("  ✓ Alice received Bob's nonces")
console.log("  ✓ Bob received Alice's nonces")
console.log('  ✓ Nonces aggregated automatically')
console.log()

// Check session status
const aliceStatus = manager.getSessionStatus(aliceSession)
console.log('Session Status:')
console.log('  Phase:', aliceStatus.phase)
console.log(
  '  Nonces collected:',
  aliceStatus.noncesCollected,
  '/',
  aliceStatus.noncesTotal,
)
console.log()

// Round 2: Partial Signatures
console.log('Step 3: Round 2 - Partial Signatures')
const alicePartialSig = manager.createPartialSignature(aliceSession, alice)
const bobPartialSig = manager.createPartialSignature(bobSession, bob)

console.log('  ✓ Alice created partial signature')
console.log('  ✓ Bob created partial signature')
console.log('  (Participants exchange partial signatures)')
console.log()

// Participants receive each other's partial signatures
manager.receivePartialSignature(aliceSession, 1, bobPartialSig)
manager.receivePartialSignature(bobSession, 0, alicePartialSig)

console.log("  ✓ Alice received Bob's partial signature")
console.log("  ✓ Bob received Alice's partial signature")
console.log('  ✓ Signature aggregated automatically')
console.log()

// Get final signature
const aliceFinalSig = manager.getFinalSignature(aliceSession)
const bobFinalSig = manager.getFinalSignature(bobSession)

console.log('Step 4: Final Signature')
console.log("  Alice's view:", aliceFinalSig.toString().slice(0, 40) + '...')
console.log("  Bob's view:  ", bobFinalSig.toString().slice(0, 40) + '...')
console.log(
  '  Signatures match:',
  aliceFinalSig.toString() === bobFinalSig.toString() ? '✓' : '✗',
)
console.log()

// Verify signature
console.log('Step 5: Verification')
const verified = Schnorr.verify(
  message,
  aliceFinalSig,
  aliceSession.keyAggContext.aggregatedPubKey,
  'big',
)

console.log('  Signature verifies:', verified ? '✓ VALID' : '✗ INVALID')
console.log()

// Session summary
const finalStatus = manager.getSessionStatus(aliceSession)
console.log('═══════════════════════════════════════════════════')
console.log('  Session Complete!')
console.log('═══════════════════════════════════════════════════')
console.log()
console.log('Final Status:')
console.log('  Phase:', finalStatus.phase)
console.log('  Complete:', finalStatus.isComplete ? 'YES' : 'NO')
console.log('  Signature Size:', aliceFinalSig.toBuffer().length, 'bytes')
console.log()

console.log('Benefits:')
console.log('  ✓ Privacy: Multi-sig looks like single-sig on-chain')
console.log('  ✓ Efficiency: 64-byte signature (same as single-sig)')
console.log('  ✓ Non-interactive: Only 2 rounds of communication')
console.log('  ✓ Secure: Provably secure under discrete log assumption')
console.log()

console.log('Communication:')
console.log('  Round 1: ~66 bytes per participant (2 × 33-byte nonces)')
console.log('  Round 2: ~32 bytes per participant (1 × 32-byte partial sig)')
console.log('  Total:   ~98 bytes per participant')
console.log()

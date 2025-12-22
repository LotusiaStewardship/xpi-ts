/**
 * MuSig2 + Taproot Integration Tests
 *
 * Tests for MuSig2 integration with Taproot outputs
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import {
  PrivateKey,
  buildMuSigTaprootKey,
  buildMuSigTaprootKeyWithScripts,
  musigNonceGen,
  musigNonceAgg,
  signTaprootKeyPathWithMuSig2,
  verifyTaprootKeyPathMuSigPartial,
  musigSigAgg,
  Schnorr,
  Script,
  Opcode,
  extractTaprootCommitment,
  tweakPublicKey,
} from '../lib/bitcore/index.js'

describe('MuSig2 + Taproot Integration', () => {
  describe('buildMuSigTaprootKey', () => {
    it('should create MuSig2 Taproot output with 2 signers', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      const result = buildMuSigTaprootKey([alice.publicKey, bob.publicKey])

      assert.ok(result.aggregatedPubKey)
      assert.ok(result.commitment)
      assert.ok(result.script)
      assert.ok(result.keyAggContext)
      assert.ok(result.tweak)
      assert.strictEqual(result.merkleRoot.length, 32)
      assert.ok(result.script.isPayToTaproot())
    })

    it('should create MuSig2 Taproot output with N signers', () => {
      const keys = [
        new PrivateKey(),
        new PrivateKey(),
        new PrivateKey(),
        new PrivateKey(),
        new PrivateKey(),
      ]

      const result = buildMuSigTaprootKey(keys.map(k => k.publicKey))

      assert.strictEqual(result.keyAggContext.pubkeys.length, 5)
      assert.ok(result.script.isPayToTaproot())
    })

    it('should extract commitment from Taproot script', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      const result = buildMuSigTaprootKey([alice.publicKey, bob.publicKey])

      const extracted = extractTaprootCommitment(result.script)

      assert.strictEqual(
        extracted.toString(),
        result.commitment.toString(),
        'Extracted commitment should match',
      )
    })

    it('should have correct Taproot tweak', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      const result = buildMuSigTaprootKey([alice.publicKey, bob.publicKey])

      // Verify tweak: commitment = aggregatedKey + tweak*G
      const expectedCommitment = tweakPublicKey(
        result.aggregatedPubKey,
        result.merkleRoot,
      )

      assert.strictEqual(
        result.commitment.toString(),
        expectedCommitment.toString(),
        'Commitment should equal tweaked aggregated key',
      )
    })
  })

  describe('buildMuSigTaprootKeyWithScripts', () => {
    it('should create MuSig2 Taproot with script tree', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      // Create timelock fallback script
      const timelockScript = new Script()
        .add(144) // 1 day timelock
        .add(Opcode.OP_CHECKSEQUENCEVERIFY)
        .add(Opcode.OP_DROP)
        .add(alice.publicKey.toBuffer())
        .add(Opcode.OP_CHECKSIG)

      const tree = {
        type: 'leaf' as const,
        script: timelockScript,
      }

      const result = buildMuSigTaprootKeyWithScripts(
        [alice.publicKey, bob.publicKey],
        tree,
      )

      assert.ok(result.aggregatedPubKey)
      assert.ok(result.commitment)
      assert.ok(result.script)
      assert.ok(result.leaves)
      assert.strictEqual(result.leaves.length, 1)
      assert.ok(result.merkleRoot.length === 32)
      // Merkle root should NOT be all zeros (has script tree)
      assert.notStrictEqual(result.merkleRoot.toString('hex'), '0'.repeat(64))
    })
  })

  describe('signTaprootKeyPathWithMuSig2', () => {
    it('should create valid partial signature for Taproot', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      const result = buildMuSigTaprootKey([alice.publicKey, bob.publicKey])
      const message = Buffer.alloc(32).fill(0x42)

      const aliceNonce = musigNonceGen(alice, result.aggregatedPubKey, message)
      const bobNonce = musigNonceGen(bob, result.aggregatedPubKey, message)
      const aggNonce = musigNonceAgg([
        aliceNonce.publicNonces,
        bobNonce.publicNonces,
      ])

      const alicePartial = signTaprootKeyPathWithMuSig2(
        aliceNonce,
        alice,
        result.keyAggContext,
        0,
        aggNonce,
        message,
        result.tweak, // Use tweak, not commitment!
      )

      assert.ok(alicePartial)
      assert.ok(!alicePartial.isZero())
    })

    it('partial signatures should verify with commitment', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      const result = buildMuSigTaprootKey([alice.publicKey, bob.publicKey])
      const message = Buffer.alloc(32).fill(0x43)

      const aliceNonce = musigNonceGen(alice, result.aggregatedPubKey, message)
      const bobNonce = musigNonceGen(bob, result.aggregatedPubKey, message)
      const aggNonce = musigNonceAgg([
        aliceNonce.publicNonces,
        bobNonce.publicNonces,
      ])

      const alicePartial = signTaprootKeyPathWithMuSig2(
        aliceNonce,
        alice,
        result.keyAggContext,
        0,
        aggNonce,
        message,
        result.tweak,
      )

      const valid = verifyTaprootKeyPathMuSigPartial(
        alicePartial,
        aliceNonce.publicNonces,
        alice.publicKey,
        result.keyAggContext,
        0,
        aggNonce,
        message,
        result.tweak,
      )

      assert.ok(valid, 'Taproot MuSig2 partial signature should verify')
    })
  })

  describe('Complete Taproot + MuSig2 Flow', () => {
    it('should create complete MuSig2 Taproot signature (2-of-2)', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      // 1. Create MuSig2 Taproot output
      const result = buildMuSigTaprootKey([alice.publicKey, bob.publicKey])

      // 2. Message (transaction sighash)
      const message = Buffer.alloc(32).fill(0x44)

      // 3. Round 1: Nonces
      const aliceNonce = musigNonceGen(alice, result.aggregatedPubKey, message)
      const bobNonce = musigNonceGen(bob, result.aggregatedPubKey, message)
      const aggNonce = musigNonceAgg([
        aliceNonce.publicNonces,
        bobNonce.publicNonces,
      ])

      // Find correct signer indices from the key aggregation context
      const aliceIndex = result.keyAggContext.pubkeys.findIndex(
        key => key.toString() === alice.publicKey.toString(),
      )
      const bobIndex = result.keyAggContext.pubkeys.findIndex(
        key => key.toString() === bob.publicKey.toString(),
      )

      // 4. Round 2: Partial signatures (with Taproot tweak)
      const alicePartial = signTaprootKeyPathWithMuSig2(
        aliceNonce,
        alice,
        result.keyAggContext,
        aliceIndex,
        aggNonce,
        message,
        result.tweak,
      )
      const bobPartial = signTaprootKeyPathWithMuSig2(
        bobNonce,
        bob,
        result.keyAggContext,
        bobIndex,
        aggNonce,
        message,
        result.tweak,
      )

      // 5. Aggregate (with commitment)
      const finalSig = musigSigAgg(
        [alicePartial, bobPartial],
        aggNonce,
        message,
        result.commitment,
      )

      // 6. Verify with commitment
      const verified = Schnorr.verify(
        message,
        finalSig,
        result.commitment,
        'big',
      )

      assert.ok(verified, 'MuSig2 Taproot signature should verify')
      console.log('✓ 2-of-2 MuSig2 Taproot signature verified!')
    })

    it('should work with 3-of-3 MuSig2 Taproot', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const carol = new PrivateKey()

      const result = buildMuSigTaprootKey([
        alice.publicKey,
        bob.publicKey,
        carol.publicKey,
      ])

      const message = Buffer.alloc(32).fill(0x45)

      const aliceNonce = musigNonceGen(alice, result.aggregatedPubKey, message)
      const bobNonce = musigNonceGen(bob, result.aggregatedPubKey, message)
      const carolNonce = musigNonceGen(carol, result.aggregatedPubKey, message)

      // Find correct signer indices from the key aggregation context
      const aliceIndex = result.keyAggContext.pubkeys.findIndex(
        key => key.toString() === alice.publicKey.toString(),
      )
      const bobIndex = result.keyAggContext.pubkeys.findIndex(
        key => key.toString() === bob.publicKey.toString(),
      )
      const carolIndex = result.keyAggContext.pubkeys.findIndex(
        key => key.toString() === carol.publicKey.toString(),
      )

      const aggNonce = musigNonceAgg([
        aliceNonce.publicNonces,
        bobNonce.publicNonces,
        carolNonce.publicNonces,
      ])

      const alicePartial = signTaprootKeyPathWithMuSig2(
        aliceNonce,
        alice,
        result.keyAggContext,
        aliceIndex,
        aggNonce,
        message,
        result.tweak,
      )
      const bobPartial = signTaprootKeyPathWithMuSig2(
        bobNonce,
        bob,
        result.keyAggContext,
        bobIndex,
        aggNonce,
        message,
        result.tweak,
      )
      const carolPartial = signTaprootKeyPathWithMuSig2(
        carolNonce,
        carol,
        result.keyAggContext,
        carolIndex,
        aggNonce,
        message,
        result.tweak,
      )

      const finalSig = musigSigAgg(
        [alicePartial, bobPartial, carolPartial],
        aggNonce,
        message,
        result.commitment,
      )

      const verified = Schnorr.verify(
        message,
        finalSig,
        result.commitment,
        'big',
      )

      assert.ok(verified, '3-of-3 MuSig2 Taproot signature should verify')
      console.log('✓ 3-of-3 MuSig2 Taproot signature verified!')
    })

    it('should fail if using wrong key for verification', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      const result = buildMuSigTaprootKey([alice.publicKey, bob.publicKey])
      const message = Buffer.alloc(32).fill(0x46)

      const aliceNonce = musigNonceGen(alice, result.aggregatedPubKey, message)
      const bobNonce = musigNonceGen(bob, result.aggregatedPubKey, message)
      const aggNonce = musigNonceAgg([
        aliceNonce.publicNonces,
        bobNonce.publicNonces,
      ])

      // Find correct signer indices from the key aggregation context
      const aliceIndex = result.keyAggContext.pubkeys.findIndex(
        key => key.toString() === alice.publicKey.toString(),
      )
      const bobIndex = result.keyAggContext.pubkeys.findIndex(
        key => key.toString() === bob.publicKey.toString(),
      )

      const alicePartial = signTaprootKeyPathWithMuSig2(
        aliceNonce,
        alice,
        result.keyAggContext,
        aliceIndex,
        aggNonce,
        message,
        result.tweak,
      )
      const bobPartial = signTaprootKeyPathWithMuSig2(
        bobNonce,
        bob,
        result.keyAggContext,
        bobIndex,
        aggNonce,
        message,
        result.tweak,
      )

      const finalSig = musigSigAgg(
        [alicePartial, bobPartial],
        aggNonce,
        message,
        result.commitment,
      )

      // Try to verify with untweaked aggregated key (WRONG!)
      const wrongKeyVerification = Schnorr.verify(
        message,
        finalSig,
        result.aggregatedPubKey, // Should use commitment!
        'big',
      )

      assert.ok(
        !wrongKeyVerification,
        'Should fail when verifying with untweaked key',
      )

      // Verify with correct commitment (RIGHT!)
      const correctVerification = Schnorr.verify(
        message,
        finalSig,
        result.commitment,
        'big',
      )

      assert.ok(
        correctVerification,
        'Should succeed when verifying with commitment',
      )

      console.log('✓ Taproot tweak validation working correctly!')
    })
  })

  describe('Script Tree Integration', () => {
    it('should create MuSig2 Taproot with script tree fallback', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      // Create timelock fallback: Alice can spend after 144 blocks
      const timelockScript = new Script()
        .add(144)
        .add(Opcode.OP_CHECKSEQUENCEVERIFY)
        .add(Opcode.OP_DROP)
        .add(alice.publicKey.toBuffer())
        .add(Opcode.OP_CHECKSIG)

      const tree = {
        type: 'leaf' as const,
        script: timelockScript,
      }

      const result = buildMuSigTaprootKeyWithScripts(
        [alice.publicKey, bob.publicKey],
        tree,
      )

      assert.ok(result.script.isPayToTaproot())
      assert.ok(result.leaves.length === 1)

      // Merkle root should include the script
      const allZeros = Buffer.alloc(32).every(b => b === 0)
      assert.ok(
        !result.merkleRoot.every(b => b === 0),
        'Merkle root should not be all zeros when script tree exists',
      )

      console.log('✓ MuSig2 with script tree fallback working!')
    })

    it('should sign with MuSig2 key path (script path unused)', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()

      // Create fallback script (won't be used)
      const fallbackScript = new Script()
        .add(alice.publicKey.toBuffer())
        .add(Opcode.OP_CHECKSIG)

      const tree = {
        type: 'leaf' as const,
        script: fallbackScript,
      }

      const result = buildMuSigTaprootKeyWithScripts(
        [alice.publicKey, bob.publicKey],
        tree,
      )

      const message = Buffer.alloc(32).fill(0x47)

      // Sign via key path (script path hidden!)
      const aliceNonce = musigNonceGen(alice, result.aggregatedPubKey, message)
      const bobNonce = musigNonceGen(bob, result.aggregatedPubKey, message)
      const aggNonce = musigNonceAgg([
        aliceNonce.publicNonces,
        bobNonce.publicNonces,
      ])

      // Find correct signer indices from the key aggregation context
      const aliceIndex = result.keyAggContext.pubkeys.findIndex(
        key => key.toString() === alice.publicKey.toString(),
      )
      const bobIndex = result.keyAggContext.pubkeys.findIndex(
        key => key.toString() === bob.publicKey.toString(),
      )

      const alicePartial = signTaprootKeyPathWithMuSig2(
        aliceNonce,
        alice,
        result.keyAggContext,
        aliceIndex,
        aggNonce,
        message,
        result.tweak,
      )
      const bobPartial = signTaprootKeyPathWithMuSig2(
        bobNonce,
        bob,
        result.keyAggContext,
        bobIndex,
        aggNonce,
        message,
        result.tweak,
      )

      const finalSig = musigSigAgg(
        [alicePartial, bobPartial],
        aggNonce,
        message,
        result.commitment,
      )

      const verified = Schnorr.verify(
        message,
        finalSig,
        result.commitment,
        'big',
      )

      assert.ok(verified, 'Key path spend should work even with script tree')
      console.log('✓ Key path spend hides script tree - privacy achieved!')
    })
  })

  describe('Privacy Properties', () => {
    it('MuSig2 Taproot output should look identical to regular Taproot', async () => {
      const singleKey = new PrivateKey()
      const multiKey1 = new PrivateKey()
      const multiKey2 = new PrivateKey()

      // Single-key Taproot
      const { buildKeyPathTaproot } = await import('../lib/bitcore/taproot.js')
      const singleKeyTaproot = buildKeyPathTaproot(singleKey.publicKey)

      // MuSig2 Taproot (2-of-2)
      const musig2Result = buildMuSigTaprootKey([
        multiKey1.publicKey,
        multiKey2.publicKey,
      ])
      const musig2Taproot = musig2Result.script

      // Both should be same size
      assert.strictEqual(
        singleKeyTaproot.toBuffer().length,
        musig2Taproot.toBuffer().length,
        'Scripts should be same size',
      )

      // Both should be Pay-To-Taproot
      assert.ok(singleKeyTaproot.isPayToTaproot())
      assert.ok(musig2Taproot.isPayToTaproot())

      console.log('✓ MuSig2 Taproot indistinguishable from single-key Taproot!')
    })
  })

  describe('Edge Cases', () => {
    it('should handle single signer MuSig2 Taproot', () => {
      const key = new PrivateKey()

      const result = buildMuSigTaprootKey([key.publicKey])
      const message = Buffer.alloc(32).fill(0x48)

      const nonce = musigNonceGen(key, result.aggregatedPubKey, message)
      const aggNonce = musigNonceAgg([nonce.publicNonces])

      const partialSig = signTaprootKeyPathWithMuSig2(
        nonce,
        key,
        result.keyAggContext,
        0,
        aggNonce,
        message,
        result.tweak,
      )

      const finalSig = musigSigAgg(
        [partialSig],
        aggNonce,
        message,
        result.commitment,
      )

      const verified = Schnorr.verify(
        message,
        finalSig,
        result.commitment,
        'big',
      )

      assert.ok(verified, 'Single signer MuSig2 Taproot should work')
    })

    it('should work with many signers (7-of-7)', () => {
      const keys = Array.from({ length: 7 }, () => new PrivateKey())

      const result = buildMuSigTaprootKey(keys.map(k => k.publicKey))
      const message = Buffer.alloc(32).fill(0x49)

      const nonces = keys.map(k =>
        musigNonceGen(k, result.aggregatedPubKey, message),
      )
      const aggNonce = musigNonceAgg(nonces.map(n => n.publicNonces))

      // Find correct signer indices from the key aggregation context
      const signerIndices = keys.map(k =>
        result.keyAggContext.pubkeys.findIndex(
          key => key.toString() === k.publicKey.toString(),
        ),
      )

      const partialSigs = keys.map((k, i) =>
        signTaprootKeyPathWithMuSig2(
          nonces[i],
          k,
          result.keyAggContext,
          signerIndices[i],
          aggNonce,
          message,
          result.tweak,
        ),
      )

      const finalSig = musigSigAgg(
        partialSigs,
        aggNonce,
        message,
        result.commitment,
      )

      const verified = Schnorr.verify(
        message,
        finalSig,
        result.commitment,
        'big',
      )

      assert.ok(verified, '7-of-7 MuSig2 Taproot should work')
      console.log('✓ 7-of-7 MuSig2 Taproot signature verified!')
    })
  })
})

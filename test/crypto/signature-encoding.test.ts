/**
 * Signature Encoding Unit Tests
 *
 * Tests for proper signature encoding in Script.buildPublicKeyIn and Script.buildPublicKeyHashIn
 * to ensure Schnorr (MuSig2) and ECDSA signatures are handled correctly
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import {
  PrivateKey,
  PublicKey,
  Transaction,
  Input,
  Output,
  Signature,
  Script,
  BN,
} from '../../lib/bitcore/index.js'

describe('Signature Encoding', () => {
  describe('Script.buildPublicKeyIn', () => {
    it('should encode Schnorr signatures correctly without double sighash', () => {
      // Create a Schnorr signature (used by MuSig2)
      const schnorrSignature = new Signature({
        r: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        s: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        compressed: true,
        isSchnorr: true,
        nhashtype: Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      })

      // Test buildPublicKeyIn
      const script1 = Script.buildPublicKeyIn(
        schnorrSignature,
        schnorrSignature.nhashtype!,
      )

      // Test direct script.add (expected behavior)
      const script2 = new Script()
      script2.add(schnorrSignature.toTxFormat('schnorr'))

      // Both should produce identical results
      assert.strictEqual(
        script1.toBuffer().length,
        script2.toBuffer().length,
        'Schnorr signature encoding should match direct script.add',
      )

      assert.ok(
        script1.toBuffer().equals(script2.toBuffer()),
        'Schnorr signature buffers should be identical',
      )

      // Verify correct length: 65-byte signature + 1-byte push opcode = 66 bytes
      assert.strictEqual(script1.toBuffer().length, 66)
    })

    it('should encode ECDSA signatures correctly with sighash concatenation', () => {
      // Create an ECDSA signature
      const ecdsaSignature = new Signature({
        r: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        s: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        compressed: true,
        isSchnorr: false, // ECDSA
        nhashtype: Signature.SIGHASH_ALL,
      })

      // Test buildPublicKeyIn
      const script1 = Script.buildPublicKeyIn(
        ecdsaSignature,
        ecdsaSignature.nhashtype!,
      )

      // Test expected behavior: signature + sighash concatenated
      const script2 = new Script()
      const ecdsaWithSighash = Buffer.concat([
        ecdsaSignature.toTxFormat('ecdsa'),
        Buffer.from([ecdsaSignature.nhashtype || 1]),
      ])
      script2.add(ecdsaWithSighash)

      // Both should produce identical results
      assert.strictEqual(
        script1.toBuffer().length,
        script2.toBuffer().length,
        'ECDSA signature encoding should match expected concatenation',
      )

      assert.ok(
        script1.toBuffer().equals(script2.toBuffer()),
        'ECDSA signature buffers should be identical',
      )

      // Verify correct length: 71-byte signature + 1-byte sighash + 1-byte push opcode = 73 bytes
      assert.strictEqual(script1.toBuffer().length, 73)
    })

    it('should handle Buffer signatures correctly', () => {
      // Test with raw Buffer signature (should concatenate with sighash)
      const rawSignature = Buffer.from(
        '1234567890123456789012345678901234567890123456789012345678901234',
        'hex',
      )
      const sigtype = Signature.SIGHASH_ALL

      const script = Script.buildPublicKeyIn(rawSignature, sigtype)

      // Should concatenate signature with sighash
      const expected = Buffer.concat([rawSignature, Buffer.from([sigtype])])

      // Remove push opcode for comparison
      const scriptData = script.toBuffer().slice(1)

      assert.ok(
        scriptData.equals(expected),
        'Buffer signature should be concatenated with sighash',
      )
    })
  })

  describe('Script.buildPublicKeyHashIn', () => {
    it('should encode Schnorr signatures correctly without double sighash', () => {
      const schnorrSignature = new Signature({
        r: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        s: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        compressed: true,
        isSchnorr: true,
        nhashtype: Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      })

      const publicKey = new PrivateKey().publicKey

      // Test buildPublicKeyHashIn
      const script1 = Script.buildPublicKeyHashIn(
        publicKey,
        schnorrSignature,
        schnorrSignature.nhashtype!,
      )

      // Test direct script.add (expected behavior)
      const script2 = new Script()
      script2.add(schnorrSignature.toTxFormat('schnorr'))
      script2.add(publicKey.toBuffer())

      // Both should produce identical results
      assert.strictEqual(
        script1.toBuffer().length,
        script2.toBuffer().length,
        'Schnorr signature encoding should match direct script.add',
      )

      assert.ok(
        script1.toBuffer().equals(script2.toBuffer()),
        'Schnorr signature buffers should be identical',
      )
    })

    it('should encode ECDSA signatures correctly with sighash concatenation', () => {
      const ecdsaSignature = new Signature({
        r: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        s: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        compressed: true,
        isSchnorr: false, // ECDSA
        nhashtype: Signature.SIGHASH_ALL,
      })

      const publicKey = new PrivateKey().publicKey

      // Test buildPublicKeyHashIn
      const script1 = Script.buildPublicKeyHashIn(
        publicKey,
        ecdsaSignature,
        ecdsaSignature.nhashtype!,
      )

      // Test expected behavior: signature + sighash concatenated
      const script2 = new Script()
      const ecdsaWithSighash = Buffer.concat([
        ecdsaSignature.toTxFormat('ecdsa'),
        Buffer.from([ecdsaSignature.nhashtype || 1]),
      ])
      script2.add(ecdsaWithSighash)
      script2.add(publicKey.toBuffer())

      // Both should produce identical results
      assert.strictEqual(
        script1.toBuffer().length,
        script2.toBuffer().length,
        'ECDSA signature encoding should match expected concatenation',
      )

      assert.ok(
        script1.toBuffer().equals(script2.toBuffer()),
        'ECDSA signature buffers should be identical',
      )
    })
  })

  describe('MuSig2 Integration', () => {
    it('should produce valid Taproot key-path signatures', () => {
      // Create MuSig2 signature (Schnorr with SIGHASH_ALL | SIGHASH_LOTUS)
      const musig2Signature = new Signature({
        r: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        s: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        compressed: true,
        isSchnorr: true,
        nhashtype: Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      })

      // Test Taproot input script creation
      const script = Script.buildPublicKeyIn(
        musig2Signature,
        musig2Signature.nhashtype!,
      )

      // Verify it's a valid Schnorr signature format
      assert.strictEqual(script.toBuffer().length, 66)

      // First byte should be push opcode for 65-byte data
      assert.strictEqual(script.toBuffer()[0], 0x41)

      // Last byte should be the sighash type (0x61 = SIGHASH_ALL | SIGHASH_LOTUS)
      assert.strictEqual(script.toBuffer()[script.toBuffer().length - 1], 0x61)

      // Total signature data should be 65 bytes (64-byte signature + 1-byte sighash)
      const signatureData = script.toBuffer().slice(1) // Remove push opcode
      assert.strictEqual(signatureData.length, 65)
    })
  })

  describe('Regression Tests', () => {
    it('should not double-encode Schnorr signature sighash', () => {
      // This test ensures the fix for the bitcore-updates regression
      const schnorrSignature = new Signature({
        r: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        s: new BN(
          '1234567890123456789012345678901234567890123456789012345678901234',
          'hex',
        ),
        compressed: true,
        isSchnorr: true,
        nhashtype: Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      })

      const script = Script.buildPublicKeyIn(
        schnorrSignature,
        schnorrSignature.nhashtype!,
      )

      // Before the fix, this would be 73 bytes (double-encoded)
      // After the fix, it should be 66 bytes
      assert.strictEqual(
        script.toBuffer().length,
        66,
        'Schnorr signature should not be double-encoded with sighash',
      )

      // Ensure only one sighash byte at the end
      const buffer = script.toBuffer()
      assert.strictEqual(
        buffer[buffer.length - 1],
        0x61,
        'Should have exactly one sighash byte',
      )
    })
  })
})

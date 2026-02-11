/**
 * Script.fromPayload() and Script.getPayload() Unit Tests
 *
 * Tests for round-trip conversion between Chronik script payloads
 * (data-only) and full Script instances.
 *
 * Reference: chronik-rocksdb/src/script_payload.rs
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'buffer/'
import { Script } from '../../lib/bitcore/script'
import { PublicKey } from '../../lib/bitcore/publickey'
import { Opcode } from '../../lib/bitcore/opcode'
import { PrivateKey } from '../../lib/bitcore/privatekey'
import type { ScriptType } from '../../lib/bitcore/script'

describe('Script.fromPayload', () => {
  // Generate a real compressed public key for testing
  const privKey = new PrivateKey()
  const pubKey = privKey.toPublicKey()
  const compressedPubKeyHex = pubKey.toString()
  const compressedPubKeyBuf = pubKey.toBuffer()

  describe('p2pk (compressed)', () => {
    it('should reconstruct P2PK script from 33-byte compressed pubkey payload', () => {
      const script = Script.fromPayload('p2pk', compressedPubKeyHex)

      assert.ok(script.isPublicKeyOut(), 'Should be detected as P2PK output')
      assert.strictEqual(script.chunks.length, 2)
      assert.strictEqual(script.chunks[0].buf!.length, 33)
      assert.strictEqual(script.chunks[1].opcodenum, Opcode.OP_CHECKSIG)
    })

    it('should accept Buffer input', () => {
      const script = Script.fromPayload('p2pk', compressedPubKeyBuf)

      assert.ok(script.isPublicKeyOut())
      assert.strictEqual(
        script.chunks[0].buf!.toString('hex'),
        compressedPubKeyHex,
      )
    })

    it('should reject invalid payload length', () => {
      assert.throws(
        () => Script.fromPayload('p2pk', '0011223344'),
        /Invalid p2pk payload length/,
      )
    })
  })

  describe('p2pkh', () => {
    const pubKeyHash = '89abcdefabbaabbaabbaabbaabbaabbaabbaabba'

    it('should reconstruct P2PKH script from 20-byte hash payload', () => {
      const script = Script.fromPayload('p2pkh', pubKeyHash)

      assert.ok(
        script.isPublicKeyHashOut(),
        'Should be detected as P2PKH output',
      )
      assert.strictEqual(script.chunks.length, 5)
      assert.strictEqual(script.chunks[0].opcodenum, Opcode.OP_DUP)
      assert.strictEqual(script.chunks[1].opcodenum, Opcode.OP_HASH160)
      assert.strictEqual(script.chunks[2].buf!.toString('hex'), pubKeyHash)
      assert.strictEqual(script.chunks[3].opcodenum, Opcode.OP_EQUALVERIFY)
      assert.strictEqual(script.chunks[4].opcodenum, Opcode.OP_CHECKSIG)
    })

    it('should accept Buffer input', () => {
      const buf = Buffer.from(pubKeyHash, 'hex')
      const script = Script.fromPayload('p2pkh', buf)

      assert.ok(script.isPublicKeyHashOut())
    })

    it('should reject invalid payload length', () => {
      assert.throws(
        () => Script.fromPayload('p2pkh', 'aabbccdd'),
        /Invalid p2pkh payload length: expected 20, got 4/,
      )
    })
  })

  describe('p2sh', () => {
    const scriptHash = 'abcdef0123456789abcdef0123456789abcdef01'

    it('should reconstruct P2SH script from 20-byte hash payload', () => {
      const script = Script.fromPayload('p2sh', scriptHash)

      assert.ok(script.isScriptHashOut(), 'Should be detected as P2SH output')
      assert.strictEqual(script.chunks.length, 3)
      assert.strictEqual(script.chunks[0].opcodenum, Opcode.OP_HASH160)
      assert.strictEqual(script.chunks[1].buf!.toString('hex'), scriptHash)
      assert.strictEqual(script.chunks[2].opcodenum, Opcode.OP_EQUAL)
    })

    it('should reject invalid payload length', () => {
      assert.throws(
        () => Script.fromPayload('p2sh', 'aabb'),
        /Invalid p2sh payload length: expected 20, got 2/,
      )
    })
  })

  describe('p2tr-commitment', () => {
    it('should reconstruct P2TR script from 33-byte commitment payload', () => {
      const script = Script.fromPayload('p2tr-commitment', compressedPubKeyHex)

      assert.ok(script.isTaprootOut(), 'Should be detected as P2TR output')
      assert.strictEqual(script.chunks.length, 3)
      assert.strictEqual(script.chunks[0].opcodenum, Opcode.OP_SCRIPTTYPE)
      assert.strictEqual(script.chunks[1].opcodenum, Opcode.OP_1)
      assert.strictEqual(
        script.chunks[2].buf!.toString('hex'),
        compressedPubKeyHex,
      )
      assert.strictEqual(script.chunks[2].buf!.length, 33)
    })

    it('should reject invalid payload length', () => {
      assert.throws(
        () =>
          Script.fromPayload(
            'p2tr-commitment',
            '89abcdefabbaabbaabbaabbaabbaabbaabbaabba',
          ),
        /Invalid p2tr-commitment payload length: expected 33, got 20/,
      )
    })
  })

  describe('p2tr-state', () => {
    it('should throw when attempting to reconstruct from state-only payload', () => {
      const stateHex =
        'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
      assert.throws(
        () => Script.fromPayload('p2tr-state', stateHex),
        /Cannot reconstruct full script from p2tr-state payload alone/,
      )
    })
  })

  describe('other', () => {
    it('should reconstruct script from raw bytecode', () => {
      // OP_RETURN followed by some data
      const opReturnScript = Script.buildDataOut('hello', 'utf8')
      const rawHex = opReturnScript.toHex()

      const reconstructed = Script.fromPayload('other', rawHex)

      assert.strictEqual(reconstructed.toHex(), rawHex)
      assert.ok(reconstructed.isDataOut())
    })
  })

  describe('unknown type', () => {
    it('should throw for unknown script type', () => {
      assert.throws(
        () =>
          Script.fromPayload(
            'p2wsh' as ScriptType,
            'abcdef0123456789abcdef0123456789abcdef01',
          ),
        /Unknown script type: p2wsh/,
      )
    })
  })
})

describe('Script.getPayload', () => {
  const privKey = new PrivateKey()
  const pubKey = privKey.toPublicKey()

  describe('P2PK', () => {
    it('should extract compressed pubkey payload from P2PK script', () => {
      const script = Script.buildPublicKeyOut(pubKey)
      const { type, payload, payloadHex } = script.getPayload()

      assert.strictEqual(type, 'p2pk')
      assert.strictEqual(payload.length, 33)
      assert.strictEqual(payloadHex, pubKey.toString())
    })
  })

  describe('P2PKH', () => {
    it('should extract 20-byte hash payload from P2PKH script', () => {
      const script = Script.buildPublicKeyHashOut(pubKey)
      const { type, payload } = script.getPayload()

      assert.strictEqual(type, 'p2pkh')
      assert.strictEqual(payload.length, 20)
    })
  })

  describe('P2SH', () => {
    it('should extract 20-byte hash payload from P2SH script', () => {
      const innerScript = Script.buildPublicKeyHashOut(pubKey)
      const p2shScript = Script.buildScriptHashOut(innerScript)
      const { type, payload } = p2shScript.getPayload()

      assert.strictEqual(type, 'p2sh')
      assert.strictEqual(payload.length, 20)
    })
  })

  describe('P2TR commitment (no state)', () => {
    it('should extract 33-byte commitment payload from P2TR script', () => {
      const script = Script.buildTaprootOut(pubKey.toBuffer())
      const { type, payload, payloadHex } = script.getPayload()

      assert.strictEqual(type, 'p2tr-commitment')
      assert.strictEqual(payload.length, 33)
      assert.strictEqual(payloadHex, pubKey.toString())
    })
  })

  describe('P2TR with state', () => {
    it('should extract commitment payload and report p2tr-state type', () => {
      const state = Buffer.alloc(32, 0xab)
      const script = Script.buildTaprootOut(pubKey.toBuffer(), state)
      const { type, payload } = script.getPayload()

      assert.strictEqual(type, 'p2tr-state')
      assert.strictEqual(payload.length, 33)
      // Payload is the commitment, not the state
      assert.strictEqual(payload.toString('hex'), pubKey.toString())
    })
  })

  describe('other (non-standard)', () => {
    it('should return full bytecode for OP_RETURN scripts', () => {
      const script = Script.buildDataOut('test data', 'utf8')
      const { type, payloadHex } = script.getPayload()

      assert.strictEqual(type, 'other')
      assert.strictEqual(payloadHex, script.toHex())
    })
  })
})

describe('fromPayload / getPayload round-trip', () => {
  const privKey = new PrivateKey()
  const pubKey = privKey.toPublicKey()

  it('P2PK round-trip', () => {
    const original = Script.buildPublicKeyOut(pubKey)
    const { type, payloadHex } = original.getPayload()
    const reconstructed = Script.fromPayload(type, payloadHex)

    assert.strictEqual(reconstructed.toHex(), original.toHex())
  })

  it('P2PKH round-trip', () => {
    const original = Script.buildPublicKeyHashOut(pubKey)
    const { type, payloadHex } = original.getPayload()
    const reconstructed = Script.fromPayload(type, payloadHex)

    assert.strictEqual(reconstructed.toHex(), original.toHex())
  })

  it('P2SH round-trip', () => {
    const innerScript = Script.buildPublicKeyHashOut(pubKey)
    const original = Script.buildScriptHashOut(innerScript)
    const { type, payloadHex } = original.getPayload()
    const reconstructed = Script.fromPayload(type, payloadHex)

    assert.strictEqual(reconstructed.toHex(), original.toHex())
  })

  it('P2TR commitment round-trip', () => {
    const original = Script.buildTaprootOut(pubKey.toBuffer())
    const { payloadHex } = original.getPayload()
    // Use p2tr-commitment explicitly (getPayload returns p2tr-commitment for no-state)
    const reconstructed = Script.fromPayload('p2tr-commitment', payloadHex)

    assert.strictEqual(reconstructed.toHex(), original.toHex())
  })

  it('other (OP_RETURN) round-trip', () => {
    const original = Script.buildDataOut('round trip test', 'utf8')
    const { type, payloadHex } = original.getPayload()
    const reconstructed = Script.fromPayload(type, payloadHex)

    assert.strictEqual(reconstructed.toHex(), original.toHex())
  })
})

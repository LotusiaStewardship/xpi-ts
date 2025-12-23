import { describe, it } from 'node:test'
import assert from 'node:assert'
import { HDPrivateKey } from '../lib/bitcore/hdprivatekey.js'
import { Base58Check } from '../lib/bitcore/encoding/base58check.js'
import { Networks } from '../lib/bitcore/networks.js'

describe('HDPrivateKey', () => {
  // Test vector from BIP32 specification
  const testXprivkey =
    'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'

  describe('fromBuffer roundtrip', () => {
    it('should correctly deserialize and serialize an extended private key', () => {
      // Create HDPrivateKey from xprivkey string
      const original = new HDPrivateKey(testXprivkey)

      // Convert to buffer
      const buffer = original.toBuffer()

      // Verify buffer length is correct (78 bytes for raw extended key)
      assert.strictEqual(buffer.length, 78)

      // Verify byte 45 is 0x00 (reserved padding byte)
      assert.strictEqual(buffer[45], 0x00)

      // Deserialize from buffer using constructor with buffer
      const restored = new HDPrivateKey(buffer)

      // Verify the restored key matches the original
      assert.strictEqual(restored.xprivkey, original.xprivkey)
      assert.strictEqual(
        restored.privateKey.toString(),
        original.privateKey.toString(),
      )
      assert.strictEqual(
        restored.chainCode.toString('hex'),
        original.chainCode.toString('hex'),
      )
      assert.strictEqual(restored.depth, original.depth)
      assert.strictEqual(restored.childIndex, original.childIndex)
      assert.strictEqual(
        restored.parentFingerPrint.toString('hex'),
        original.parentFingerPrint.toString('hex'),
      )
    })

    it('should handle multiple roundtrips correctly', () => {
      const original = new HDPrivateKey(testXprivkey)

      // First roundtrip
      const buffer1 = original.toBuffer()
      const restored1 = new HDPrivateKey(buffer1)

      // Second roundtrip
      const buffer2 = restored1.toBuffer()
      const restored2 = new HDPrivateKey(buffer2)

      // All should be equal
      assert.strictEqual(restored1.xprivkey, original.xprivkey)
      assert.strictEqual(restored2.xprivkey, original.xprivkey)
      assert.strictEqual(buffer1.toString('hex'), buffer2.toString('hex'))
    })

    it('should correctly parse buffer structure according to BIP32', () => {
      const original = new HDPrivateKey(testXprivkey)
      const buffer = original.toBuffer()

      // Verify buffer structure (78 bytes total)
      // Bytes 0-3: version (4 bytes)
      const version = buffer.readUInt32BE(0)
      assert.strictEqual(version, original.network.xprivkey)

      // Byte 4: depth (1 byte)
      const depth = buffer.readUInt8(4)
      assert.strictEqual(depth, original.depth)

      // Bytes 5-8: parent fingerprint (4 bytes)
      const parentFP = buffer.subarray(5, 9)
      assert.strictEqual(
        parentFP.toString('hex'),
        original.parentFingerPrint.toString('hex'),
      )

      // Bytes 9-12: child index (4 bytes)
      const childIndex = buffer.readUInt32BE(9)
      assert.strictEqual(childIndex, original.childIndex)

      // Bytes 13-44: chain code (32 bytes)
      const chainCode = buffer.subarray(13, 45)
      assert.strictEqual(
        chainCode.toString('hex'),
        original.chainCode.toString('hex'),
      )

      // Byte 45: reserved padding (must be 0x00)
      assert.strictEqual(buffer[45], 0x00)

      // Bytes 46-77: private key (32 bytes)
      const privKeyBuffer = buffer.subarray(46, 78)
      assert.strictEqual(
        privKeyBuffer.toString('hex'),
        original.privateKey.toBuffer().toString('hex'),
      )
    })

    it('should correctly handle derived keys', () => {
      const parent = new HDPrivateKey(testXprivkey)

      // Derive a child key
      const child = parent.derive(0)

      // Convert to buffer and back
      const childBuffer = child.toBuffer()
      const restoredChild = new HDPrivateKey(childBuffer)

      // Verify the restored child matches
      assert.strictEqual(restoredChild.xprivkey, child.xprivkey)
      assert.strictEqual(restoredChild.depth, child.depth)
      assert.strictEqual(restoredChild.childIndex, child.childIndex)
      assert.strictEqual(
        restoredChild.privateKey.toString(),
        child.privateKey.toString(),
      )
    })

    it('should correctly initialize PrivateKey with proper compression state', () => {
      const hdkey = new HDPrivateKey(testXprivkey)

      // The private key should be properly initialized
      assert.ok(hdkey.privateKey)
      assert.ok(hdkey.privateKey.bn)
      assert.strictEqual(hdkey.privateKey.compressed, true)

      // Roundtrip should preserve compression state
      const buffer = hdkey.toBuffer()
      const restored = new HDPrivateKey(buffer)

      assert.strictEqual(restored.privateKey.compressed, true)
      assert.strictEqual(
        restored.privateKey.toString(),
        hdkey.privateKey.toString(),
      )
    })

    it('should match bitcore-lib-xpi behavior for buffer parsing', () => {
      // Create from xprivkey string
      const hdkey1 = new HDPrivateKey(testXprivkey)

      // Create from buffer (using constructor)
      const buffer = Base58Check.decode(testXprivkey)
      const hdkey2 = new HDPrivateKey(buffer)

      // Both should produce identical results
      assert.strictEqual(hdkey2.xprivkey, hdkey1.xprivkey)
      assert.strictEqual(
        hdkey2.privateKey.toString(),
        hdkey1.privateKey.toString(),
      )
      assert.strictEqual(
        hdkey2.chainCode.toString('hex'),
        hdkey1.chainCode.toString('hex'),
      )
      assert.strictEqual(hdkey2.depth, hdkey1.depth)
      assert.strictEqual(hdkey2.childIndex, hdkey1.childIndex)
      assert.strictEqual(
        hdkey2.parentFingerPrint.toString('hex'),
        hdkey1.parentFingerPrint.toString('hex'),
      )
    })
  })

  describe('buffer structure validation', () => {
    it('should reject buffers with incorrect length', () => {
      const shortBuffer = Buffer.alloc(77)
      assert.throws(() => new HDPrivateKey(shortBuffer))

      const longBuffer = Buffer.alloc(79)
      assert.throws(() => new HDPrivateKey(longBuffer))
    })

    it('should correctly identify network from version bytes', () => {
      const hdkey = new HDPrivateKey(testXprivkey)
      const buffer = hdkey.toBuffer()

      const restored = new HDPrivateKey(buffer)
      assert.strictEqual(restored.network.name, hdkey.network.name)
    })
  })

  describe('compatibility with derived keys', () => {
    it('should correctly roundtrip hardened derived keys', () => {
      const parent = new HDPrivateKey(testXprivkey)
      const hardened = parent.derive(0, true)

      const buffer = hardened.toBuffer()
      const restored = new HDPrivateKey(buffer)

      assert.strictEqual(restored.xprivkey, hardened.xprivkey)
      assert.strictEqual(restored.depth, 1)
      assert.ok(restored.childIndex >= 0x80000000)
    })

    it('should correctly roundtrip non-hardened derived keys', () => {
      const parent = new HDPrivateKey(testXprivkey)
      const nonHardened = parent.derive(0, false)

      const buffer = nonHardened.toBuffer()
      const restored = new HDPrivateKey(buffer)

      assert.strictEqual(restored.xprivkey, nonHardened.xprivkey)
      assert.strictEqual(restored.depth, 1)
      assert.ok(restored.childIndex < 0x80000000)
    })
  })

  describe('network propagation', () => {
    it('should create random key with default network (livenet)', () => {
      const hdkey = new HDPrivateKey()
      assert.strictEqual(hdkey.network.name, 'livenet')
      assert.strictEqual(hdkey.privateKey.network.name, 'livenet')
    })

    it('should create random key with specified network via constructor', () => {
      const hdkey = new HDPrivateKey('testnet')
      assert.strictEqual(hdkey.network.name, 'testnet')
      assert.strictEqual(hdkey.privateKey.network.name, 'testnet')
    })

    it('should create random key with specified network via fromRandom', () => {
      const hdkey = HDPrivateKey.fromRandom('testnet')
      assert.strictEqual(hdkey.network.name, 'testnet')
      assert.strictEqual(hdkey.privateKey.network.name, 'testnet')
    })

    it('should create key from seed with specified network', () => {
      const seed = Buffer.alloc(64, 0x42)
      const hdkey = HDPrivateKey.fromSeed(seed, 'testnet')
      assert.strictEqual(hdkey.network.name, 'testnet')
      assert.strictEqual(hdkey.privateKey.network.name, 'testnet')
    })

    it('should create key from seed with default network when not specified', () => {
      const seed = Buffer.alloc(64, 0x42)
      const hdkey = HDPrivateKey.fromSeed(seed)
      assert.strictEqual(hdkey.network.name, 'livenet')
      assert.strictEqual(hdkey.privateKey.network.name, 'livenet')
    })

    it('should propagate network through derivation', () => {
      const hdkey = HDPrivateKey.fromRandom('testnet')
      const derived = hdkey.derive("m/44'/0'/0'/0/0")
      assert.strictEqual(derived.network.name, 'testnet')
      assert.strictEqual(derived.privateKey.network.name, 'testnet')
    })

    it('should accept Network object in constructor', () => {
      const hdkey = new HDPrivateKey(Networks.testnet)
      assert.strictEqual(hdkey.network.name, 'testnet')
      assert.strictEqual(hdkey.privateKey.network.name, 'testnet')
    })

    it('should accept Network object in fromSeed', () => {
      const seed = Buffer.alloc(64, 0x42)
      const hdkey = HDPrivateKey.fromSeed(seed, Networks.regtest)
      assert.strictEqual(hdkey.network.name, 'regtest')
      assert.strictEqual(hdkey.privateKey.network.name, 'regtest')
    })

    it('should propagate network to HDPublicKey', () => {
      const hdkey = HDPrivateKey.fromRandom('testnet')
      const hdpubkey = hdkey.hdPublicKey
      assert.strictEqual(hdpubkey.network.name, 'testnet')
    })

    it('should propagate network to HDPublicKey through derivation', () => {
      const hdkey = HDPrivateKey.fromRandom('testnet')
      const derived = hdkey.derive("m/44'/0'/0'/0/0")
      const hdpubkey = derived.hdPublicKey
      assert.strictEqual(hdpubkey.network.name, 'testnet')
    })

    it('should use correct xpubkey version for testnet HDPublicKey', () => {
      const hdkey = HDPrivateKey.fromRandom('testnet')
      const hdpubkey = hdkey.hdPublicKey

      // Testnet xpubkey version is 0x043587cf (tpub prefix)
      const xpubkeyStr = hdpubkey.xpubkey.toString()
      assert.ok(
        xpubkeyStr.startsWith('tpub'),
        `Expected testnet xpubkey to start with 'tpub', got: ${xpubkeyStr.substring(0, 10)}`,
      )
    })

    it('should use correct xpubkey version for livenet HDPublicKey', () => {
      const hdkey = HDPrivateKey.fromRandom('livenet')
      const hdpubkey = hdkey.hdPublicKey

      // Livenet xpubkey version is 0x0488b21e (xpub prefix)
      const xpubkeyStr = hdpubkey.xpubkey.toString()
      assert.ok(
        xpubkeyStr.startsWith('xpub'),
        `Expected livenet xpubkey to start with 'xpub', got: ${xpubkeyStr.substring(0, 10)}`,
      )
    })
  })
})

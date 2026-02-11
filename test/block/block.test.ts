/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * Block and BlockHeader test suite
 * Following xpi-ts testing conventions and Node.js test runner
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'buffer/'
import { Block } from '../../lib/bitcore/block/block.js'
import { BlockHeader } from '../../lib/bitcore/block/blockheader.js'
import { BN } from '../../lib/bitcore/crypto/bn.js'

// Raw block and header data from lotus-cli at height 1000000
const rawBlockHex =
  '7c09a10a2295261f596e4624d431e29fc063f67b8db8295cbef9610000000000fa03011c7498ec670000000002636ee60fe32d00012f01000000000040420f00c610162b6a8e2ff88f1d2115a4b40c3c765d61c6cf57d6f1bd92990000000000fa0fd143da139d2774d37b62e9cdf119f8efa9836c37c4c9005e55d82e805a251406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a000102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff020000ffffffff0300000000000000000b6a056c6f676f730340420fe5199226000000001976a914957cc58bc320240f96be219faa27bab92fa8976588ace5199226000000001976a914d7756030f4292b70cb70dc4df231b14109c6806188ac00000000'
const rawHeaderHex =
  '7c09a10a2295261f596e4624d431e29fc063f67b8db8295cbef9610000000000fa03011c7498ec670000000002636ee60fe32d00012f01000000000040420f00c610162b6a8e2ff88f1d2115a4b40c3c765d61c6cf57d6f1bd92990000000000fa0fd143da139d2774d37b62e9cdf119f8efa9836c37c4c9005e55d82e805a251406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a'
const expectedHash =
  '0000000000a7d7abc07f34248db967957f8800d44085b8e2edc7e9f4f053ab0f'

describe('Block', () => {
  describe('constructor', () => {
    it('should create empty block with no arguments', () => {
      const block = new Block()
      assert.ok(block.header)
      assert.deepStrictEqual(block.transactions, [])
    })

    it('should create block from hex string', () => {
      const block = new Block(rawBlockHex)
      assert.strictEqual(block.header.height, 1000000)
      assert.strictEqual(block.transactions.length, 1)
    })

    it('should create block from Buffer', () => {
      const block = new Block(Buffer.from(rawBlockHex, 'hex'))
      assert.strictEqual(block.header.height, 1000000)
    })
  })

  describe('static factory methods', () => {
    it('fromBuffer should parse raw block', () => {
      const blockBuf = Buffer.from(rawBlockHex, 'hex')
      const block = Block.fromBuffer(blockBuf)
      assert.strictEqual(block.hash, expectedHash)
      assert.strictEqual(block.header.height, 1000000)
      assert.strictEqual(block.transactions.length, 1)
    })

    it('fromString should parse hex string', () => {
      const block = Block.fromString(rawBlockHex)
      assert.strictEqual(block.header.height, 1000000)
    })

    it('fromRawBlock should parse raw block data', () => {
      const block = Block.fromRawBlock(Buffer.from(rawBlockHex, 'hex'))
      assert.strictEqual(block.header.height, 1000000)
    })
  })

  describe('serialization', () => {
    it('should serialize and deserialize correctly', () => {
      const original = Block.fromBuffer(Buffer.from(rawBlockHex, 'hex'))
      const serialized = original.toBuffer()
      const deserialized = Block.fromBuffer(serialized)
      assert.strictEqual(deserialized.hash, original.hash)
    })

    it('toObject should return correct structure', () => {
      const block = Block.fromBuffer(Buffer.from(rawBlockHex, 'hex'))
      const obj = block.toObject()
      assert.strictEqual(obj.hash, expectedHash)
      assert.ok(obj.header)
      assert.ok(Array.isArray(obj.transactions))
    })
  })

  describe('merkle operations', () => {
    it('should validate merkle root for block 1000000', () => {
      const block = Block.fromBuffer(Buffer.from(rawBlockHex, 'hex'))
      assert.strictEqual(block.validMerkleRoot(), true)
    })

    it('should calculate merkle root', () => {
      const block = Block.fromBuffer(Buffer.from(rawBlockHex, 'hex'))
      const root = block.getMerkleRoot()
      assert.ok(Buffer.isBuffer(root))
      assert.strictEqual(root.length, 32)
    })
  })

  describe('constants', () => {
    it('should have MAX_BLOCK_SIZE set to 32MB', () => {
      assert.strictEqual(Block.MAX_BLOCK_SIZE, 32 * 1024 * 1024)
    })

    it('should have NULL_HASH', () => {
      assert.ok(Buffer.isBuffer(Block.NULL_HASH))
      assert.strictEqual(Block.NULL_HASH.length, 32)
    })
  })
})

describe('BlockHeader', () => {
  describe('constructor', () => {
    it('should create empty header with no arguments', () => {
      const header = new BlockHeader()
      assert.strictEqual(header.height, 0)
      assert.strictEqual(header.bits, 0)
    })

    it('should create header from hex string', () => {
      const header = BlockHeader.fromString(rawHeaderHex)
      assert.strictEqual(header.height, 1000000)
      assert.strictEqual(header.bits, 469828602)
    })

    it('should create header from Buffer', () => {
      const header = BlockHeader.fromBuffer(Buffer.from(rawHeaderHex, 'hex'))
      assert.strictEqual(header.height, 1000000)
    })
  })

  describe('static factory methods', () => {
    it('fromBuffer should parse raw header', () => {
      const header = BlockHeader.fromBuffer(Buffer.from(rawHeaderHex, 'hex'))
      assert.strictEqual(header.hash, expectedHash)
      assert.strictEqual(header.height, 1000000)
    })

    it('fromString should parse hex string', () => {
      const header = BlockHeader.fromString(rawHeaderHex)
      assert.strictEqual(header.height, 1000000)
    })
  })

  describe('serialization', () => {
    it('should serialize to 160 bytes', () => {
      const header = BlockHeader.fromBuffer(Buffer.from(rawHeaderHex, 'hex'))
      const buf = header.toBuffer()
      assert.strictEqual(buf.length, 160)
    })

    it('should serialize and deserialize correctly', () => {
      const original = BlockHeader.fromBuffer(Buffer.from(rawHeaderHex, 'hex'))
      const serialized = original.toBuffer()
      const deserialized = BlockHeader.fromBuffer(serialized)
      assert.strictEqual(deserialized.hash, original.hash)
    })
  })

  describe('difficulty', () => {
    it('should calculate target difficulty', () => {
      const header = BlockHeader.fromBuffer(Buffer.from(rawHeaderHex, 'hex'))
      const target = header.getTargetDifficulty()
      assert.ok(target instanceof BN)
      assert.ok(target.gt(new BN(0)))
    })

    it('should calculate difficulty', () => {
      const header = BlockHeader.fromBuffer(Buffer.from(rawHeaderHex, 'hex'))
      const difficulty = header.getDifficulty()
      assert.strictEqual(typeof difficulty, 'number')
      assert.ok(difficulty > 0)
    })
  })

  describe('validation', () => {
    it('should validate proof of work for block 1000000', () => {
      const header = BlockHeader.fromBuffer(Buffer.from(rawHeaderHex, 'hex'))
      assert.strictEqual(header.validProofOfWork(), true)
    })

    it('should validate timestamp', () => {
      const header = BlockHeader.fromBuffer(Buffer.from(rawHeaderHex, 'hex'))
      assert.strictEqual(header.validTimestamp(), true)
    })

    it('should reject future timestamp', () => {
      const futureTime = Math.floor(Date.now() / 1000) + 3 * 60 * 60
      const header = new BlockHeader({
        prevHash: Buffer.alloc(32),
        bits: 0x1d00ffff,
        time: futureTime,
        nonce: new BN(0),
        version: 1,
        size: new BN(0),
        height: 1,
        epochBlock: Buffer.alloc(32),
        merkleRoot: Buffer.alloc(32),
        extendedMetadata: Buffer.alloc(32),
      })
      assert.strictEqual(header.validTimestamp(), false)
    })
  })

  describe('properties', () => {
    const header = BlockHeader.fromBuffer(Buffer.from(rawHeaderHex, 'hex'))

    it('should have correct id/hash', () => {
      assert.strictEqual(header.id, expectedHash)
      assert.strictEqual(header.hash, expectedHash)
    })

    it('should have correct height', () => {
      assert.strictEqual(header.height, 1000000)
    })

    it('should have correct bits', () => {
      assert.strictEqual(header.bits, 469828602)
    })

    it('should have correct version', () => {
      assert.strictEqual(header.version, 1)
    })

    it('should have correct prevHash', () => {
      assert.ok(Buffer.isBuffer(header.prevHash))
      assert.strictEqual(header.prevHash.length, 32)
    })

    it('should have correct merkleRoot', () => {
      assert.ok(Buffer.isBuffer(header.merkleRoot))
      assert.strictEqual(header.merkleRoot.length, 32)
    })

    it('should have nonce as BN', () => {
      assert.ok(header.nonce instanceof BN)
    })

    it('should have size as BN', () => {
      assert.ok(header.size instanceof BN)
    })
  })

  describe('constants', () => {
    it('should have START_OF_HEADER', () => {
      assert.strictEqual(BlockHeader.START_OF_HEADER, 0)
    })

    it('should have MAX_TIME_OFFSET', () => {
      assert.strictEqual(BlockHeader.MAX_TIME_OFFSET, 2 * 60 * 60)
    })
  })
})

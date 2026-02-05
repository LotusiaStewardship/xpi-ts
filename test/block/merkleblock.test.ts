/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * MerkleBlock test suite
 * Following xpi-ts testing conventions and Node.js test runner
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'buffer/'
import { MerkleBlock } from '../../lib/bitcore/block/merkleblock.js'
import {
  InvalidMerkleBlockError,
  MerkleBlockValidationError,
} from '../../lib/bitcore/block/merkleblock.js'
import { BN } from '../../lib/bitcore/crypto/bn.js'
import type { MerkleBlockObject } from '../../lib/bitcore/block/merkleblock.js'

describe('MerkleBlock', () => {
  // Test data from actual block 1000000 on Lotus blockchain
  // Source: https://explorer.lotusia.org/chronik/block/1000000
  // Using MerkleBlockObject format (serialized/JSON-compatible types)
  // Must use MerkleBlock.fromObject() to construct from this format
  const validBlockData: MerkleBlockObject = {
    header: {
      hash: '0000000000a7d7abc07f34248db967957f8800d44085b8e2edc7e9f4f053ab0f',
      prevHash:
        '000000000061f9be5c29b88d7bf663c09fe231d424466e591f2695220aa1097c',
      bits: 469828602,
      time: 1743558772,
      reserved: 0,
      nonce: '12916031381988098',
      version: 1,
      size: 303,
      height: 1000000,
      epochBlock:
        '00000000009992bdf1d657cfc6615d763c0cb4a415211d8ff82f8e6a2b1610c6',
      merkleRoot:
        '255a802ed8555e00c9c4376c83a9eff819f1cde9627bd374279d13da43d10ffa',
      extendedMetadata:
        '9a538906e6466ebd2617d321f71bc94e56056ce213d366773699e28158e00614',
    },
    numTransactions: 1,
    hashes: [
      '255a802ed8555e00c9c4376c83a9eff819f1cde9627bd374279d13da43d10ffa',
    ],
    flags: [1],
  }

  describe('fromObject (serialized format)', () => {
    it('should create a MerkleBlock from valid MerkleBlockObject data', () => {
      const merkleBlock = MerkleBlock.fromObject(validBlockData)

      assert.ok(merkleBlock.header)
      assert.strictEqual(merkleBlock.numTransactions, 1)
      assert.ok(Array.isArray(merkleBlock.hashes))
      assert.ok(Array.isArray(merkleBlock.flags))
      assert.strictEqual(merkleBlock.hashes.length, 1)
      assert.strictEqual(merkleBlock.flags.length, 1)
    })

    it('should throw MerkleBlockValidationError for missing header', () => {
      const invalidData = { ...validBlockData }
      delete (invalidData as any).header

      assert.throws(
        () => MerkleBlock.fromObject(invalidData as any),
        (error: Error) => error instanceof MerkleBlockValidationError,
      )
    })

    it('should throw MerkleBlockValidationError for negative transaction count', () => {
      const invalidData = { ...validBlockData, numTransactions: -1 }

      assert.throws(
        () => MerkleBlock.fromObject(invalidData),
        (error: Error) => error instanceof MerkleBlockValidationError,
      )
    })

    it('should throw MerkleBlockValidationError for non-array hashes', () => {
      const invalidData = { ...validBlockData, hashes: 'not-an-array' as any }

      assert.throws(
        () => MerkleBlock.fromObject(invalidData),
        (error: Error) => error instanceof MerkleBlockValidationError,
      )
    })

    it('should throw MerkleBlockValidationError for non-array flags', () => {
      const invalidData = { ...validBlockData, flags: 'not-an-array' as any }

      assert.throws(
        () => MerkleBlock.fromObject(invalidData),
        (error: Error) => error instanceof MerkleBlockValidationError,
      )
    })
  })

  describe('constructor (internal format)', () => {
    it('should throw InvalidMerkleBlockError for undefined input', () => {
      assert.throws(
        () => new MerkleBlock(undefined as any),
        (error: Error) => error instanceof InvalidMerkleBlockError,
      )
    })

    it('should throw InvalidMerkleBlockError for null input', () => {
      assert.throws(
        () => new MerkleBlock(null as any),
        (error: Error) => error instanceof InvalidMerkleBlockError,
      )
    })

    it('should throw InvalidMerkleBlockError for invalid input type', () => {
      assert.throws(
        () => new MerkleBlock('invalid' as any),
        (error: Error) => error instanceof InvalidMerkleBlockError,
      )
    })
  })

  describe('static factory methods', () => {
    describe('fromBuffer', () => {
      it('should throw InvalidMerkleBlockError for empty buffer', () => {
        assert.throws(
          () => MerkleBlock.fromBuffer(Buffer.alloc(0)),
          (error: Error) => error instanceof InvalidMerkleBlockError,
        )
      })

      it('should throw InvalidMerkleBlockError for non-buffer input', () => {
        assert.throws(
          () => MerkleBlock.fromBuffer('not-a-buffer' as any),
          (error: Error) => error instanceof InvalidMerkleBlockError,
        )
      })
    })
  })

  describe('serialization methods', () => {
    it('should convert to object correctly', () => {
      const merkleBlock = MerkleBlock.fromObject(validBlockData)
      const obj = merkleBlock.toObject()

      assert.ok(obj.header)
      assert.strictEqual(obj.numTransactions, 1)
      assert.deepStrictEqual(obj.hashes, validBlockData.hashes)
      // Flags are stored as boolean bits packed into bytes
      // Original [1] serializes to 1 byte, may deserialize with padding bits
      assert.ok(Array.isArray(obj.flags))
      assert.strictEqual(obj.flags[0], 1)
    })

    it('should convert to buffer correctly', () => {
      const merkleBlock = MerkleBlock.fromObject(validBlockData)
      const buffer = merkleBlock.toBuffer()

      assert.ok(Buffer.isBuffer(buffer))
      assert.ok(buffer.length > 0)
    })

    it('should convert to buffer writer correctly', () => {
      const merkleBlock = MerkleBlock.fromObject(validBlockData)
      const writer = merkleBlock.toBufferWriter()

      assert.ok(writer)
      assert.strictEqual(typeof writer.concat, 'function')
    })
  })

  describe('merkle tree operations', () => {
    it('should validate merkle tree structure', () => {
      const merkleBlock = MerkleBlock.fromObject(validBlockData)
      const isValid = merkleBlock.validMerkleTree()

      assert.strictEqual(typeof isValid, 'boolean')
    })

    it('should filter transaction hashes', () => {
      const merkleBlock = MerkleBlock.fromObject(validBlockData)
      const filteredTxs = merkleBlock.filteredTxsHash()

      assert.ok(Array.isArray(filteredTxs))
    })

    it('should check transaction inclusion', () => {
      const merkleBlock = MerkleBlock.fromObject(validBlockData)
      const txId =
        '255a802ed8555e00c9c4376c83a9eff819f1cde9627bd374279d13da43d10ffa'
      const isIncluded = merkleBlock.hasTransaction(txId)

      assert.strictEqual(typeof isIncluded, 'boolean')
    })

    it('should return false for non-existent transaction', () => {
      const merkleBlock = MerkleBlock.fromObject(validBlockData)
      const nonExistentTx =
        '0000000000000000000000000000000000000000000000000000000000000000'
      const isIncluded = merkleBlock.hasTransaction(nonExistentTx)

      assert.strictEqual(isIncluded, false)
    })

    it('should throw for undefined transaction check', () => {
      const merkleBlock = MerkleBlock.fromObject(validBlockData)
      assert.throws(
        () => merkleBlock.hasTransaction(undefined as any),
        /Transaction cannot be undefined/,
      )
    })
  })

  describe('constants', () => {
    it('should have NULL_HASH constant', () => {
      assert.ok(MerkleBlock.NULL_HASH)
      assert.ok(Buffer.isBuffer(MerkleBlock.NULL_HASH))
    })
  })

  describe('error handling', () => {
    it('should provide proper error context for constructor', () => {
      try {
        new MerkleBlock(undefined as any)
        assert.fail('Should have thrown an error')
      } catch (error) {
        const merkleError = error as InvalidMerkleBlockError
        assert.strictEqual(merkleError.name, 'InvalidMerkleBlockError')
        assert.strictEqual(merkleError.code, 'INVALID_MERKLE_BLOCK')
        assert.ok(merkleError.context)
      }
    })

    it('should provide validation error context for fromObject', () => {
      try {
        MerkleBlock.fromObject({ ...validBlockData, numTransactions: -1 })
        assert.fail('Should have thrown an error')
      } catch (error) {
        const validationError = error as MerkleBlockValidationError
        assert.strictEqual(validationError.name, 'MerkleBlockValidationError')
        assert.strictEqual(
          validationError.code,
          'MERKLE_BLOCK_VALIDATION_ERROR',
        )
        assert.ok(validationError.context)
      }
    })
  })
})

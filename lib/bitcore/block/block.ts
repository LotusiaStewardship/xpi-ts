/**
 * Block implementation for the Lotus blockchain
 *
 * Represents a complete Lotus block (CBlock in lotusd) containing a header,
 * extended metadata fields, and transactions.
 *
 * Serialization order:
 *   CBlockHeader(160 bytes) + varint(metadata count) + metadata fields +
 *   varint(tx count) + transactions
 *
 * Lotus merkle tree construction:
 *   Each transaction contributes two leaves: txhash (SHA256d of serialized tx)
 *   and txid (merkle-based identifier). These are combined per-transaction as
 *   SHA256d(txhash || txid) before building the merkle tree.
 *
 * @see lotusd: src/primitives/block.h, src/primitives/block.cpp
 */

import { Buffer } from 'buffer/'
import { Preconditions as $ } from '../util/preconditions.js'
import { BufferUtil, NULL_HASH } from '../util/buffer.js'
import { BufferReader } from '../encoding/bufferreader.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { Hash } from '../crypto/hash.js'
import { JSUtil } from '../util/js.js'
import { Transaction } from '../transaction/index.js'
import { BN } from '../crypto/bn.js'
import { calcTreeHeight, traverseAndBuild } from '../util/merkle.js'
import {
  BlockHeader,
  type BlockHeaderData,
  type BlockHeaderObject,
} from './blockheader.js'
import { MerkleBlock } from './merkleblock.js'

/**
 * Block data interface for construction (internal format).
 * Used when creating a Block from deserialized data or objects.
 */
export interface BlockData {
  /** Block header (BlockHeader instance or BlockHeaderData) */
  header?: BlockHeader | BlockHeaderData
  /** Array of transactions in this block */
  transactions?: Transaction[]
}

/**
 * Block object interface for serialization/JSON.
 * All values converted to serializable formats.
 */
export interface BlockObject {
  /** Block hash (big-endian hex) */
  id: string
  /** Block hash (big-endian hex, alias for id) */
  hash: string
  /** Serialized block header object */
  header: BlockHeaderObject
  /** Array of serialized transaction objects */
  transactions: unknown[]
}

/**
 * Represents a complete Lotus blockchain block.
 *
 * A Block extends the BlockHeader with metadata and transactions, providing
 * methods for serialization, merkle tree computation, and validation.
 *
 * @example
 * ```typescript
 * // Create from hex string
 * const block = Block.fromString(hexString)
 *
 * // Create from buffer
 * const block = Block.fromBuffer(buffer)
 *
 * // Access block hash
 * console.log(block.id)
 *
 * // Validate merkle root
 * if (block.validMerkleRoot()) {
 *   console.log('Merkle root is valid')
 * }
 *
 * // Create SPV proof for specific transactions
 * const merkleBlock = block.toMerkleBlock(['txid1...'])
 * ```
 */
export class Block {
  /** Maximum block size (32 MiB) */
  static readonly MAX_BLOCK_SIZE = 32 * 1024 * 1024
  /** 32-byte zero hash constant */
  static readonly NULL_HASH = NULL_HASH

  /** Block header */
  header!: BlockHeader

  /** Transactions in this block */
  transactions!: Transaction[]

  /** Cached block hash */
  private _id?: string

  /**
   * Create a new Block
   *
   * @param serialized - Input data: BlockData object, Block instance,
   *                     Buffer, or hex string
   *
   * @example
   * ```typescript
   * // From hex string
   * const block = new Block(hexString)
   *
   * // From object
   * const block = new Block({ header: headerData, transactions: [] })
   *
   * // Empty block
   * const block = new Block()
   * ```
   */
  constructor(serialized?: BlockData | Block | Buffer | string) {
    if (serialized instanceof Block) {
      return Block.shallowCopy(serialized)
    } else if (typeof serialized === 'string' && JSUtil.isHexa(serialized)) {
      this._fromString(serialized)
    } else if (
      Buffer.isBuffer(serialized) ||
      (serialized && typeof serialized === 'object')
    ) {
      const info = Block._from(serialized)
      this.header = info.header as BlockHeader
      this.transactions = info.transactions!
    } else {
      this._initEmpty()
    }
  }

  // ---------------------------------------------------------------------------
  // Static factory methods
  // ---------------------------------------------------------------------------

  /**
   * Create a shallow copy of a block by serializing and deserializing it.
   *
   * @param block - Block to copy
   * @returns New Block instance with the same data
   */
  static shallowCopy(block: Block): Block {
    return new Block(block.toBuffer())
  }

  /**
   * Create a Block from an object containing header and transactions.
   *
   * @param obj - BlockData object
   * @returns New Block instance
   */
  static fromObject(obj: BlockData): Block {
    const info = Block._fromObject(obj)
    return new Block(info)
  }

  /**
   * Create a Block from a BufferReader.
   *
   * @param br - BufferReader positioned at block data
   * @returns New Block instance
   */
  static fromBufferReader(br: BufferReader): Block {
    $.checkArgument(br instanceof BufferReader, 'br is required')
    const info = Block._readFromBuffer(br)
    return new Block(info)
  }

  /**
   * Create a Block from a Buffer.
   *
   * @param buf - Buffer containing serialized block data
   * @returns New Block instance
   */
  static fromBuffer(buf: Buffer): Block {
    return Block.fromBufferReader(new BufferReader(buf))
  }

  /**
   * Create a Block from a hex string.
   *
   * @param str - Hex-encoded serialized block
   * @returns New Block instance
   */
  static fromString(str: string): Block {
    return Block.fromBuffer(Buffer.from(str, 'hex'))
  }

  /**
   * Create a Block from raw block data (e.g., from disk or network).
   *
   * @param data - Raw block data as Buffer or binary string
   * @returns New Block instance
   */
  static fromRawBlock(data: Buffer | string): Block {
    if (!BufferUtil.isBuffer(data)) {
      data = Buffer.from(data, 'binary')
    }
    const br = new BufferReader(data) // position is set to 0 by default
    const info = Block._readFromBuffer(br)
    return new Block(info)
  }

  // ---------------------------------------------------------------------------
  // Serialization methods
  // ---------------------------------------------------------------------------

  /**
   * Convert to a plain JavaScript object.
   *
   * @returns BlockObject with all values serialized
   */
  toObject(): BlockObject {
    const transactions = this.transactions.map(tx => tx.toObject())
    return {
      id: this.id,
      hash: this.hash,
      header: this.header.toObject(),
      transactions,
    }
  }

  /**
   * Convert to JSON (alias for toObject)
   */
  toJSON(): BlockObject {
    return this.toObject()
  }

  /**
   * Serialize the block to a Buffer.
   *
   * Format: header + varint(0 metadata) + varint(tx count) + transactions
   *
   * @returns Buffer containing serialized block data
   */
  toBuffer(): Buffer {
    return this.toBufferWriter().concat()
  }

  /**
   * Serialize the block to a hex string.
   *
   * @returns Hex-encoded serialized block
   */
  toString(): string {
    return this.toBuffer().toString('hex')
  }

  /**
   * Write block data to a BufferWriter.
   *
   * Serializes header, metadata vector (currently empty), and transactions
   * to match lotusd CBlock serialization format.
   *
   * @param bw - Optional BufferWriter to reuse
   * @returns BufferWriter containing the serialized block data
   */
  toBufferWriter(bw?: BufferWriter): BufferWriter {
    if (!bw) {
      bw = new BufferWriter()
    }
    bw.write(this.header.toBuffer())
    // Metadata vector (compact size 0 — metadata fields not currently stored)
    bw.writeVarintNum(0)
    bw.writeVarintNum(this.transactions.length)
    for (const tx of this.transactions) {
      tx.toBufferWriter(bw)
    }
    return bw
  }

  // ---------------------------------------------------------------------------
  // Merkle tree operations
  // ---------------------------------------------------------------------------

  /**
   * Compute combined transaction hashes for merkle tree construction.
   *
   * In Lotus, each transaction contributes two identifiers:
   * - **hash**: SHA256d of the serialized transaction data
   * - **txid**: Merkle-based identifier (inputs/outputs merkle roots)
   *
   * These are combined as SHA256d(hash || txid) per transaction.
   *
   * @returns Array of 32-byte hash buffers, one per transaction.
   *          Returns [NULL_HASH] if the block has no transactions.
   */
  getTransactionHashes(): Buffer[] {
    if (this.transactions.length === 0) {
      return [Block.NULL_HASH]
    }

    const hashes: Buffer[] = []
    for (const tx of this.transactions) {
      const combined = Buffer.concat([tx.hashBuffer, tx.txidBuffer])
      hashes.push(Hash.sha256sha256(combined))
    }
    return hashes
  }

  /**
   * Build the full merkle tree from transaction hashes.
   *
   * Constructs the tree by iteratively hashing pairs of nodes. If a level
   * has an odd number of elements, a null hash is appended to make it even.
   *
   * @returns Array of Buffers representing all tree nodes.
   *          The merkle root is the last element.
   */
  getMerkleTree(): Buffer[] {
    const tree = this.getTransactionHashes()

    let j = 0
    for (let size = tree.length; size > 1; size = Math.floor(size / 2)) {
      if (size % 2 === 1) {
        tree.push(Block.NULL_HASH)
        size += 1
      }
      for (let i = 0; i < size; i += 2) {
        const combined = Buffer.concat([tree[j + i], tree[j + i + 1]])
        tree.push(Hash.sha256sha256(combined))
      }
      j += size
    }

    return tree
  }

  /**
   * Compute the merkle root from the transactions in this block.
   *
   * @returns 32-byte merkle root buffer
   */
  getMerkleRoot(): Buffer {
    const tree = this.getMerkleTree()
    return tree[tree.length - 1]
  }

  /**
   * Verify that the computed merkle root matches the header merkle root.
   *
   * @returns True if the merkle roots match
   */
  validMerkleRoot(): boolean {
    const headerRoot = BN.fromBuffer(this.header.merkleRoot)
    const computedRoot = BN.fromBuffer(this.getMerkleRoot())
    return headerRoot.eq(computedRoot)
  }

  /**
   * Create a MerkleBlock containing a partial merkle tree for specific
   * transactions. Used for SPV (Simplified Payment Verification).
   *
   * @param txids - Array of transaction IDs to include in the proof
   * @returns MerkleBlock with partial merkle tree
   *
   * @throws {TypeError} If txids is empty or contains invalid format
   * @throws {Error} If block has no transactions
   */
  toMerkleBlock(txids: string[]): MerkleBlock {
    if (!Array.isArray(txids) || txids.length === 0) {
      throw new TypeError('txids must be a non-empty array of transaction IDs')
    }

    for (const txid of txids) {
      if (!/^[0-9a-fA-F]{64}$/.test(txid)) {
        throw new TypeError(`Invalid transaction ID format: ${txid}`)
      }
    }

    if (this.transactions.length === 0) {
      throw new Error(
        'Cannot create MerkleBlock from block with no transactions',
      )
    }

    // Build leaf arrays: hash + txid pairs per transaction (Lotus-specific)
    const vHashes: string[] = []
    const vMatch: boolean[] = []

    for (const tx of this.transactions) {
      const txhash = tx.hash
      const txid = tx.txid
      const txidLower = txid.toLowerCase()

      // Even index: txhash (not matchable)
      vMatch.push(false)
      vHashes.push(txhash)

      // Odd index: txid (matchable)
      const isMatch = txids.some(id => id.toLowerCase() === txidLower)
      vMatch.push(isMatch)
      vHashes.push(txid)
    }

    const nLeaves = vHashes.length
    const height = calcTreeHeight(nLeaves)

    const vBits: boolean[] = []
    const vHash: string[] = []
    traverseAndBuild(
      height,
      0,
      nLeaves,
      vHashes,
      vMatch,
      vBits,
      vHash,
      Block.NULL_HASH,
    )

    return new MerkleBlock({
      header: this.header,
      numTransactions: this.transactions.length,
      hashes: vHash,
      flags: vBits.map(b => (b ? 1 : 0)),
    })
  }

  // ---------------------------------------------------------------------------
  // Hash and identification
  // ---------------------------------------------------------------------------

  /**
   * Block hash in display format (big-endian hex).
   * Delegates to the header hash computation.
   */
  get hash(): string {
    if (!this._id) {
      this._id = this.header.id
    }
    return this._id
  }

  /**
   * Block ID (alias for hash)
   */
  get id(): string {
    return this.hash
  }

  /**
   * String representation for console/debugging
   */
  inspect(): string {
    return '<Block ' + this.id + '>'
  }

  // ---------------------------------------------------------------------------
  // Private methods
  // ---------------------------------------------------------------------------

  /**
   * Dispatch construction from Buffer or object.
   */
  private static _from(arg: BlockData | Buffer): BlockData {
    if (Buffer.isBuffer(arg)) {
      return Block._readFromBuffer(new BufferReader(arg))
    } else if (typeof arg === 'object' && arg !== null) {
      return Block._fromObject(arg)
    }
    throw new TypeError('Unrecognized argument for Block')
  }

  /**
   * Create BlockData from an object, normalizing header and transactions.
   */
  private static _fromObject(data: BlockData): BlockData {
    const transactions: Transaction[] = []
    if (data.transactions) {
      for (const tx of data.transactions) {
        transactions.push(tx instanceof Transaction ? tx : new Transaction(tx))
      }
    }

    let header: BlockHeader
    if (data.header instanceof BlockHeader) {
      header = data.header
    } else if (data.header) {
      header = new BlockHeader(data.header)
    } else {
      header = new BlockHeader()
    }

    return { header, transactions }
  }

  /**
   * Read a complete block from a BufferReader.
   *
   * Reads: header + metadata vector + transaction vector
   * (matches lotusd CBlock serialization)
   */
  private static _readFromBuffer(br: BufferReader): BlockData {
    $.checkState(!br.finished(), 'No block data received')

    const header = BlockHeader.fromBufferReader(br)

    // Read metadata vector (CBlockMetadataField entries)
    const metadataCount = br.readVarintNum()
    for (let i = 0; i < metadataCount; i++) {
      br.readUInt32LE() // nFieldId (skip)
      const dataLength = br.readVarintNum()
      br.read(dataLength) // vData (skip)
    }

    // Read transaction vector
    const transactionCount = br.readVarintNum()
    const transactions: Transaction[] = []
    for (let i = 0; i < transactionCount; i++) {
      const tx = new Transaction()
      transactions.push(tx.fromBufferReader(br))
    }

    return { header, transactions }
  }

  /**
   * Initialize an empty block with default header and no transactions.
   */
  private _initEmpty(): void {
    this.header = new BlockHeader()
    this.transactions = []
  }

  /**
   * Deserialize block from a hex string (instance method).
   */
  private _fromString(str: string): void {
    const buf = Buffer.from(str, 'hex')
    const info = Block._readFromBuffer(new BufferReader(buf))
    this.header = info.header as BlockHeader
    this.transactions = info.transactions!
  }
}

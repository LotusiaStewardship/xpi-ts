/**
 * MerkleBlock implementation for SPV (Simplified Payment Verification)
 *
 * Represents a CMerkleBlock from lotusd: a block header paired with a
 * CPartialMerkleTree that proves inclusion of specific transactions
 * without requiring the full block.
 *
 * Lotus-specific: each transaction contributes two leaves to the merkle
 * tree (txhash + txid), so nLeaves = numTransactions * 2.
 *
 * Serialization format:
 *   BlockHeader(160) + uint32(numTransactions) + varint(numHashes) +
 *   uint256[](hashes) + varint(numFlagBytes) + byte[](flags)
 *
 * The partial merkle tree traversal algorithm matches lotusd's
 * CPartialMerkleTree::TraverseAndExtract exactly.
 *
 * @see lotusd: src/merkleblock.h, src/merkleblock.cpp
 * @see BIP37: https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
 */

import { Buffer } from 'buffer/'
import {
  BlockHeader,
  type BlockHeaderData,
  type BlockHeaderObject,
} from './blockheader.js'
import { BufferReader } from '../encoding/bufferreader.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { Hash } from '../crypto/hash.js'
import { BufferUtil, NULL_HASH } from '../util/buffer.js'
import { Transaction } from '../transaction/index.js'
import { BitcoreError } from '../errors.js'
import { Preconditions as $ } from '../util/preconditions.js'
import { bitsToBytes, bytesToBits, extractBit } from '../util/bits.js'
import { calcTreeWidth } from '../util/merkle.js'

/**
 * Error thrown when a MerkleBlock is invalid (e.g., missing data, wrong format).
 */
export class InvalidMerkleBlockError extends Error {
  readonly code: string
  readonly context: Record<string, unknown>

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message)
    this.name = 'InvalidMerkleBlockError'
    this.code = 'INVALID_MERKLE_BLOCK'
    this.context = context
  }
}

/**
 * Error thrown when MerkleBlock validation fails (e.g., invalid field values).
 */
export class MerkleBlockValidationError extends Error {
  readonly code: string
  readonly context: Record<string, unknown>

  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message)
    this.name = 'MerkleBlockValidationError'
    this.code = 'MERKLE_BLOCK_VALIDATION_ERROR'
    this.context = context
  }
}

/**
 * Internal state for merkle tree traversal.
 * Tracks consumed hashes and flag bits during tree reconstruction.
 * @internal
 */
interface MerkleTraversalState {
  /** Number of hashes consumed during traversal */
  hashesUsed: number
  /** Number of flag bits consumed during traversal */
  flagBitsUsed: number
  /** Collected matched transaction hashes */
  txs: string[]
}

/**
 * MerkleBlock data interface for construction (internal format).
 * Uses BlockHeader instance or BlockHeaderData (Buffer/BN types).
 */
export interface MerkleBlockData {
  /** Block header */
  header: BlockHeader | BlockHeaderData
  /** Total number of transactions in the original block */
  numTransactions: number
  /** Array of merkle node hashes (hex strings, little-endian) */
  hashes: string[]
  /** Bit flags for partial merkle tree traversal */
  flags: number[]
}

/**
 * MerkleBlock object interface for serialization/JSON.
 * Header is in BlockHeaderObject format with display-format hashes.
 */
export interface MerkleBlockObject {
  /** Block header in serialized format */
  header: BlockHeaderObject
  /** Total number of transactions in the original block */
  numTransactions: number
  /** Array of merkle node hashes (hex strings) */
  hashes: string[]
  /** Bit flags for partial merkle tree traversal */
  flags: number[]
}

/**
 * A MerkleBlock is a block header with a partial merkle tree that proves
 * inclusion of specific transactions without requiring the full block.
 *
 * This is essential for SPV clients that need to verify transaction
 * inclusion while downloading minimal data.
 *
 * @example
 * ```typescript
 * // Create from buffer (e.g., from network)
 * const merkleBlock = MerkleBlock.fromBuffer(buffer)
 *
 * // Validate the merkle tree
 * if (merkleBlock.validMerkleTree()) {
 *   console.log('Valid merkle proof')
 * }
 *
 * // Check if a transaction is included
 * if (merkleBlock.hasTransaction(txid)) {
 *   console.log('Transaction is in the block')
 * }
 *
 * // Get all matched transaction hashes
 * const matched = merkleBlock.filteredTxsHash()
 * ```
 */
export class MerkleBlock {
  /** 32-byte zero hash for merkle tree padding */
  static readonly NULL_HASH = NULL_HASH
  /** Block header containing proof-of-work and metadata */
  readonly header!: BlockHeader
  /** Total number of transactions in the original block */
  readonly numTransactions!: number
  /** Merkle node hashes (hex strings, little-endian byte order) */
  readonly hashes!: string[]
  /** Bit flags for partial merkle tree traversal */
  readonly flags!: number[]

  /**
   * Create a new MerkleBlock
   *
   * @param arg - Buffer or MerkleBlockData object
   *
   * @throws {Error} If input is invalid or missing
   *
   * @example
   * ```typescript
   * // From buffer
   * const mb = new MerkleBlock(buffer)
   *
   * // From data object
   * const mb = new MerkleBlock({
   *   header: blockHeader,
   *   numTransactions: 5,
   *   hashes: ['abc...', 'def...'],
   *   flags: [1, 0, 1]
   * })
   * ```
   */
  constructor(arg?: Buffer | MerkleBlockData) {
    if (arg instanceof MerkleBlock) {
      return arg
    }

    if (!arg) {
      throw new InvalidMerkleBlockError(
        'Argument is required for MerkleBlock',
        {
          received: arg,
        },
      )
    }

    const info = MerkleBlock._from(arg)

    if (info.header instanceof BlockHeader) {
      this.header = info.header
    } else {
      this.header = new BlockHeader(info.header)
    }
    this.numTransactions = info.numTransactions
    this.hashes = info.hashes
    this.flags = info.flags
  }

  // ---------------------------------------------------------------------------
  // Static factory methods
  // ---------------------------------------------------------------------------

  /**
   * Create from a MerkleBlockObject (serialized/JSON format).
   *
   * @param obj - Object with header in BlockHeaderObject format
   * @returns New MerkleBlock instance
   *
   * @throws {TypeError} If required fields are missing or invalid
   */
  static fromObject(obj: MerkleBlockObject): MerkleBlock {
    if (!obj.header) {
      throw new MerkleBlockValidationError('Block header is required', {
        header: obj.header,
      })
    }
    return new MerkleBlock({
      header: BlockHeader.fromObject(obj.header),
      numTransactions: obj.numTransactions,
      hashes: obj.hashes,
      flags: obj.flags,
    })
  }

  /**
   * Create from a Buffer.
   *
   * @param buf - Buffer containing serialized MerkleBlock data
   * @returns New MerkleBlock instance
   *
   * @throws {TypeError} If buffer is invalid or empty
   */
  static fromBuffer(buf: Buffer): MerkleBlock {
    if (!BufferUtil.isBuffer(buf) || buf.length === 0) {
      throw new InvalidMerkleBlockError('Invalid buffer provided', {
        isBuffer: BufferUtil.isBuffer(buf),
        length: buf?.length,
      })
    }
    return MerkleBlock.fromBufferReader(new BufferReader(buf))
  }

  /**
   * Create from a BufferReader.
   *
   * @param br - BufferReader positioned at MerkleBlock data
   * @returns New MerkleBlock instance
   */
  static fromBufferReader(br: BufferReader): MerkleBlock {
    const info = MerkleBlock._readFromBuffer(br)
    return new MerkleBlock(info)
  }

  /**
   * Create from a hex string.
   *
   * @param str - Hex-encoded serialized MerkleBlock
   * @returns New MerkleBlock instance
   *
   * @throws {TypeError} If string is empty or invalid
   */
  static fromString(str: string): MerkleBlock {
    $.checkArgument(
      typeof str === 'string' && str.length > 0,
      'str',
      'Invalid hex string provided',
    )
    return MerkleBlock.fromBuffer(Buffer.from(str, 'hex'))
  }

  // ---------------------------------------------------------------------------
  // Serialization methods
  // ---------------------------------------------------------------------------

  /**
   * Serialize to a Buffer.
   *
   * Format: header + uint32(numTransactions) + varint(numHashes) +
   *         hashes + varint(numFlagBytes) + flagBytes
   *
   * @returns Buffer containing serialized MerkleBlock
   */
  toBuffer(): Buffer {
    return this.toBufferWriter().concat()
  }

  /**
   * Write MerkleBlock data to a BufferWriter.
   *
   * @param bw - Optional BufferWriter to reuse
   * @returns BufferWriter containing serialized data
   */
  toBufferWriter(bw?: BufferWriter): BufferWriter {
    if (!bw) {
      bw = new BufferWriter()
    }

    bw.write(this.header.toBuffer())
    bw.writeUInt32LE(this.numTransactions)
    bw.writeVarintNum(this.hashes.length)

    for (const hash of this.hashes) {
      bw.write(Buffer.from(hash, 'hex'))
    }

    // Pack flag bits into bytes (LSB-first, matching lotusd BitsToBytes)
    const flagBytes = bitsToBytes(this.flags.map(f => f !== 0))
    bw.writeVarintNum(flagBytes.length)
    for (const byte of flagBytes) {
      bw.writeUInt8(byte)
    }

    return bw
  }

  /**
   * Convert to a plain JavaScript object.
   *
   * @returns MerkleBlockObject with header in display format
   */
  toObject(): MerkleBlockObject {
    return {
      header: this.header.toObject(),
      numTransactions: this.numTransactions,
      hashes: this.hashes,
      flags: this.flags,
    }
  }

  /**
   * Convert to JSON (alias for toObject)
   */
  toJSON(): MerkleBlockObject {
    return this.toObject()
  }

  // ---------------------------------------------------------------------------
  // Validation and querying
  // ---------------------------------------------------------------------------

  /**
   * Verify that the partial merkle tree is valid and produces the
   * expected merkle root stored in the block header.
   *
   * Performs the same validation as lotusd CPartialMerkleTree::ExtractMatches:
   * - Checks hash/flag array consistency
   * - Traverses the tree and verifies all hashes are consumed
   * - Compares computed root against header merkle root
   *
   * @returns True if the merkle tree is valid
   */
  validMerkleTree(): boolean {
    if (!Array.isArray(this.flags) || !Array.isArray(this.hashes)) {
      return false
    }

    // Can't have more hashes than numTransactions
    if (this.hashes.length > this.numTransactions) {
      return false
    }

    // Can't have fewer flag bits than hashes
    if (this.flags.length * 8 < this.hashes.length) {
      return false
    }

    const height = this._calcTreeHeight()
    const state: MerkleTraversalState = {
      hashesUsed: 0,
      flagBitsUsed: 0,
      txs: [],
    }
    const root = this._traverseAndExtract(height, 0, state)

    if (state.hashesUsed !== this.hashes.length) {
      return false
    }

    return BufferUtil.equals(root, this.header.merkleRoot)
  }

  /**
   * Extract and return transaction hashes that match the filter criteria.
   *
   * @returns Array of matched transaction hash strings (little-endian hex)
   *
   * @throws {BitcoreError.MerkleBlock.InvalidMerkleTree} If the tree is invalid
   */
  filteredTxsHash(): string[] {
    if (!Array.isArray(this.flags) || !Array.isArray(this.hashes)) {
      throw new BitcoreError.MerkleBlock.InvalidMerkleTree()
    }

    if (this.hashes.length > this.numTransactions) {
      throw new BitcoreError.MerkleBlock.InvalidMerkleTree()
    }

    if (this.flags.length * 8 < this.hashes.length) {
      throw new BitcoreError.MerkleBlock.InvalidMerkleTree()
    }

    // Single hash means no matched transactions
    if (this.hashes.length === 1) {
      return []
    }

    const height = this._calcTreeHeight()
    const state: MerkleTraversalState = {
      hashesUsed: 0,
      flagBitsUsed: 0,
      txs: [],
    }
    this._traverseAndExtract(height, 0, state)

    if (state.hashesUsed !== this.hashes.length) {
      throw new BitcoreError.MerkleBlock.InvalidMerkleTree()
    }

    return state.txs
  }

  /**
   * Check if a specific transaction is included in this MerkleBlock.
   *
   * @param tx - Transaction object or transaction ID string
   * @returns True if the transaction is found in the partial merkle tree
   *
   * @throws {BitcoreError} If tx is undefined or invalid format
   *
   * @remarks
   * In Lotus, txid and hash are different values. SPV verification
   * uses txid for transaction identification.
   */
  hasTransaction(tx: Transaction | string): boolean {
    if (!tx) {
      throw new BitcoreError('Transaction cannot be undefined')
    }

    if (!(tx instanceof Transaction) && typeof tx !== 'string') {
      throw new BitcoreError(
        'Invalid transaction: must be string or Transaction',
      )
    }

    if (typeof tx === 'string' && !/^[0-9a-fA-F]{64}$/.test(tx)) {
      throw new BitcoreError(
        'Invalid transaction ID format: must be 64-character hex string',
      )
    }

    let searchTxid: string
    let searchHash: string

    if (tx instanceof Transaction) {
      // Reverse for comparison with merkle tree (stored little-endian)
      searchTxid = BufferUtil.reverse(Buffer.from(tx.txid, 'hex')).toString(
        'hex',
      )
      searchHash = BufferUtil.reverse(Buffer.from(tx.hash, 'hex')).toString(
        'hex',
      )
    } else {
      searchTxid = BufferUtil.reverse(Buffer.from(tx, 'hex')).toString('hex')
      searchHash = searchTxid
    }

    const state: MerkleTraversalState = {
      hashesUsed: 0,
      flagBitsUsed: 0,
      txs: [],
    }
    const height = this._calcTreeHeight()
    this._traverseAndExtract(height, 0, state)

    return state.txs.includes(searchTxid) || state.txs.includes(searchHash)
  }

  // ---------------------------------------------------------------------------
  // Private methods
  // ---------------------------------------------------------------------------

  /**
   * Dispatch construction from Buffer or object.
   */
  private static _from(arg: Buffer | MerkleBlockData): MerkleBlockData {
    if (BufferUtil.isBuffer(arg)) {
      return MerkleBlock._readFromBuffer(new BufferReader(arg))
    } else if (typeof arg === 'object' && arg !== null) {
      return MerkleBlock._validateData(arg)
    }
    throw new InvalidMerkleBlockError('Unrecognized argument for MerkleBlock', {
      type: typeof arg,
      arg,
    })
  }

  /**
   * Validate and normalize MerkleBlockData input.
   */
  private static _validateData(data: MerkleBlockData): MerkleBlockData {
    if (!data.header) {
      throw new MerkleBlockValidationError('Block header is required', {
        header: data.header,
      })
    }
    if (typeof data.numTransactions !== 'number' || data.numTransactions < 0) {
      throw new MerkleBlockValidationError(
        'Number of transactions must be a non-negative number',
        {
          numTransactions: data.numTransactions,
          type: typeof data.numTransactions,
        },
      )
    }
    if (!Array.isArray(data.hashes)) {
      throw new MerkleBlockValidationError('Hashes must be an array', {
        hashes: data.hashes,
        type: typeof data.hashes,
      })
    }
    if (!Array.isArray(data.flags)) {
      throw new MerkleBlockValidationError('Flags must be an array', {
        flags: data.flags,
        type: typeof data.flags,
      })
    }

    const header =
      data.header instanceof BlockHeader
        ? data.header
        : new BlockHeader(data.header)

    return {
      header,
      numTransactions: data.numTransactions,
      hashes: data.hashes,
      flags: data.flags,
    }
  }

  /**
   * Read MerkleBlock data from a BufferReader.
   *
   * Format: header + uint32(numTransactions) + varint(numHashes) +
   *         hashes + varint(numFlagBytes) + flagBytes
   */
  private static _readFromBuffer(br: BufferReader): MerkleBlockData {
    if (br.finished()) {
      throw new InvalidMerkleBlockError('No merkleblock data received')
    }

    const header = BlockHeader.fromBufferReader(br)
    const numTransactions = br.readUInt32LE()
    const numHashes = br.readVarintNum()
    const hashes: string[] = []

    for (let i = 0; i < numHashes; i++) {
      hashes.push(br.read(32).toString('hex'))
    }

    const numFlags = br.readVarintNum()
    const flagBytes: number[] = []

    for (let i = 0; i < numFlags; i++) {
      flagBytes.push(br.readUInt8())
    }

    // Unpack bytes to flag bits (LSB-first, matching lotusd BytesToBits)
    const flags = bytesToBits(flagBytes).map(b => (b ? 1 : 0))

    return { header, numTransactions, hashes, flags }
  }

  /**
   * Calculate the width of the merkle tree at a given height.
   * Lotus uses 2 leaves per transaction (hash + txid).
   */
  private _calcTreeWidth(height: number): number {
    return calcTreeWidth(this.numTransactions * 2, height)
  }

  /**
   * Calculate the total height of the merkle tree.
   */
  private _calcTreeHeight(): number {
    let height = 0
    while (this._calcTreeWidth(height) > 1) {
      height++
    }
    return height
  }

  /**
   * Traverse the partial merkle tree and extract matched transaction hashes.
   *
   * This is a faithful port of lotusd CPartialMerkleTree::TraverseAndExtract.
   * It reconstructs the merkle root while collecting matched leaf hashes.
   *
   * @param depth - Current depth in the tree
   * @param pos - Current position at this depth
   * @param state - Mutable traversal state
   * @returns 32-byte hash buffer for this node
   */
  private _traverseAndExtract(
    depth: number,
    pos: number,
    state: MerkleTraversalState,
  ): Buffer {
    if (state.flagBitsUsed > this.flags.length * 8) {
      return MerkleBlock.NULL_HASH
    }

    // Read the flag bit for this node
    const isParentOfMatch = extractBit(this.flags, state.flagBitsUsed++)

    if (depth === 0 || !isParentOfMatch) {
      // At leaf level, or not a parent of match: use stored hash
      if (state.hashesUsed >= this.hashes.length) {
        return MerkleBlock.NULL_HASH
      }

      const hash = this.hashes[state.hashesUsed++]

      // At leaf level with match flag: this is a matched txid
      if (depth === 0 && isParentOfMatch) {
        state.txs.push(hash)
      }

      return Buffer.from(hash, 'hex')
    }

    // Descend into left subtree
    const left = this._traverseAndExtract(depth - 1, pos * 2, state)

    // Descend into right subtree if it exists
    let right: Buffer
    if (pos * 2 + 1 < this._calcTreeWidth(depth - 1)) {
      right = this._traverseAndExtract(depth - 1, pos * 2 + 1, state)
    } else {
      right = MerkleBlock.NULL_HASH
    }

    // Combine left and right hashes
    return Hash.sha256sha256(Buffer.concat([left, right]))
  }
}

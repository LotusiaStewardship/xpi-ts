/**
 * BlockHeader implementation for the Lotus blockchain
 *
 * Represents the header portion of a Lotus block (CBlockHeader in lotusd).
 * Implements the Lotus-specific 3-layer hashing algorithm and custom field
 * sizes for time (6 bytes), size (7 bytes), nonce (8 bytes), etc.
 *
 * Serialization order (160 bytes total):
 *   prevHash(32) + bits(4) + time(6) + reserved(2) + nonce(8) +
 *   version(1) + size(7) + height(4) + epochBlock(32) +
 *   merkleRoot(32) + extendedMetadata(32)
 *
 * Hash algorithm (3-layer SHA256):
 *   Layer 3: SHA256(version || size || height || epochBlock || merkleRoot || extendedMetadata)
 *   Layer 2: SHA256(bits || time || reserved || nonce || layer3Hash)
 *   Layer 1: SHA256(prevHash || layer2Hash)
 *
 * @see lotusd: src/primitives/block.h, src/primitives/block.cpp
 */

import { Buffer } from 'buffer/'
import { Preconditions as $ } from '../util/preconditions.js'
import { BufferUtil } from '../util/buffer.js'
import { BufferReader } from '../encoding/bufferreader.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { Hash } from '../crypto/hash.js'
import { BN } from '../crypto/bn.js'

/** Number of blocks per epoch in Lotus */
const EPOCH_NUM_BLOCKS = 5040

/** Genesis block compact target difficulty */
const GENESIS_BITS = 0x1d00ffff

/** Total serialized size of a block header in bytes */
const HEADER_SIZE = 160

/**
 * Block header data interface for internal/deserialized format.
 * Uses native types: Buffer for hashes, BN for large numbers.
 */
export interface BlockHeaderData {
  /** Hash of the previous block (32 bytes, little-endian) */
  prevHash?: Buffer
  /** Compact representation of the target difficulty */
  bits?: number
  /** Block timestamp in seconds since Unix epoch */
  time?: number
  /** Reserved field for future use (always 0) */
  reserved?: number
  /** Nonce used for proof of work (8 bytes) */
  nonce?: BN
  /** Block header version number (1 byte, always 0x01) */
  version?: number
  /** Advertised block size (7 bytes) */
  size?: BN
  /** Block height in the chain */
  height?: number
  /** Hash of the epoch block (32 bytes, little-endian) */
  epochBlock?: Buffer
  /** Merkle root of all transactions (32 bytes, little-endian) */
  merkleRoot?: Buffer
  /** Extended metadata hash (32 bytes, little-endian) */
  extendedMetadata?: Buffer
  /** Precomputed block hash for validation (display format, big-endian hex) */
  hash?: string
}

/**
 * Block header object interface for serialization/JSON.
 * All values are converted to serializable formats (strings and numbers).
 * Hash fields are in display format (big-endian hex).
 */
export interface BlockHeaderObject {
  /** Computed block hash (big-endian hex) */
  hash: string
  /** Hash of the previous block (big-endian hex) */
  prevHash: string
  /** Compact representation of the target difficulty */
  bits: number
  /** Block timestamp in seconds since Unix epoch */
  time: number
  /** Reserved field for future use */
  reserved: number
  /** Nonce as decimal string */
  nonce: string
  /** Block header version number */
  version: number
  /** Advertised block size as number */
  size: number
  /** Block height in the chain */
  height: number
  /** Hash of the epoch block (big-endian hex) */
  epochBlock: string
  /** Merkle root of all transactions (big-endian hex) */
  merkleRoot: string
  /** Extended metadata hash (big-endian hex) */
  extendedMetadata: string
}

/**
 * Represents a Lotus blockchain block header.
 *
 * Implements the CBlockHeader structure from lotusd with Lotus-specific
 * features including 3-layer SHA256 hashing, 6-byte timestamps, 7-byte
 * block sizes, and epoch block references.
 *
 * @example
 * ```typescript
 * // Create from buffer
 * const header = BlockHeader.fromBuffer(headerBuffer)
 *
 * // Get block hash
 * console.log(header.id)
 *
 * // Validate proof of work
 * if (header.validProofOfWork()) {
 *   console.log('Valid PoW')
 * }
 *
 * // Serialize to buffer
 * const buffer = header.toBuffer()
 * ```
 */
export class BlockHeader {
  /** Start buffer position in raw block data */
  static readonly START_OF_HEADER = 0

  /** Maximum time offset (2 hours) a block timestamp can be ahead of current time */
  static readonly MAX_TIME_OFFSET = 2 * 60 * 60

  /** Largest possible hash value (2^256) for difficulty calculations */
  static readonly LARGEST_HASH = new BN(
    '10000000000000000000000000000000000000000000000000000000000000000',
    'hex',
  )

  /** Total serialized size of a block header */
  static readonly HEADER_SIZE = HEADER_SIZE

  /** Number of blocks per epoch */
  static readonly EPOCH_NUM_BLOCKS = EPOCH_NUM_BLOCKS

  /** Constants structure for backward compatibility */
  static readonly Constants = {
    START_OF_HEADER: 0,
    MAX_TIME_OFFSET: 2 * 60 * 60,
    LARGEST_HASH: new BN(
      '10000000000000000000000000000000000000000000000000000000000000000',
      'hex',
    ),
  }

  /** Hash of the previous block (32 bytes, little-endian) */
  readonly prevHash!: Buffer
  /** Compact target difficulty */
  readonly bits!: number
  /** Block timestamp in seconds since Unix epoch */
  readonly time!: number
  /** Alias for time (backward compatibility) */
  readonly timestamp!: number
  /** Reserved field (always 0) */
  readonly reserved!: number
  /** Nonce used for proof of work */
  readonly nonce!: BN
  /** Header version (always 0x01) */
  readonly version!: number
  /** Advertised block size */
  readonly size!: BN
  /** Block height in the chain */
  readonly height!: number
  /** Hash of the epoch block (32 bytes, little-endian) */
  readonly epochBlock!: Buffer
  /** Merkle root of transactions (32 bytes, little-endian) */
  readonly merkleRoot!: Buffer
  /** Extended metadata hash (32 bytes, little-endian) */
  readonly extendedMetadata!: Buffer

  /** Cached block hash (big-endian hex, display format) */
  private _id?: string

  /**
   * Create a new BlockHeader
   *
   * @param arg - BlockHeaderData object or existing BlockHeader instance
   *
   * @example
   * ```typescript
   * // Empty header with defaults
   * const header = new BlockHeader()
   *
   * // From deserialized data
   * const header = new BlockHeader({ prevHash: buf, bits: 0x1d00ffff, ... })
   * ```
   */
  constructor(arg?: BlockHeaderData | BlockHeader) {
    if (arg instanceof BlockHeader) {
      return arg
    }

    const data = arg
      ? BlockHeader._normalizeData(arg)
      : BlockHeader._defaultData()

    this.prevHash = data.prevHash!
    this.bits = data.bits!
    this.time = data.time!
    this.timestamp = data.time!
    this.reserved = data.reserved!
    this.nonce = data.nonce!
    this.version = data.version!
    this.size = data.size!
    this.height = data.height!
    this.epochBlock = data.epochBlock!
    this.merkleRoot = data.merkleRoot!
    this.extendedMetadata = data.extendedMetadata!

    if (data.hash) {
      $.checkState(
        this.hash === data.hash,
        'Argument object hash property does not match block hash.',
      )
    }
  }

  // ---------------------------------------------------------------------------
  // Static factory methods
  // ---------------------------------------------------------------------------

  /**
   * Create from a BlockHeaderObject (serialized/JSON format).
   * Hash fields are expected in display format (big-endian hex strings).
   *
   * @param obj - BlockHeaderObject with display-format hashes
   * @returns New BlockHeader instance
   */
  static fromObject(obj: BlockHeaderObject): BlockHeader {
    $.checkArgument(
      typeof obj === 'object' && obj !== null,
      'data',
      'data is required',
    )

    const prevHash = obj.prevHash
      ? BufferUtil.reverse(Buffer.from(obj.prevHash, 'hex'))
      : Buffer.alloc(32)
    const merkleRoot = obj.merkleRoot
      ? BufferUtil.reverse(Buffer.from(obj.merkleRoot, 'hex'))
      : Buffer.alloc(32)
    const epochBlock = obj.epochBlock
      ? BufferUtil.reverse(Buffer.from(obj.epochBlock, 'hex'))
      : Buffer.alloc(32)
    const extendedMetadata = obj.extendedMetadata
      ? BufferUtil.reverse(Buffer.from(obj.extendedMetadata, 'hex'))
      : Buffer.alloc(32)

    return new BlockHeader({
      hash: obj.hash,
      prevHash,
      bits: obj.bits || 0,
      time: obj.time || 0,
      reserved: obj.reserved || 0,
      nonce: new BN(obj.nonce, 10),
      version: obj.version || 0,
      size: new BN(obj.size),
      height: obj.height || 0,
      epochBlock,
      merkleRoot,
      extendedMetadata,
    })
  }

  /**
   * Create from raw block data (binary string or Buffer)
   *
   * @param data - Raw block data
   * @returns New BlockHeader instance
   */
  static fromRawBlock(data: Buffer | string): BlockHeader {
    if (!Buffer.isBuffer(data)) {
      data = Buffer.from(data, 'binary')
    }
    const br = new BufferReader(data)
    br.pos = BlockHeader.START_OF_HEADER
    return BlockHeader.fromBufferReader(br)
  }

  /**
   * Create from a Buffer containing a serialized block header
   *
   * @param buf - Buffer with serialized header data
   * @returns New BlockHeader instance
   */
  static fromBuffer(buf: Buffer): BlockHeader {
    return BlockHeader.fromBufferReader(new BufferReader(buf))
  }

  /**
   * Create from a hex string
   *
   * @param str - Hex-encoded serialized block header
   * @returns New BlockHeader instance
   */
  static fromString(str: string): BlockHeader {
    return BlockHeader.fromBuffer(Buffer.from(str, 'hex'))
  }

  /**
   * Create from a BufferReader
   *
   * @param br - BufferReader positioned at the start of header data
   * @returns New BlockHeader instance
   */
  static fromBufferReader(br: BufferReader): BlockHeader {
    const data = BlockHeader._readFromBuffer(br)
    return new BlockHeader(data)
  }

  // ---------------------------------------------------------------------------
  // Serialization methods
  // ---------------------------------------------------------------------------

  /**
   * Convert to a plain JavaScript object (serializable format).
   * Hash fields are in display format (big-endian hex).
   *
   * @returns BlockHeaderObject with all values as strings/numbers
   */
  toObject(): BlockHeaderObject {
    return {
      hash: this.hash,
      prevHash: BufferUtil.reverse(this.prevHash).toString('hex'),
      bits: this.bits,
      time: this.time,
      reserved: this.reserved,
      nonce: this.nonce.toString(10),
      version: this.version,
      size: this.size.toNumber(),
      height: this.height,
      epochBlock: BufferUtil.reverse(this.epochBlock).toString('hex'),
      merkleRoot: BufferUtil.reverse(this.merkleRoot).toString('hex'),
      extendedMetadata: BufferUtil.reverse(this.extendedMetadata).toString(
        'hex',
      ),
    }
  }

  /**
   * Convert to JSON (alias for toObject)
   */
  toJSON(): BlockHeaderObject {
    return this.toObject()
  }

  /**
   * Serialize to a Buffer (160 bytes)
   *
   * @returns Buffer containing the serialized block header
   */
  toBuffer(): Buffer {
    return this.toBufferWriter().toBuffer()
  }

  /**
   * Serialize to a hex string
   *
   * @returns Hex-encoded serialized block header
   */
  toString(): string {
    return this.toBuffer().toString('hex')
  }

  /**
   * Write header fields to a BufferWriter.
   *
   * Serialization order matches lotusd CBlockHeader::SERIALIZE_METHODS:
   *   prevHash(32) + bits(4) + time(6) + reserved(2) + nonce(8) +
   *   version(1) + size(7) + height(4) + epochBlock(32) +
   *   merkleRoot(32) + extendedMetadata(32)
   *
   * @param bw - Optional BufferWriter to reuse
   * @returns BufferWriter containing the serialized data
   */
  toBufferWriter(bw?: BufferWriter): BufferWriter {
    if (!bw) {
      bw = new BufferWriter()
    }
    bw.write(this.prevHash)
    bw.writeUInt32LE(this.bits)
    bw.writeUInt48LE(this.time)
    bw.writeUInt16LE(this.reserved)
    bw.writeUInt64LEBN(this.nonce)
    bw.writeUInt8(this.version)
    bw.writeUInt56LEBN(this.size)
    bw.writeUInt32LE(this.height)
    bw.write(this.epochBlock)
    bw.write(this.merkleRoot)
    bw.write(this.extendedMetadata)
    return bw
  }

  // ---------------------------------------------------------------------------
  // Hash and identification
  // ---------------------------------------------------------------------------

  /**
   * Block hash in display format (big-endian hex).
   * Computed using the Lotus 3-layer SHA256 algorithm.
   */
  get hash(): string {
    if (!this._id) {
      const hashBuffer = this._computeHash()
      this._id = BufferUtil.reverse(hashBuffer).toString('hex')
    }
    return this._id
  }

  /**
   * Block ID (alias for hash)
   */
  get id(): string {
    return this.hash
  }

  // ---------------------------------------------------------------------------
  // Difficulty and validation
  // ---------------------------------------------------------------------------

  /**
   * Calculate the target difficulty from compact bits encoding.
   *
   * @param bits - Optional compact bits value (defaults to this.bits)
   * @returns Target as a BN value
   */
  getTargetDifficulty(bits?: number): BN {
    bits = bits || this.bits

    let target = new BN(bits & 0xffffff)
    let mov = 8 * ((bits >>> 24) - 3)
    while (mov-- > 0) {
      target = target.mul(new BN(2))
    }
    return target
  }

  /**
   * Calculate the human-readable difficulty value.
   *
   * @returns Difficulty as a floating-point number
   */
  getDifficulty(): number {
    const difficulty1TargetBN = this.getTargetDifficulty(GENESIS_BITS).mul(
      new BN(Math.pow(10, 8)),
    )
    const currentTargetBN = this.getTargetDifficulty()

    const difficultyString = difficulty1TargetBN
      .div(currentTargetBN)
      .toString(10)
    const decimalPos = difficultyString.length - 8
    const formattedDifficulty =
      difficultyString.slice(0, decimalPos) +
      '.' +
      difficultyString.slice(decimalPos)

    return parseFloat(formattedDifficulty)
  }

  /**
   * Check if the block timestamp is not too far in the future.
   *
   * @returns True if the timestamp is within the acceptable range
   */
  validTimestamp(): boolean {
    const currentTime = Math.round(new Date().getTime() / 1000)
    return this.time <= currentTime + BlockHeader.MAX_TIME_OFFSET
  }

  /**
   * Check if the proof-of-work hash satisfies the target difficulty.
   *
   * @returns True if the block hash is below the target
   */
  validProofOfWork(): boolean {
    const pow = new BN(this.id, 'hex')
    const target = this.getTargetDifficulty()
    return !pow.gt(target)
  }

  /**
   * String representation for console/debugging
   */
  inspect(): string {
    return '<BlockHeader ' + this.id + '>'
  }

  // ---------------------------------------------------------------------------
  // Private methods
  // ---------------------------------------------------------------------------

  /**
   * Compute the block hash using the Lotus 3-layer SHA256 algorithm.
   *
   * Layer 3: SHA256(nHeaderVersion || vSize || nHeight || hashEpochBlock || hashMerkleRoot || hashExtendedMetadata)
   * Layer 2: SHA256(nBits || vTime || nReserved || nNonce || layer3Hash)
   * Layer 1: SHA256(hashPrevBlock || layer2Hash)
   *
   * @returns 32-byte hash buffer (little-endian)
   */
  private _computeHash(): Buffer {
    // Layer 3
    const bw3 = new BufferWriter()
    bw3.writeUInt8(this.version)
    bw3.writeUInt56LEBN(this.size)
    bw3.writeUInt32LE(this.height)
    bw3.write(this.epochBlock)
    bw3.write(this.merkleRoot)
    bw3.write(this.extendedMetadata)
    const layer3Hash = Hash.sha256(bw3.toBuffer())

    // Layer 2
    const bw2 = new BufferWriter()
    bw2.writeUInt32LE(this.bits)
    bw2.writeUInt48LE(this.time)
    bw2.writeUInt16LE(this.reserved)
    bw2.writeUInt64LEBN(this.nonce)
    bw2.write(layer3Hash)
    const layer2Hash = Hash.sha256(bw2.toBuffer())

    // Layer 1
    const bw1 = new BufferWriter()
    bw1.write(this.prevHash)
    bw1.write(layer2Hash)
    return Hash.sha256(bw1.toBuffer())
  }

  /**
   * Normalize BlockHeaderData input, filling in defaults for missing fields.
   */
  private static _normalizeData(data: BlockHeaderData): BlockHeaderData {
    return {
      hash: data.hash,
      prevHash: data.prevHash || Buffer.alloc(32),
      bits: data.bits || 0,
      time: data.time || 0,
      reserved: data.reserved || 0,
      nonce: data.nonce || new BN(0),
      version: data.version || 0,
      size: data.size || new BN(0),
      height: data.height || 0,
      epochBlock: data.epochBlock || Buffer.alloc(32),
      merkleRoot: data.merkleRoot || Buffer.alloc(32),
      extendedMetadata: data.extendedMetadata || Buffer.alloc(32),
    }
  }

  /**
   * Create default header data (all zeroes).
   */
  private static _defaultData(): BlockHeaderData {
    return {
      prevHash: Buffer.alloc(32),
      bits: 0,
      time: 0,
      reserved: 0,
      nonce: new BN(0),
      version: 0,
      size: new BN(0),
      height: 0,
      epochBlock: Buffer.alloc(32),
      merkleRoot: Buffer.alloc(32),
      extendedMetadata: Buffer.alloc(32),
    }
  }

  /**
   * Read header fields from a BufferReader.
   * Order matches lotusd CBlockHeader serialization.
   */
  private static _readFromBuffer(br: BufferReader): BlockHeaderData {
    return {
      prevHash: br.read(32),
      bits: br.readUInt32LE(),
      time: br.readUInt48LE(),
      reserved: br.readUInt16LE(),
      nonce: br.readUInt64LEBN(),
      version: br.readUInt8(),
      size: br.readUInt56LEBN(),
      height: br.readUInt32LE(),
      epochBlock: br.read(32),
      merkleRoot: br.read(32),
      extendedMetadata: br.read(32),
    }
  }
}

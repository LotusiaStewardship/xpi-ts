import { Preconditions } from '../util/preconditions.js'
import { BufferUtil } from '../util/buffer.js'
import { BufferReader } from '../encoding/bufferreader.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { Hash } from '../crypto/hash.js'
import { JSUtil } from '../util/js.js'
import { BN } from '../crypto/bn.js'

const GENESIS_BITS = 0x1d00ffff

export interface BlockHeaderData {
  prevHash?: Buffer | string
  bits?: number
  time?: number
  timestamp?: number
  reserved?: number
  nonce?: BN
  version?: number
  size?: BN
  height?: number
  epochBlock?: Buffer | string
  merkleRoot?: Buffer | string
  extendedMetadata?: Buffer | string
  hash?: string
}

export interface BlockHeaderObject {
  hash: string
  prevHash: string
  bits: number
  time: number
  reserved: number
  nonce: string // Match reference: BN converted to string
  version: number
  size: number // Match reference: BN converted to number
  height: number
  epochBlock: string
  merkleRoot: string
  extendedMetadata: string
}

export class BlockHeader {
  // Constants structure to match reference
  static readonly Constants = {
    START_OF_HEADER: 0, // Start buffer position in raw block data
    MAX_TIME_OFFSET: 2 * 60 * 60, // The max a timestamp can be in the future
    LARGEST_HASH: new BN(
      '10000000000000000000000000000000000000000000000000000000000000000',
      'hex',
    ),
  }

  // Individual constants for backward compatibility
  static readonly START_OF_HEADER = 0 // Start buffer position in raw block data
  static readonly MAX_TIME_OFFSET = 2 * 60 * 60 // The max a timestamp can be in the future
  static readonly LARGEST_HASH = BigInt(
    '0x10000000000000000000000000000000000000000000000000000000000000000',
  )

  // Instance properties
  prevHash!: Buffer
  bits!: number
  time!: number
  timestamp!: number
  reserved!: number
  nonce!: BN
  version!: number
  size!: BN
  height!: number
  epochBlock!: Buffer
  merkleRoot!: Buffer
  extendedMetadata!: Buffer
  private _id?: string

  constructor(arg?: BlockHeaderData | BlockHeader) {
    if (arg instanceof BlockHeader) {
      return arg
    }

    // Initialize with default values
    this.prevHash = Buffer.alloc(32)
    this.bits = 0
    this.time = 0
    this.timestamp = 0
    this.reserved = 0
    this.nonce = new BN(0)
    this.version = 0
    this.size = new BN(0)
    this.height = 0
    this.epochBlock = Buffer.alloc(32)
    this.merkleRoot = Buffer.alloc(32)
    this.extendedMetadata = Buffer.alloc(32)

    if (arg && typeof arg === 'object') {
      const info = BlockHeader._from(arg)
      this.prevHash = info.prevHash as Buffer
      this.bits = info.bits!
      this.time = info.time!
      this.timestamp = info.time!
      this.reserved = info.reserved || 0
      this.nonce = info.nonce as BN
      this.version = info.version!
      this.size = info.size as BN
      this.height = info.height!
      this.epochBlock = info.epochBlock as Buffer
      this.merkleRoot = info.merkleRoot as Buffer
      this.extendedMetadata = info.extendedMetadata as Buffer

      if (info.hash) {
        Preconditions.checkState(
          this.hash === info.hash,
          'Argument object hash property does not match block hash.',
        )
      }
    }
  }

  /**
   * Create from various input types
   */
  private static _from(
    arg: BlockHeaderData | Buffer | string,
  ): BlockHeaderData {
    let info: BlockHeaderData = {}
    if (Buffer.isBuffer(arg)) {
      info = BlockHeader._fromBufferReader(new BufferReader(arg))
    } else if (typeof arg === 'string' && JSUtil.isHexa(arg)) {
      const buf = Buffer.from(arg, 'hex')
      info = BlockHeader._fromBufferReader(new BufferReader(buf))
    } else if (typeof arg === 'object' && arg !== null) {
      info = BlockHeader._fromObject(arg)
    } else {
      throw new TypeError('Unrecognized argument for BlockHeader')
    }
    return info
  }

  /**
   * Create from object
   */
  private static _fromObject(data: BlockHeaderData): BlockHeaderData {
    Preconditions.checkArgument(
      typeof data === 'object' && data !== null,
      'data is required',
    )

    let prevHash = data.prevHash
    let merkleRoot = data.merkleRoot
    let epochBlock = data.epochBlock
    let extendedMetadata = data.extendedMetadata
    let nonce = data.nonce
    let size = data.size

    if (typeof data.prevHash === 'string') {
      prevHash = BufferUtil.reverse(Buffer.from(data.prevHash, 'hex'))
    } else if (!Buffer.isBuffer(data.prevHash)) {
      prevHash = Buffer.alloc(32)
    }
    if (typeof data.merkleRoot === 'string') {
      merkleRoot = BufferUtil.reverse(Buffer.from(data.merkleRoot, 'hex'))
    } else if (!Buffer.isBuffer(data.merkleRoot)) {
      merkleRoot = Buffer.alloc(32)
    }
    if (typeof data.epochBlock === 'string') {
      epochBlock = BufferUtil.reverse(Buffer.from(data.epochBlock, 'hex'))
    } else if (!Buffer.isBuffer(data.epochBlock)) {
      epochBlock = Buffer.alloc(32)
    }
    if (typeof data.extendedMetadata === 'string') {
      extendedMetadata = BufferUtil.reverse(
        Buffer.from(data.extendedMetadata, 'hex'),
      )
    } else if (!Buffer.isBuffer(data.extendedMetadata)) {
      extendedMetadata = Buffer.alloc(32)
    }
    if (typeof data.nonce === 'string') {
      nonce = new BN(data.nonce, 10)
    } else if (typeof data.nonce === 'number') {
      nonce = new BN(data.nonce)
    } else if (data.nonce instanceof BN) {
      nonce = data.nonce
    } else {
      nonce = new BN(0)
    }
    if (typeof data.size === 'string') {
      size = new BN(data.size, 10)
    } else if (typeof data.size === 'number') {
      size = new BN(data.size)
    } else if (data.size instanceof BN) {
      size = data.size
    } else {
      size = new BN(0)
    }

    return {
      hash: data.hash,
      prevHash: prevHash as Buffer,
      bits: data.bits || 0,
      timestamp: data.time || data.timestamp || 0,
      reserved: data.reserved || 0,
      nonce: nonce as BN,
      version: data.version || 0,
      size: size as BN,
      height: data.height || 0,
      epochBlock: epochBlock as Buffer,
      merkleRoot: merkleRoot as Buffer,
      extendedMetadata: extendedMetadata as Buffer,
      time: data.time || data.timestamp || 0,
    }
  }

  /**
   * Create from object
   */
  static fromObject(obj: BlockHeaderData): BlockHeader {
    const info = BlockHeader._fromObject(obj)
    return new BlockHeader(info)
  }

  /**
   * Create from raw block data
   */
  static fromRawBlock(data: Buffer | string): BlockHeader {
    if (!Buffer.isBuffer(data)) {
      data = Buffer.from(data, 'binary')
    }
    const br = new BufferReader(data)
    br.pos = BlockHeader.Constants.START_OF_HEADER
    const info = BlockHeader._fromBufferReader(br)
    return new BlockHeader(info)
  }

  /**
   * Create from buffer
   */
  static fromBuffer(buf: Buffer): BlockHeader {
    const info = BlockHeader._fromBufferReader(new BufferReader(buf))
    return new BlockHeader(info)
  }

  /**
   * Create from hex string
   */
  static fromString(str: string): BlockHeader {
    const buf = Buffer.from(str, 'hex')
    return BlockHeader.fromBuffer(buf)
  }

  /**
   * Create from buffer reader
   */
  private static _fromBufferReader(br: BufferReader): BlockHeaderData {
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

  /**
   * Create from buffer reader
   */
  static fromBufferReader(br: BufferReader): BlockHeader {
    const info = BlockHeader._fromBufferReader(br)
    return new BlockHeader(info)
  }

  /**
   * Convert to object
   */
  toObject(): BlockHeaderObject {
    return {
      hash: this.hash,
      prevHash: BufferUtil.reverse(this.prevHash).toString('hex'),
      bits: this.bits,
      time: this.time,
      reserved: this.reserved,
      nonce: this.nonce.toString(10), // Match reference: convert BN to string
      version: this.version,
      size: this.size.toNumber(), // Match reference: convert BN to number
      height: this.height,
      epochBlock: BufferUtil.reverse(this.epochBlock).toString('hex'),
      merkleRoot: BufferUtil.reverse(this.merkleRoot).toString('hex'),
      extendedMetadata: BufferUtil.reverse(this.extendedMetadata).toString(
        'hex',
      ),
    }
  }

  /**
   * Convert to JSON
   */
  toJSON = this.toObject

  /**
   * Convert to buffer
   */
  toBuffer(): Buffer {
    return this.toBufferWriter().toBuffer()
  }

  /**
   * Convert to hex string
   */
  toString(): string {
    return this.toBuffer().toString('hex')
  }

  /**
   * Convert to buffer writer
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

  /**
   * Returns the target difficulty for this block
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
   * Get difficulty
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
   * Get the little endian hash buffer of the header
   */
  private _getHash(): Buffer {
    const layer3Hash = this._getLayer3Hash()
    const layer2Hash = this._getLayer2Hash(layer3Hash)

    const bw = new BufferWriter()
    bw.write(this.prevHash)
    bw.write(layer2Hash)

    return Hash.sha256(bw.toBuffer())
  }

  /**
   * Convert time to 6-byte array (block_time_t)
   */
  private _timeToBytes(): Buffer {
    const buf = Buffer.alloc(6)
    buf.writeUIntLE(this.time, 0, 6)
    return buf
  }

  /**
   * Convert size to 7-byte array (block_size_t)
   */
  private _sizeToBytes(): Buffer {
    const buf = Buffer.alloc(7)
    // Use BN's toBuffer method for little-endian 7-byte output
    const sizeBuffer = this.size.toArrayLike(Buffer, 'le', 7)
    sizeBuffer.copy(buf)
    return buf
  }

  /**
   * Get the little endian hash buffer of the layer3 of the header
   */
  private _getLayer3Hash(): Buffer {
    const bw = new BufferWriter()
    // Layer 3: nHeaderVersion, vSize, nHeight, hashEpochBlock, hashMerkleRoot, hashExtendedMetadata
    bw.writeUInt8(this.version) // nHeaderVersion
    bw.writeUInt56LEBN(this.size) // vSize (7 bytes) - use direct serialization like old bitcore-lib-xpi
    bw.writeUInt32LE(this.height) // nHeight
    bw.write(this.epochBlock) // hashEpochBlock
    bw.write(this.merkleRoot) // hashMerkleRoot
    bw.write(this.extendedMetadata) // hashExtendedMetadata

    return Hash.sha256(bw.toBuffer())
  }

  /**
   * Get the little endian hash buffer of the layer2 of the header
   */
  private _getLayer2Hash(layer3Hash: Buffer): Buffer {
    const bw = new BufferWriter()
    // Layer 2: nBits, vTime, nReserved, nNonce, layer3.GetSHA256()
    bw.writeUInt32LE(this.bits) // nBits
    bw.writeUInt48LE(this.time) // vTime (6 bytes) - use direct serialization like old bitcore-lib-xpi
    bw.writeUInt16LE(this.reserved) // nReserved
    bw.writeUInt64LEBN(this.nonce) // nNonce
    bw.write(layer3Hash) // layer3.GetSHA256()

    return Hash.sha256(bw.toBuffer())
  }

  /**
   * Get the big endian hash buffer of the header
   */
  get hash(): string {
    if (!this._id) {
      const hashBuffer = this._getHash()
      const reader = new BufferReader(hashBuffer)
      this._id = reader.readReverse(32).toString('hex')
    }
    return this._id
  }

  /**
   * Get the big endian hash buffer of the header (alias for hash)
   */
  get id(): string {
    return this.hash
  }

  /**
   * Check if timestamp is not too far in the future
   */
  validTimestamp(): boolean {
    const currentTime = Math.round(new Date().getTime() / 1000)
    if (this.time > currentTime + BlockHeader.Constants.MAX_TIME_OFFSET) {
      return false
    }
    return true
  }

  /**
   * Check if the proof-of-work hash satisfies the target difficulty
   */
  validProofOfWork(): boolean {
    const pow = new BN(this.id, 'hex') // Match reference: use 'hex' radix
    const target = this.getTargetDifficulty()

    if (pow.gt(target)) {
      // Use gt() method instead of cmp()
      return false
    }
    return true
  }

  /**
   * String representation for console
   */
  inspect(): string {
    return '<BlockHeader ' + this.id + '>'
  }
}

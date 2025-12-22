import { Preconditions } from '../util/preconditions.js'
import { BufferUtil } from '../util/buffer.js'
import { BufferReader } from '../encoding/bufferreader.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { Hash } from '../crypto/hash.js'
import { JSUtil } from '../util/js.js'
import { Transaction } from '../transaction/index.js'
import { BN } from '../crypto/bn.js'
import {
  BlockHeader,
  BlockHeaderData,
  BlockHeaderObject,
} from './blockheader.js'

export interface BlockData {
  header?: BlockHeader | BlockHeaderData
  metadata?: number
  transactions?: Transaction[]
}

export interface BlockObject {
  id: string
  hash: string
  header: BlockHeaderObject
  metadata: number
  transactions: unknown[]
}

export class Block {
  // Constants
  static readonly MAX_BLOCK_SIZE = 32 * 1024 * 1024 // 32MiB
  static readonly START_OF_BLOCK = 0 // Start of block in raw block data
  static readonly NULL_HASH = Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex',
  )

  // Values structure to match reference
  static readonly Values = {
    START_OF_BLOCK: 0, // Start of block in raw block data
    NULL_HASH: Buffer.from(
      '0000000000000000000000000000000000000000000000000000000000000000',
      'hex',
    ),
  }

  // Instance properties
  header!: BlockHeader
  metadata!: number
  transactions!: Transaction[]
  private _id?: string

  constructor(serialized?: BlockData | Block | Buffer | string) {
    if (!(this instanceof Block)) {
      return new Block(serialized)
    }

    if (serialized instanceof Block) {
      return Block.shallowCopy(serialized)
    } else if (typeof serialized === 'string' && JSUtil.isHexa(serialized)) {
      this.fromString(serialized)
    } else if (Buffer.isBuffer(serialized)) {
      this.fromBuffer(serialized)
    } else if (serialized && typeof serialized === 'object') {
      this.fromObject(serialized)
    } else {
      this._newBlock()
    }
  }

  /**
   * Create a 'shallow' copy of the block, by serializing and deserializing
   * it dropping any additional information that transactions may have hold
   */
  static shallowCopy(block: Block): Block {
    const copy = new Block(block.toBuffer())
    return copy
  }

  /**
   * Create from various input types
   */
  private static _from(arg: BlockData | Buffer | string): BlockData {
    let info: BlockData = {}
    if (Buffer.isBuffer(arg)) {
      info = Block._fromBufferReader(new BufferReader(arg))
    } else if (typeof arg === 'object' && arg !== null) {
      info = Block._fromObject(arg)
    } else {
      throw new TypeError('Unrecognized argument for Block')
    }
    return info
  }

  /**
   * Create from object
   */
  static fromObject(obj: BlockData): Block {
    const info = Block._fromObject(obj)
    return new Block(info)
  }

  /**
   * Create from buffer reader
   */
  static fromBufferReader(br: BufferReader): Block {
    Preconditions.checkArgument(br instanceof BufferReader, 'br is required')
    const info = Block._fromBufferReader(br)
    return new Block(info)
  }

  /**
   * Create from buffer
   */
  static fromBuffer(buf: Buffer): Block {
    return Block.fromBufferReader(new BufferReader(buf))
  }

  /**
   * Create from hex string
   */
  static fromString(str: string): Block {
    const buf = Buffer.from(str, 'hex')
    return Block.fromBuffer(buf)
  }

  /**
   * Create from raw block data
   */
  static fromRawBlock(data: Buffer | string): Block {
    if (!BufferUtil.isBuffer(data)) {
      data = Buffer.from(data, 'binary')
    }
    const br = new BufferReader(data)
    br.pos = Block.Values.START_OF_BLOCK
    const info = Block._fromBufferReader(br)
    return new Block(info)
  }

  /**
   * Create from object
   */
  private static _fromObject(data: BlockData): BlockData {
    const transactions: Transaction[] = []
    if (data.transactions) {
      data.transactions.forEach(tx => {
        if (tx instanceof Transaction) {
          transactions.push(tx)
        } else {
          transactions.push(new Transaction(tx))
        }
      })
    }

    return {
      header: data.header
        ? data.header instanceof BlockHeader
          ? data.header
          : new BlockHeader(data.header)
        : new BlockHeader(),
      metadata: data.metadata || 0x00,
      transactions: transactions,
    }
  }

  /**
   * Create from buffer reader
   */
  private static _fromBufferReader(br: BufferReader): BlockData {
    Preconditions.checkState(!br.finished(), 'No block data received')

    const header = BlockHeader.fromBufferReader(br)
    const metadata = br.readUInt8()
    const transactionCount = br.readVarintNum()
    const transactions: Transaction[] = []

    for (let i = 0; i < transactionCount; i++) {
      const tx = new Transaction()
      transactions.push(tx.fromBufferReader(br))
    }

    return {
      header,
      metadata,
      transactions,
    }
  }

  /**
   * Create new empty block
   */
  private _newBlock(): void {
    this.header = new BlockHeader()
    this.metadata = 0x00
    this.transactions = []
  }

  /**
   * Deserialize from buffer
   */
  fromBuffer(buf: Buffer): Block {
    const info = Block._fromBufferReader(new BufferReader(buf))
    this.header = info.header as BlockHeader
    this.metadata = info.metadata!
    this.transactions = info.transactions!
    return this
  }

  /**
   * Deserialize from hex string
   */
  fromString(str: string): Block {
    const buf = Buffer.from(str, 'hex')
    return this.fromBuffer(buf)
  }

  /**
   * Deserialize from object
   */
  fromObject(obj: BlockData): Block {
    const info = Block._fromObject(obj)
    this.header = info.header as BlockHeader
    this.metadata = info.metadata!
    this.transactions = info.transactions!
    return this
  }

  /**
   * Convert to object
   */
  toObject(): BlockObject {
    const transactions = this.transactions.map(tx => tx.toObject())
    return {
      id: this.id,
      hash: this.hash,
      header: this.header.toObject(),
      metadata: this.metadata,
      transactions: transactions,
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
    return this.toBufferWriter().concat()
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
    bw.write(this.header.toBuffer())
    bw.writeUInt8(this.metadata)
    bw.writeVarintNum(this.transactions.length)
    for (let i = 0; i < this.transactions.length; i++) {
      this.transactions[i].toBufferWriter(bw)
    }
    return bw
  }

  /**
   * Will iterate through each transaction and return an array of hashes
   */
  getTransactionHashes(): Buffer[] {
    const hashes: Buffer[] = []
    if (this.transactions.length === 0) {
      return [Block.Values.NULL_HASH]
    }
    for (let t = 0; t < this.transactions.length; t++) {
      const tx = this.transactions[t]
      const txid = (tx as unknown as { _getTxid(): Buffer })._getTxid()
      const hash = (tx as unknown as { _getHash(): Buffer })._getHash()
      const buf = Buffer.concat([hash, txid])
      const resultHash = Hash.sha256sha256(buf)
      hashes.push(resultHash)
    }
    return hashes
  }

  /**
   * Will build a merkle tree of all the transactions, ultimately arriving at
   * a single point, the merkle root.
   */
  getMerkleTree(): Buffer[] {
    const tree = this.getTransactionHashes()

    let j = 0
    for (let size = tree.length; size > 1; size = Math.floor(size / 2)) {
      if (size % 2 === 1) {
        tree.push(Block.Values.NULL_HASH)
        size += 1
      }
      for (let i = 0; i < size; i += 2) {
        const buf = Buffer.concat([tree[j + i], tree[j + i + 1]])
        tree.push(Hash.sha256sha256(buf))
      }
      j += size
    }

    return tree
  }

  /**
   * Calculates the merkleRoot from the transactions.
   */
  getMerkleRoot(): Buffer {
    const tree = this.getMerkleTree()
    return tree[tree.length - 1]
  }

  /**
   * Verifies that the transactions in the block match the header merkle root
   */
  validMerkleRoot(): boolean {
    const h = new BN(this.header.merkleRoot.toString('hex'), 'hex')
    const c = new BN(this.getMerkleRoot().toString('hex'), 'hex')

    if (!h.eq(c)) {
      return false
    }

    return true
  }

  /**
   * Get the little endian hash buffer of the header
   */
  private _getHash(): Buffer {
    const header = this.header as unknown as { _getHash(): Buffer }
    return header._getHash()
  }

  /**
   * Get the big endian hash buffer of the header
   */
  get hash(): string {
    if (!this._id) {
      this._id = this.header.id
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
   * String representation for console
   */
  inspect(): string {
    return '<Block ' + this.id + '>'
  }
}

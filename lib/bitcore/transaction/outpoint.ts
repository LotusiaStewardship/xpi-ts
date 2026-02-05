/**
 * COutPoint - A combination of a transaction hash and an index n into its vout
 *
 * Faithful TypeScript implementation of lotusd/src/primitives/transaction.h COutPoint.
 * An outpoint uniquely identifies a specific output of a previous transaction.
 *
 * Serialization format (36 bytes):
 *   - txid: 32 bytes (uint256, little-endian)
 *   - n: 4 bytes (uint32_t, little-endian)
 *
 * Reference: lotusd/src/primitives/transaction.h lines 22-54
 */

import { BufferReader } from '../encoding/bufferreader.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { BufferUtil } from '../util/buffer.js'
import type { Buffer } from 'buffer/'

/** Serialized size of an outpoint in bytes */
export const OUTPOINT_SIZE = 36

/**
 * Data for constructing an OutPoint from an object
 */
export interface OutPointData {
  /** Transaction ID as hex string (big-endian display order) */
  txid: string
  /** Output index within the transaction */
  outputIndex: number
}

/**
 * Serialized representation of an OutPoint
 */
export interface OutPointObject {
  /** Transaction ID as hex string (big-endian display order) */
  txid: string
  /** Output index within the transaction */
  outputIndex: number
}

/**
 * An outpoint - a combination of a transaction hash and an index n into its
 * vout.
 *
 * Reference: lotusd COutPoint (primitives/transaction.h)
 */
export class OutPoint {
  /**
   * Sentinel value for null output index.
   * Matches lotusd COutPoint::NULL_INDEX = std::numeric_limits<uint32_t>::max()
   */
  static readonly NULL_INDEX: number = 0xffffffff

  /** Transaction ID (32 bytes, stored as internal little-endian buffer) */
  private _txid: Buffer

  /** Output index within the transaction (uint32) */
  private _n: number

  /**
   * Create a new OutPoint
   *
   * @param txid - Transaction ID as 32-byte Buffer (little-endian) or hex string (big-endian display order)
   * @param n - Output index (uint32), defaults to NULL_INDEX
   */
  constructor(txid?: Buffer | string, n?: number) {
    if (txid === undefined) {
      // Default: null outpoint
      this._txid = BufferUtil.alloc(32, 0)
      this._n = OutPoint.NULL_INDEX
    } else if (BufferUtil.isBuffer(txid)) {
      if (txid.length !== 32) {
        throw new TypeError(
          `OutPoint txid buffer must be 32 bytes, got ${txid.length}`,
        )
      }
      this._txid = BufferUtil.from(txid)
      this._n = n !== undefined ? n >>> 0 : OutPoint.NULL_INDEX
    } else if (typeof txid === 'string') {
      if (txid.length !== 64) {
        throw new TypeError(
          `OutPoint txid hex string must be 64 characters, got ${txid.length}`,
        )
      }
      // Convert from big-endian display order to internal little-endian
      this._txid = BufferUtil.reverse(BufferUtil.from(txid, 'hex'))
      this._n = n !== undefined ? n >>> 0 : OutPoint.NULL_INDEX
    } else {
      throw new TypeError('OutPoint txid must be a Buffer or hex string')
    }
  }

  /**
   * Create an OutPoint from a data object
   *
   * @param data - Object with txid (hex string) and outputIndex
   * @returns New OutPoint instance
   */
  static fromObject(data: OutPointData): OutPoint {
    return new OutPoint(data.txid, data.outputIndex)
  }

  /**
   * Deserialize an OutPoint from a buffer
   *
   * @param buf - Buffer containing serialized outpoint (36 bytes)
   * @returns New OutPoint instance
   */
  static fromBuffer(buf: Buffer): OutPoint {
    const reader = new BufferReader(buf)
    return OutPoint.fromBufferReader(reader)
  }

  /**
   * Deserialize an OutPoint from a BufferReader
   *
   * Reads: txid (32 bytes LE) + n (4 bytes LE)
   * Matches lotusd SERIALIZE_METHODS(COutPoint, obj) { READWRITE(obj.txid, obj.n); }
   *
   * @param reader - BufferReader positioned at the outpoint data
   * @returns New OutPoint instance
   */
  static fromBufferReader(reader: BufferReader): OutPoint {
    const txidBuf = reader.read(32)
    const n = reader.readUInt32LE()
    const outpoint = new OutPoint()
    outpoint._txid = txidBuf
    outpoint._n = n
    return outpoint
  }

  /**
   * Check if this is a null outpoint (all-zero txid and NULL_INDEX)
   *
   * Matches lotusd: bool IsNull() const { return txid.IsNull() && n == NULL_INDEX; }
   */
  isNull(): boolean {
    return (
      this._n === OutPoint.NULL_INDEX && this._txid.every(byte => byte === 0)
    )
  }

  /**
   * Get the transaction ID as a hex string (big-endian display order)
   *
   * Matches lotusd: const TxId &GetTxId() const
   */
  getTxId(): string {
    return BufferUtil.reverse(this._txid).toString('hex')
  }

  /**
   * Get the transaction ID as a Buffer (internal little-endian)
   */
  getTxIdBuffer(): Buffer {
    return BufferUtil.from(this._txid)
  }

  /**
   * Get the output index
   *
   * Matches lotusd: uint32_t GetN() const
   */
  getN(): number {
    return this._n
  }

  /**
   * Serialize to a Buffer (36 bytes)
   *
   * Format: txid (32 bytes LE) + n (4 bytes LE)
   * Matches lotusd SERIALIZE_METHODS
   */
  toBuffer(): Buffer {
    const writer = new BufferWriter()
    this.toBufferWriter(writer)
    return writer.toBuffer()
  }

  /**
   * Write serialized outpoint to a BufferWriter
   *
   * @param writer - BufferWriter to write to
   * @returns The BufferWriter for chaining
   */
  toBufferWriter(writer: BufferWriter): BufferWriter {
    writer.write(this._txid)
    writer.writeUInt32LE(this._n)
    return writer
  }

  /**
   * Convert to a plain object
   */
  toObject(): OutPointObject {
    return {
      txid: this.getTxId(),
      outputIndex: this._n,
    }
  }

  /**
   * String representation matching lotusd COutPoint::ToString()
   *
   * Format: "COutPoint(txid_prefix, n)"
   */
  toString(): string {
    return `COutPoint(${this.getTxId().substring(0, 10)}, ${this._n})`
  }

  /**
   * Compare two outpoints for equality
   *
   * Matches lotusd: friend bool operator==(const COutPoint &a, const COutPoint &b)
   */
  equals(other: OutPoint): boolean {
    return this._txid.equals(other._txid) && this._n === other._n
  }

  /**
   * Compare two outpoints for ordering (less-than)
   *
   * Matches lotusd: friend bool operator<(const COutPoint &a, const COutPoint &b)
   */
  lessThan(other: OutPoint): boolean {
    const cmp = this._txid.compare(other._txid)
    return cmp < 0 || (cmp === 0 && this._n < other._n)
  }
}

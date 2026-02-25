/**
 * Variable integer encoding/decoding module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */
import { BufferWriter } from './bufferwriter'
import { BufferReader } from './bufferreader'
import { BN } from '../crypto/bn'
import { BufferUtil } from '../util'
import type { Buffer } from 'buffer/'

/**
 * Data interface for Varint construction.
 * Used when creating a Varint from an object with a buffer property.
 */
export interface VarintData {
  /** The buffer containing the varint-encoded data */
  buf?: Buffer
}

/**
 * Varint (Variable-length integer) class for encoding and decoding
 * variable-length integers used in Bitcoin protocol.
 *
 * Variable integers are used throughout the Bitcoin protocol to encode
 * lengths and counts. They can represent values from 0 to 2^64-1 using
 * 1 to 9 bytes depending on the magnitude of the value.
 *
 * Encoding scheme:
 * - 0x00-0xFC: 1 byte (value as-is)
 * - 0xFD followed by 2 bytes: values 0xFD to 0xFFFF (little-endian)
 * - 0xFE followed by 4 bytes: values 0x10000 to 0xFFFFFFFF (little-endian)
 * - 0xFF followed by 8 bytes: values 0x100000000 to 0xFFFFFFFFFFFFFFFF (little-endian)
 *
 * @example
 * // Create from number
 * const varint = new Varint(100)
 *
 * // Create from BN
 * const varint = new Varint(new BN(1000000))
 *
 * // Create from buffer
 * const varint = new Varint(buffer)
 *
 * // Convert to number
 * const num = varint.toNumber()
 *
 * // Convert to BN
 * const bn = varint.toBN()
 */
export class Varint {
  /**
   * The buffer containing the varint-encoded data.
   * Initialized to an empty buffer by default.
   */
  buf: Buffer = BufferUtil.alloc(0)

  constructor(buf?: Buffer | number | BN | VarintData) {
    if (BufferUtil.isBuffer(buf)) {
      this.buf = buf
    } else if (typeof buf === 'number') {
      const num = buf
      this.fromNumber(num)
    } else if (buf instanceof BN) {
      const bn = buf
      this.fromBN(bn)
    } else if (buf) {
      const obj = buf as VarintData
      this.set(obj)
    }
    // no "else" case required since this.buf is already set at property level
  }

  /**
   * Set the varint from a VarintData object
   * @param obj - Object containing buffer data
   * @returns This Varint instance for chaining
   */
  set(obj: VarintData): Varint {
    this.buf = obj.buf || this.buf
    return this
  }

  /**
   * Create a Varint from a hex string
   * @param str - Hex string representation of the varint
   * @returns This Varint instance for chaining
   */
  fromString(str: string): Varint {
    this.set({
      buf: BufferUtil.from(str, 'hex'),
    })
    return this
  }

  /**
   * Convert the varint to a hex string
   * @returns Hex string representation of the varint
   */
  toString(): string {
    return this.buf.toString('hex')
  }

  /**
   * Create a Varint from a buffer
   * @param buf - Buffer containing varint-encoded data
   * @returns This Varint instance for chaining
   */
  fromBuffer(buf: Buffer): Varint {
    this.buf = buf
    return this
  }

  /**
   * Create a Varint by reading from a BufferReader
   * @param br - BufferReader to read the varint from
   * @returns This Varint instance for chaining
   */
  fromBufferReader(br: BufferReader): Varint {
    this.buf = br.readVarintBuf()
    return this
  }

  /**
   * Create a Varint from a BN (big number)
   * @param bn - BN instance to encode as varint
   * @returns This Varint instance for chaining
   */
  fromBN(bn: BN): Varint {
    this.buf = BufferWriter.varintBufBN(bn)
    return this
  }

  /**
   * Create a Varint from a number
   * @param num - Number to encode as varint
   * @returns This Varint instance for chaining
   */
  fromNumber(num: number): Varint {
    this.buf = new BufferWriter().writeVarintNum(num).concat()
    return this
  }

  /**
   * Convert the varint to a buffer
   * @returns Buffer containing the varint-encoded data
   */
  toBuffer(): Buffer {
    return this.buf
  }

  /**
   * Convert the varint to a BN (big number)
   * @returns BN instance containing the decoded value
   */
  toBN(): BN {
    return new BufferReader(this.buf).readVarintBN()
  }

  /**
   * Convert the varint to a number
   * @returns The decoded varint value as a number
   * @throws {Error} If the value is too large to retain precision as a number
   */
  toNumber(): number {
    return new BufferReader(this.buf).readVarintNum()
  }
}

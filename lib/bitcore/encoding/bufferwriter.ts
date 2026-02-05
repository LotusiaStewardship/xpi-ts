/**
 * Buffer writer utility module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import { BufferUtil } from '../util/buffer'
import { BN } from '../crypto/bn'
import type { Buffer } from 'buffer/'

/**
 * Data structure for initializing a BufferWriter
 */
export interface BufferWriterData {
  /** Array of buffers to initialize with */
  bufs?: Buffer[]
}

/**
 * BufferWriter utility class for building binary data
 * Provides methods for writing various data types to a buffer
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */
export class BufferWriter {
  /** Array of buffers that have been written */
  bufs: Buffer[] = []
  /** Total length of all buffers combined */
  bufLen: number = 0

  /**
   * Create a new BufferWriter instance
   * @param obj - Optional initialization data
   */
  constructor(obj?: BufferWriterData) {
    this.bufLen = 0
    if (obj) {
      this.set(obj)
    } else {
      this.bufs = []
    }
  }

  /**
   * Factory function to allow calling BufferWriter() without 'new'
   * @param obj - Optional initialization data
   * @returns A new BufferWriter instance
   */
  static create(obj?: BufferWriterData): BufferWriter {
    return new BufferWriter(obj)
  }

  /**
   * Set the BufferWriter state from an object
   * @param obj - Object containing buffer data
   * @returns This BufferWriter instance for chaining
   */
  set(obj: BufferWriterData): BufferWriter {
    this.bufs = obj.bufs || this.bufs || []
    this.bufLen = this.bufs.reduce((prev, buf) => prev + buf.length, 0)
    return this
  }

  /**
   * Convert all written buffers to a single Buffer
   * @returns Concatenated buffer of all written data
   */
  toBuffer(): Buffer {
    return this.concat()
  }

  /**
   * Concatenate all buffers into a single Buffer
   * @returns Concatenated buffer of all written data
   */
  concat(): Buffer {
    return BufferUtil.concat(this.bufs, this.bufLen)
  }

  /**
   * Write a buffer to the writer
   * @param buf - Buffer to write
   * @returns This BufferWriter instance for chaining
   * @throws Error if buf is not a Buffer
   */
  write(buf: Buffer): BufferWriter {
    if (!BufferUtil.isBuffer(buf)) {
      throw new Error('Expected Buffer')
    }
    this.bufs.push(buf)
    this.bufLen += buf.length
    return this
  }

  /**
   * Write a buffer in reverse byte order
   * @param buf - Buffer to write reversed
   * @returns This BufferWriter instance for chaining
   * @throws Error if buf is not a Buffer
   */
  writeReverse(buf: Buffer): BufferWriter {
    if (!BufferUtil.isBuffer(buf)) {
      throw new Error('Expected Buffer')
    }
    this.bufs.push(BufferUtil.reverse(buf))
    this.bufLen += buf.length
    return this
  }

  /**
   * Write an unsigned 8-bit integer
   * @param n - Number to write (0-255)
   * @returns This BufferWriter instance for chaining
   */
  writeUInt8(n: number): BufferWriter {
    const buf = BufferUtil.alloc(1)
    buf.writeUInt8(n, 0)
    this.write(buf)
    return this
  }

  /**
   * Write an unsigned 16-bit integer in big-endian format
   * @param n - Number to write (0-65535)
   * @returns This BufferWriter instance for chaining
   */
  writeUInt16BE(n: number): BufferWriter {
    const buf = BufferUtil.alloc(2)
    buf.writeUInt16BE(n, 0)
    this.write(buf)
    return this
  }

  /**
   * Write an unsigned 16-bit integer in little-endian format
   * @param n - Number to write (0-65535)
   * @returns This BufferWriter instance for chaining
   */
  writeUInt16LE(n: number): BufferWriter {
    const buf = BufferUtil.alloc(2)
    buf.writeUInt16LE(n, 0)
    this.write(buf)
    return this
  }

  /**
   * Write an unsigned 32-bit integer in big-endian format
   * @param n - Number to write (0-4294967295)
   * @returns This BufferWriter instance for chaining
   */
  writeUInt32BE(n: number): BufferWriter {
    const buf = BufferUtil.alloc(4)
    buf.writeUInt32BE(n, 0)
    this.write(buf)
    return this
  }

  /**
   * Write a signed 32-bit integer in little-endian format
   * @param n - Number to write (-2147483648 to 2147483647)
   * @returns This BufferWriter instance for chaining
   */
  writeInt32LE(n: number): BufferWriter {
    const buf = BufferUtil.alloc(4)
    buf.writeInt32LE(n, 0)
    this.write(buf)
    return this
  }

  /**
   * Write an unsigned 32-bit integer in little-endian format
   * @param n - Number to write (0-4294967295)
   * @returns This BufferWriter instance for chaining
   */
  writeUInt32LE(n: number): BufferWriter {
    const buf = BufferUtil.alloc(4)
    buf.writeUInt32LE(n, 0)
    this.write(buf)
    return this
  }

  /**
   * Write an unsigned 48-bit integer in little-endian format
   * @param n - Number to write (0-281474976710655)
   * @returns This BufferWriter instance for chaining
   */
  writeUInt48LE(n: number): BufferWriter {
    const buf = BufferUtil.alloc(6)
    buf.writeUIntLE(n, 0, 6)
    this.write(buf)
    return this
  }

  /**
   * Write an unsigned 56-bit integer in little-endian format
   * @param n - Number to write
   * @returns This BufferWriter instance for chaining
   */
  writeUInt56LE(n: number): BufferWriter {
    const buf = BufferUtil.alloc(7)
    buf.writeUIntLE(n, 0, 7)
    this.write(buf)
    return this
  }

  /**
   * Write an unsigned 64-bit integer from a BN in big-endian format
   * @param bn - BN instance containing the number to write
   * @returns This BufferWriter instance for chaining
   */
  writeUInt64BEBN(bn: BN): BufferWriter {
    const buf = bn.toBuffer({ size: 8 })
    this.write(buf)
    return this
  }

  /**
   * Write an unsigned 56-bit integer from a BN in little-endian format
   * @param bn - BN instance containing the number to write
   * @returns This BufferWriter instance for chaining
   */
  writeUInt56LEBN(bn: BN): BufferWriter {
    const buf = bn.toBuffer({ size: 7 })
    this.writeReverse(buf)
    return this
  }

  /**
   * Write an unsigned 64-bit integer from a BN in little-endian format
   * @param bn - BN instance containing the number to write
   * @returns This BufferWriter instance for chaining
   */
  writeUInt64LEBN(bn: BN): BufferWriter {
    const buf = bn.toBuffer({ size: 8 })
    this.writeReverse(buf)
    return this
  }

  /**
   * Write an unsigned 64-bit integer from a BigInt in little-endian format
   * @param value - BigInt value to write
   * @returns This BufferWriter instance for chaining
   */
  writeUInt64LEBigInt(value: bigint): BufferWriter {
    const bn = new BN(value.toString())
    return this.writeUInt64LEBN(bn)
  }

  /**
   * Write an unsigned 32-bit integer from a BN in little-endian format
   * @param bn - BN instance containing the number to write
   * @returns This BufferWriter instance for chaining
   */
  writeUInt32LEBN(bn: BN): BufferWriter {
    const value = bn.toNumber()
    this.writeUInt32LE(value)
    return this
  }

  /**
   * Write an unsigned 32-bit integer from a number in little-endian format
   * @param value - Number to write
   * @returns This BufferWriter instance for chaining
   */
  writeUInt32LENumber(value: number): BufferWriter {
    this.writeUInt32LE(value)
    return this
  }

  /**
   * Write a variable-length integer (varint) from a number
   * @param n - Number to write as varint
   * @returns This BufferWriter instance for chaining
   */
  writeVarintNum(n: number): BufferWriter {
    const buf = BufferWriter.varintBufNum(n)
    this.write(buf)
    return this
  }

  /**
   * Write a variable-length integer (varint) from a BN
   * @param bn - BN instance to write as varint
   * @returns This BufferWriter instance for chaining
   */
  writeVarintBN(bn: BN): BufferWriter {
    const buf = BufferWriter.varintBufBN(bn)
    this.write(buf)
    return this
  }

  /**
   * Write a length-prefixed buffer (varint length followed by data)
   * @param buf - Buffer to write with length prefix
   * @returns This BufferWriter instance for chaining
   */
  writeVarLengthBuffer(buf: Buffer): BufferWriter {
    this.writeVarintNum(buf.length)
    this.write(buf)
    return this
  }

  /**
   * Create a varint buffer from a number
   * @param n - Number to encode as varint
   * @returns Buffer containing the varint-encoded number
   */
  static varintBufNum(n: number): Buffer {
    let buf: Buffer
    if (n < 253) {
      buf = BufferUtil.alloc(1)
      buf.writeUInt8(n, 0)
    } else if (n < 0x10000) {
      buf = BufferUtil.alloc(1 + 2)
      buf.writeUInt8(253, 0)
      buf.writeUInt16LE(n, 1)
    } else if (n < 0x100000000) {
      buf = BufferUtil.alloc(1 + 4)
      buf.writeUInt8(254, 0)
      buf.writeUInt32LE(n, 1)
    } else {
      buf = BufferUtil.alloc(1 + 8)
      buf.writeUInt8(255, 0)
      buf.writeInt32LE(n & -1, 1)
      buf.writeUInt32LE(Math.floor(n / 0x100000000), 5)
    }
    return buf
  }

  /**
   * Create a varint buffer from a BN
   * @param bn - BN instance to encode as varint
   * @returns Buffer containing the varint-encoded number
   */
  static varintBufBN(bn: BN): Buffer {
    const n = bn.toNumber()
    if (n < 253) {
      const buf = BufferUtil.alloc(1)
      buf.writeUInt8(n, 0)
      return buf
    } else if (n < 0x10000) {
      const buf = BufferUtil.alloc(1 + 2)
      buf.writeUInt8(253, 0)
      buf.writeUInt16LE(n, 1)
      return buf
    } else if (n < 0x100000000) {
      const buf = BufferUtil.alloc(1 + 4)
      buf.writeUInt8(254, 0)
      buf.writeUInt32LE(n, 1)
      return buf
    } else {
      const bw = new BufferWriter()
      bw.writeUInt8(255)
      bw.writeUInt64LEBN(bn)
      return bw.concat()
    }
  }
}

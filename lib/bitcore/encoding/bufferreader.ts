import { Preconditions } from '../util/preconditions'
import { BN } from '../crypto/bn'
import { BufferUtil } from '../util/buffer'
import type { Buffer } from 'buffer/'

export interface BufferReaderData {
  buf?: Buffer
  pos?: number
}

/**
 * BufferReader class for reading binary data from a buffer
 * Provides methods to read various data types in different byte orders
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */
export class BufferReader {
  /** The underlying buffer being read */
  buf!: Buffer
  /** Current position in the buffer */
  pos: number = 0

  /**
   * Create a new BufferReader instance
   * @param buf - Buffer, hex string, or BufferReaderData object to read from
   * @throws {TypeError} If the argument is not a valid buffer, hex string, or object
   */
  constructor(buf?: Buffer | string | BufferReaderData) {
    if (buf === undefined) {
      return
    }
    if (BufferUtil.isBuffer(buf)) {
      this.set({
        buf: buf,
      })
    } else if (typeof buf === 'string') {
      const b = BufferUtil.from(buf, 'hex')
      if (b.length * 2 !== buf.length) {
        throw new TypeError('Invalid hex string')
      }

      this.set({
        buf: b,
      })
    } else if (typeof buf === 'object' && buf !== null) {
      const obj = buf as BufferReaderData
      this.set(obj)
    } else {
      throw new TypeError('Unrecognized argument for BufferReader')
    }
  }

  /**
   * Factory function to create a BufferReader without using 'new'
   * @param buf - Buffer, hex string, or BufferReaderData object to read from
   * @returns A new BufferReader instance
   */
  static create(buf?: Buffer | string | BufferReaderData): BufferReader {
    return new BufferReader(buf)
  }

  /**
   * Set the buffer and position from a BufferReaderData object
   * @param obj - Object containing buf and/or pos properties
   * @returns This BufferReader instance for chaining
   */
  set(obj: BufferReaderData): BufferReader {
    this.buf = obj.buf || this.buf || undefined
    this.pos = obj.pos || this.pos || 0
    return this
  }

  /**
   * Check if the reader has reached the end of the buffer
   * @returns True if position is at or past the end of the buffer
   */
  eof(): boolean {
    return this.pos >= this.buf.length
  }

  /**
   * Alias for eof() - check if reading is finished
   * @returns True if position is at or past the end of the buffer
   */
  finished(): boolean {
    return this.eof()
  }

  /**
   * Read a specified number of bytes from the buffer
   * @param len - Number of bytes to read
   * @returns Buffer containing the read bytes
   * @throws {Error} If len is undefined
   */
  read(len: number): Buffer {
    Preconditions.checkArgument(
      len !== undefined,
      'len',
      'Must specify a length',
    )
    const buf = this.buf.slice(this.pos, this.pos + len)
    this.pos = this.pos + len
    return buf
  }

  /**
   * Read all remaining bytes from the buffer
   * @returns Buffer containing all remaining bytes
   */
  readAll(): Buffer {
    const buf = this.buf.slice(this.pos, this.buf.length)
    this.pos = this.buf.length
    return buf
  }

  /**
   * Read an unsigned 8-bit integer
   * @returns The unsigned 8-bit integer value
   */
  readUInt8(): number {
    const val = this.buf.readUInt8(this.pos)
    this.pos = this.pos + 1
    return val
  }

  /**
   * Read an unsigned 16-bit integer in big-endian format
   * @returns The unsigned 16-bit integer value
   */
  readUInt16BE(): number {
    const val = this.buf.readUInt16BE(this.pos)
    this.pos = this.pos + 2
    return val
  }

  /**
   * Read an unsigned 16-bit integer in little-endian format
   * @returns The unsigned 16-bit integer value
   */
  readUInt16LE(): number {
    const val = this.buf.readUInt16LE(this.pos)
    this.pos = this.pos + 2
    return val
  }

  /**
   * Read an unsigned 32-bit integer in big-endian format
   * @returns The unsigned 32-bit integer value
   */
  readUInt32BE(): number {
    const val = this.buf.readUInt32BE(this.pos)
    this.pos = this.pos + 4
    return val
  }

  /**
   * Read an unsigned 32-bit integer in little-endian format
   * @returns The unsigned 32-bit integer value
   */
  readUInt32LE(): number {
    const val = this.buf.readUInt32LE(this.pos)
    this.pos = this.pos + 4
    return val
  }

  /**
   * Read an unsigned 48-bit integer in little-endian format
   * @returns The unsigned 48-bit integer value
   */
  readUInt48LE(): number {
    const val = this.buf.readUIntLE(this.pos, 6)
    this.pos = this.pos + 6
    return val
  }

  /**
   * Read an unsigned 56-bit integer in little-endian format as a BN
   * @returns BN instance containing the 56-bit value
   */
  readUInt56LEBN(): BN {
    const buf = this.buf.slice(this.pos, this.pos + 7)
    const bn = BN.fromBuffer(buf, { endian: 'little' })
    this.pos = this.pos + 7
    return bn
  }

  /**
   * Read a signed 32-bit integer in little-endian format
   * @returns The signed 32-bit integer value
   */
  readInt32LE(): number {
    const val = this.buf.readInt32LE(this.pos)
    this.pos = this.pos + 4
    return val
  }

  /**
   * Read an unsigned 64-bit integer in big-endian format as a BN
   * @returns BN instance containing the 64-bit value
   */
  readUInt64BEBN(): BN {
    const buf = this.buf.slice(this.pos, this.pos + 8)
    const bn = BN.fromBuffer(buf)
    this.pos = this.pos + 8
    return bn
  }

  /**
   * Read an unsigned 64-bit integer in little-endian format as a BN
   * Uses optimized path for values that fit in JavaScript's safe integer range
   * @returns BN instance containing the 64-bit value
   */
  readUInt64LEBN(): BN {
    const second = this.buf.readUInt32LE(this.pos)
    const first = this.buf.readUInt32LE(this.pos + 4)
    const combined = first * 0x100000000 + second
    // Instantiating an instance of BN with a number is faster than with an
    // array or string. However, the maximum safe number for a double precision
    // floating point is 2 ^ 52 - 1 (0x1fffffffffffff), thus we can safely use
    // non-floating point numbers less than this amount (52 bits). And in the case
    // that the number is larger, we can instatiate an instance of BN by passing
    // an array from the buffer (slower) and specifying the endianness.
    let bn: BN
    if (combined <= 0x1fffffffffffff) {
      bn = new BN(combined)
    } else {
      const data = Array.prototype.slice.call(this.buf, this.pos, this.pos + 8)
      bn = new BN(BufferUtil.from(data), 'le')
    }
    this.pos = this.pos + 8
    return bn
  }

  /**
   * Read an unsigned 32-bit integer in little-endian format as a BN
   * @returns BN instance containing the 32-bit value
   */
  readUInt32LEBN(): BN {
    const value = this.buf.readUInt32LE(this.pos)
    this.pos = this.pos + 4
    return new BN(value)
  }

  /**
   * Read a variable-length integer (varint) as a number
   * @returns The varint value as a number
   * @throws {Error} If the value is too large to retain precision as a number
   */
  readVarintNum(): number {
    const first = this.readUInt8()
    switch (first) {
      case 0xfd:
        return this.readUInt16LE()
      case 0xfe:
        return this.readUInt32LE()
      case 0xff: {
        const bn = this.readUInt64LEBN()
        const n = Number(bn)
        if (n <= Math.pow(2, 53)) {
          return n
        } else {
          throw new Error(
            'number too large to retain precision - use readVarintBN',
          )
        }
      }
      default:
        return first
    }
  }

  /**
   * Read a length-prepended buffer where the length is encoded as a varint
   * @returns Buffer containing the data
   * @throws {Error} If the read buffer length doesn't match the expected length
   */
  readVarLengthBuffer(): Buffer {
    const len = this.readVarintNum()
    const buf = this.read(len)
    Preconditions.checkState(
      buf.length === len,
      'Invalid length while reading varlength buffer. ' +
        'Expected to read: ' +
        len +
        ' and read ' +
        buf.length,
    )
    return buf
  }

  /**
   * Read a varint as a raw buffer including the prefix byte
   * @returns Buffer containing the varint bytes
   */
  readVarintBuf(): Buffer {
    const first = this.buf.readUInt8(this.pos)
    switch (first) {
      case 0xfd:
        return this.read(1 + 2)
      case 0xfe:
        return this.read(1 + 4)
      case 0xff:
        return this.read(1 + 8)
      default:
        return this.read(1)
    }
  }

  /**
   * Read a variable-length integer (varint) as a BN
   * @returns BN instance containing the varint value
   */
  readVarintBN(): BN {
    const first = this.readUInt8()
    switch (first) {
      case 0xfd:
        return new BN(this.readUInt16LE())
      case 0xfe:
        return new BN(this.readUInt32LE())
      case 0xff:
        return this.readUInt64LEBN()
      default:
        return new BN(first)
    }
  }

  /**
   * Reverse the entire buffer in place
   * @returns This BufferReader instance for chaining
   */
  reverse(): BufferReader {
    const buf = BufferUtil.alloc(this.buf.length)
    for (let i = 0; i < buf.length; i++) {
      buf[i] = this.buf[this.buf.length - 1 - i]
    }
    this.buf = buf
    return this
  }

  /**
   * Read bytes and return them in reversed order
   * @param len - Number of bytes to read (defaults to remaining buffer length)
   * @returns Buffer containing the read bytes in reversed order
   */
  readReverse(len?: number): Buffer {
    if (len === undefined) {
      len = this.buf.length
    }
    const buf = this.buf.slice(this.pos, this.pos + len)
    this.pos = this.pos + len
    return BufferUtil.reverse(buf)
  }
}

/**
 * Buffer reader utility module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import { Preconditions } from '../util/preconditions.js'
import { BN } from '../crypto/bn.js'
import { BufferUtil } from '../util/buffer.js'

export interface BufferReaderData {
  buf?: Buffer
  pos?: number
}

export class BufferReader {
  buf!: Buffer
  pos: number = 0

  constructor(buf?: Buffer | string | BufferReaderData) {
    if (buf === undefined) {
      return
    }
    if (Buffer.isBuffer(buf)) {
      this.set({
        buf: buf,
      })
    } else if (typeof buf === 'string') {
      const b = Buffer.from(buf, 'hex')
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

  // Factory function to allow calling BufferReader() without 'new'
  static create(buf?: Buffer | string | BufferReaderData): BufferReader {
    return new BufferReader(buf)
  }

  set(obj: BufferReaderData): BufferReader {
    this.buf = obj.buf || this.buf || undefined
    this.pos = obj.pos || this.pos || 0
    return this
  }

  eof(): boolean {
    return this.pos >= this.buf.length
  }

  finished(): boolean {
    return this.eof()
  }

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

  readAll(): Buffer {
    const buf = this.buf.slice(this.pos, this.buf.length)
    this.pos = this.buf.length
    return buf
  }

  readUInt8(): number {
    const val = this.buf.readUInt8(this.pos)
    this.pos = this.pos + 1
    return val
  }

  readUInt16BE(): number {
    const val = this.buf.readUInt16BE(this.pos)
    this.pos = this.pos + 2
    return val
  }

  readUInt16LE(): number {
    const val = this.buf.readUInt16LE(this.pos)
    this.pos = this.pos + 2
    return val
  }

  readUInt32BE(): number {
    const val = this.buf.readUInt32BE(this.pos)
    this.pos = this.pos + 4
    return val
  }

  readUInt32LE(): number {
    const val = this.buf.readUInt32LE(this.pos)
    this.pos = this.pos + 4
    return val
  }

  readUInt48LE(): number {
    const val = this.buf.readUIntLE(this.pos, 6)
    this.pos = this.pos + 6
    return val
  }

  readUInt56LEBN(): BN {
    const buf = this.buf.slice(this.pos, this.pos + 7)
    const bn = BN.fromBuffer(buf, { endian: 'little' })
    this.pos = this.pos + 7
    return bn
  }

  readInt32LE(): number {
    const val = this.buf.readInt32LE(this.pos)
    this.pos = this.pos + 4
    return val
  }

  readUInt64BEBN(): BN {
    const buf = this.buf.slice(this.pos, this.pos + 8)
    const bn = BN.fromBuffer(buf)
    this.pos = this.pos + 8
    return bn
  }

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
      bn = new BN(Buffer.from(data), 'le')
    }
    this.pos = this.pos + 8
    return bn
  }

  readUInt32LEBN(): BN {
    const value = this.buf.readUInt32LE(this.pos)
    this.pos = this.pos + 4
    return new BN(value)
  }

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
   * reads a length prepended buffer
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

  reverse(): BufferReader {
    const buf = Buffer.alloc(this.buf.length)
    for (let i = 0; i < buf.length; i++) {
      buf[i] = this.buf[this.buf.length - 1 - i]
    }
    this.buf = buf
    return this
  }

  readReverse(len?: number): Buffer {
    if (len === undefined) {
      len = this.buf.length
    }
    const buf = this.buf.slice(this.pos, this.pos + len)
    this.pos = this.pos + len
    return BufferUtil.reverse(buf)
  }
}

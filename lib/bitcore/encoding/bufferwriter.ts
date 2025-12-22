/**
 * Buffer writer utility module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import { BufferUtil } from '../util/buffer.js'
import { BN } from '../crypto/bn.js'

export interface BufferWriterData {
  bufs?: Buffer[]
}

export class BufferWriter {
  bufs: Buffer[] = []
  bufLen: number = 0

  constructor(obj?: BufferWriterData) {
    this.bufLen = 0
    if (obj) {
      this.set(obj)
    } else {
      this.bufs = []
    }
  }

  // Factory function to allow calling BufferWriter() without 'new'
  static create(obj?: BufferWriterData): BufferWriter {
    return new BufferWriter(obj)
  }

  set(obj: BufferWriterData): BufferWriter {
    this.bufs = obj.bufs || this.bufs || []
    this.bufLen = this.bufs.reduce((prev, buf) => prev + buf.length, 0)
    return this
  }

  toBuffer(): Buffer {
    return this.concat()
  }

  concat(): Buffer {
    return Buffer.concat(this.bufs, this.bufLen)
  }

  write(buf: Buffer): BufferWriter {
    if (!BufferUtil.isBuffer(buf)) {
      throw new Error('Expected Buffer')
    }
    this.bufs.push(buf)
    this.bufLen += buf.length
    return this
  }

  writeReverse(buf: Buffer): BufferWriter {
    if (!BufferUtil.isBuffer(buf)) {
      throw new Error('Expected Buffer')
    }
    this.bufs.push(BufferUtil.reverse(buf))
    this.bufLen += buf.length
    return this
  }

  writeUInt8(n: number): BufferWriter {
    const buf = Buffer.alloc(1)
    buf.writeUInt8(n, 0)
    this.write(buf)
    return this
  }

  writeUInt16BE(n: number): BufferWriter {
    const buf = Buffer.alloc(2)
    buf.writeUInt16BE(n, 0)
    this.write(buf)
    return this
  }

  writeUInt16LE(n: number): BufferWriter {
    const buf = Buffer.alloc(2)
    buf.writeUInt16LE(n, 0)
    this.write(buf)
    return this
  }

  writeUInt32BE(n: number): BufferWriter {
    const buf = Buffer.alloc(4)
    buf.writeUInt32BE(n, 0)
    this.write(buf)
    return this
  }

  writeInt32LE(n: number): BufferWriter {
    const buf = Buffer.alloc(4)
    buf.writeInt32LE(n, 0)
    this.write(buf)
    return this
  }

  writeUInt32LE(n: number): BufferWriter {
    const buf = Buffer.alloc(4)
    buf.writeUInt32LE(n, 0)
    this.write(buf)
    return this
  }

  writeUInt48LE(n: number): BufferWriter {
    const buf = Buffer.alloc(6)
    buf.writeUIntLE(n, 0, 6)
    this.write(buf)
    return this
  }

  writeUInt56LE(n: number): BufferWriter {
    const buf = Buffer.alloc(7)
    buf.writeUIntLE(n, 0, 7)
    this.write(buf)
    return this
  }

  writeUInt64BEBN(bn: BN): BufferWriter {
    const buf = bn.toBuffer({ size: 8 })
    this.write(buf)
    return this
  }

  writeUInt56LEBN(bn: BN): BufferWriter {
    const buf = bn.toBuffer({ size: 7 })
    this.writeReverse(buf)
    return this
  }

  writeUInt64LEBN(bn: BN): BufferWriter {
    const buf = bn.toBuffer({ size: 8 })
    this.writeReverse(buf)
    return this
  }

  writeUInt64LEBigInt(value: bigint): BufferWriter {
    const bn = new BN(value.toString())
    return this.writeUInt64LEBN(bn)
  }

  writeUInt32LEBN(bn: BN): BufferWriter {
    const value = bn.toNumber()
    this.writeUInt32LE(value)
    return this
  }

  writeUInt32LENumber(value: number): BufferWriter {
    this.writeUInt32LE(value)
    return this
  }

  writeVarintNum(n: number): BufferWriter {
    const buf = BufferWriter.varintBufNum(n)
    this.write(buf)
    return this
  }

  writeVarintBN(bn: BN): BufferWriter {
    const buf = BufferWriter.varintBufBN(bn)
    this.write(buf)
    return this
  }

  writeVarLengthBuffer(buf: Buffer): BufferWriter {
    this.writeVarintNum(buf.length)
    this.write(buf)
    return this
  }

  static varintBufNum(n: number): Buffer {
    let buf: Buffer
    if (n < 253) {
      buf = Buffer.alloc(1)
      buf.writeUInt8(n, 0)
    } else if (n < 0x10000) {
      buf = Buffer.alloc(1 + 2)
      buf.writeUInt8(253, 0)
      buf.writeUInt16LE(n, 1)
    } else if (n < 0x100000000) {
      buf = Buffer.alloc(1 + 4)
      buf.writeUInt8(254, 0)
      buf.writeUInt32LE(n, 1)
    } else {
      buf = Buffer.alloc(1 + 8)
      buf.writeUInt8(255, 0)
      buf.writeInt32LE(n & -1, 1)
      buf.writeUInt32LE(Math.floor(n / 0x100000000), 5)
    }
    return buf
  }

  static varintBufBN(bn: BN): Buffer {
    const n = bn.toNumber()
    if (n < 253) {
      const buf = Buffer.alloc(1)
      buf.writeUInt8(n, 0)
      return buf
    } else if (n < 0x10000) {
      const buf = Buffer.alloc(1 + 2)
      buf.writeUInt8(253, 0)
      buf.writeUInt16LE(n, 1)
      return buf
    } else if (n < 0x100000000) {
      const buf = Buffer.alloc(1 + 4)
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

// Factory function to allow calling BufferWriter() without 'new'
export function BufferWriterFactory(obj?: BufferWriterData): BufferWriter {
  return new BufferWriter(obj)
}

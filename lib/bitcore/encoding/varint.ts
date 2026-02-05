/**
 * Variable integer encoding/decoding module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */
import { BufferWriter } from './bufferwriter'
import { BufferReader } from './bufferreader'
import { BN } from '../crypto/bn'
import { BufferUtil } from '../util'
import type { Buffer } from 'buffer/'

export interface VarintData {
  buf?: Buffer
}

export class Varint {
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
  }

  set(obj: VarintData): Varint {
    this.buf = obj.buf || this.buf
    return this
  }

  fromString(str: string): Varint {
    this.set({
      buf: BufferUtil.from(str, 'hex'),
    })
    return this
  }

  toString(): string {
    return this.buf.toString('hex')
  }

  fromBuffer(buf: Buffer): Varint {
    this.buf = buf
    return this
  }

  fromBufferReader(br: BufferReader): Varint {
    this.buf = br.readVarintBuf()
    return this
  }

  fromBN(bn: BN): Varint {
    this.buf = BufferWriter.varintBufBN(bn)
    return this
  }

  fromNumber(num: number): Varint {
    this.buf = new BufferWriter().writeVarintNum(num).concat()
    return this
  }

  toBuffer(): Buffer {
    return this.buf
  }

  toBN(): BN {
    return new BufferReader(this.buf).readVarintBN()
  }

  toNumber(): number {
    return new BufferReader(this.buf).readVarintNum()
  }
}

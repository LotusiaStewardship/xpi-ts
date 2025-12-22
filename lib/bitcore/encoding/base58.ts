/**
 * Base58 encoding/decoding module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

// Need to use the require syntax to load bs58 in cjs
// eslint-disable-next-line @typescript-eslint/no-require-imports
//const bs58 = require('bs58').default

import bs58 from 'bs58'

const ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.split('')

export interface Base58Data {
  buf?: Buffer
}

export class Base58 {
  buf?: Buffer

  constructor(obj?: Buffer | string | Base58Data) {
    if (Buffer.isBuffer(obj)) {
      const buf = obj
      this.fromBuffer(buf)
    } else if (typeof obj === 'string') {
      const str = obj
      this.fromString(str)
    } else if (obj) {
      this.set(obj)
    }
  }

  static validCharacters(chars: string | Buffer): boolean {
    if (Buffer.isBuffer(chars)) {
      chars = chars.toString()
    }
    return Array.from(chars).every(char => ALPHABET.includes(char))
  }

  set(obj: Base58Data): Base58 {
    this.buf = obj.buf || this.buf || undefined
    return this
  }

  static encode(buf: Buffer): string {
    if (!Buffer.isBuffer(buf)) {
      throw new Error('Input should be a buffer')
    }
    return bs58.encode(buf)
  }

  static decode(str: string): Buffer {
    if (typeof str !== 'string') {
      throw new Error('Input should be a string')
    }
    return Buffer.from(bs58.decode(str))
  }

  fromBuffer(buf: Buffer): Base58 {
    this.buf = buf
    return this
  }

  fromString(str: string): Base58 {
    const buf = Base58.decode(str)
    this.buf = buf
    return this
  }

  toBuffer(): Buffer {
    return this.buf!
  }

  toString(): string {
    return Base58.encode(this.buf!)
  }
}

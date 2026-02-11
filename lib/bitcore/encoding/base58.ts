/**
 * Base58 encoding/decoding module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import bs58 from 'bs58'
import { BufferUtil } from '../util'
import type { Buffer } from 'buffer/'

const ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.split('')

export interface Base58Data {
  buf?: Buffer
}

/**
 * Base58 encoding/decoding class
 *
 * Provides utilities for encoding and decoding data using Base58 encoding,
 * which is commonly used in Lotus and other cryptocurrencies for addresses
 * and other data that needs to be human-readable.
 *
 * @example
 * // Encode a buffer to Base58 string
 * const encoded = Base58.encode(Buffer.from('hello'))
 *
 * @example
 * // Decode a Base58 string to buffer
 * const decoded = Base58.decode('Cn8eVZg')
 *
 * @example
 * // Create instance from buffer
 * const b58 = new Base58(Buffer.from('hello'))
 * console.log(b58.toString())
 */
export class Base58 {
  buf?: Buffer

  /**
   * Creates a new Base58 instance
   * @param obj - Optional input: Buffer to encode, Base58 string to decode, or Base58Data object
   */
  constructor(obj?: Buffer | string | Base58Data) {
    if (BufferUtil.isBuffer(obj)) {
      const buf = obj
      this.fromBuffer(buf)
    } else if (typeof obj === 'string') {
      const str = obj
      this.fromString(str)
    } else if (obj) {
      this.set(obj)
    }
  }

  /**
   * Validates that all characters in the input are valid Base58 characters
   * @param chars - String or Buffer to validate
   * @returns True if all characters are valid Base58 characters
   */
  static validCharacters(chars: string | Buffer): boolean {
    if (BufferUtil.isBuffer(chars)) {
      chars = chars.toString()
    }
    return Array.from(chars).every(char => ALPHABET.includes(char))
  }

  /**
   * Sets the internal buffer from a Base58Data object
   * @param obj - Object containing buffer data
   * @returns This Base58 instance for chaining
   */
  set(obj: Base58Data): Base58 {
    this.buf = obj.buf || this.buf || undefined
    return this
  }

  /**
   * Encodes a buffer to a Base58 string
   * @param buf - Buffer to encode
   * @returns Base58 encoded string
   * @throws Error if input is not a Buffer
   */
  static encode(buf: Buffer): string {
    if (!BufferUtil.isBuffer(buf)) {
      throw new Error('Input should be a buffer')
    }
    return bs58.encode(buf)
  }

  /**
   * Decodes a Base58 string to a buffer
   * @param str - Base58 encoded string to decode
   * @returns Decoded buffer
   * @throws Error if input is not a string
   */
  static decode(str: string): Buffer {
    if (typeof str !== 'string') {
      throw new Error('Input should be a string')
    }
    return BufferUtil.from(bs58.decode(str))
  }

  /**
   * Sets the internal buffer from a Buffer
   * @param buf - Buffer to store
   * @returns This Base58 instance for chaining
   */
  fromBuffer(buf: Buffer): Base58 {
    this.buf = buf
    return this
  }

  /**
   * Decodes a Base58 string and stores the result in the internal buffer
   * @param str - Base58 encoded string to decode
   * @returns This Base58 instance for chaining
   */
  fromString(str: string): Base58 {
    const buf = Base58.decode(str)
    this.buf = buf
    return this
  }

  /**
   * Returns the internal buffer
   * @returns The stored buffer
   */
  toBuffer(): Buffer {
    return this.buf!
  }

  /**
   * Encodes the internal buffer to a Base58 string
   * @returns Base58 encoded string
   */
  toString(): string {
    return Base58.encode(this.buf!)
  }
}

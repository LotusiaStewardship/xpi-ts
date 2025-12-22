/**
 * Base58Check encoding/decoding utilities
 * Migrated from bitcore-lib-xpi with ESM support
 *
 * Uses @noble/hashes for browser compatibility
 */

import { sha256 } from '@noble/hashes/sha256'

// Base58 alphabet
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const ALPHABET_MAP: Record<string, number> = {}

// Build alphabet map
for (let i = 0; i < ALPHABET.length; i++) {
  ALPHABET_MAP[ALPHABET[i]] = i
}

export class Base58Check {
  /**
   * Encode a buffer to Base58Check
   */
  static encode(buf: Buffer): string {
    if (!Buffer.isBuffer(buf)) {
      throw new Error('Input must be a Buffer')
    }

    // Add checksum
    const checksum = this.checksum(buf)
    const payload = Buffer.concat([buf, checksum])

    return this.base58Encode(payload)
  }

  /**
   * Decode a Base58Check string to buffer
   */
  static decode(str: string): Buffer {
    if (typeof str !== 'string') {
      throw new Error('Input must be a string')
    }

    const buf = this.base58Decode(str)

    if (buf.length < 4) {
      throw new Error('Input string too short')
    }

    const data = buf.subarray(0, -4)
    const checksum = buf.subarray(-4)

    if (!this.validChecksum(data, checksum)) {
      throw new Error('Invalid checksum')
    }

    return data
  }

  /**
   * Calculate checksum for data
   */
  static checksum(data: Buffer): Buffer {
    const hash1 = sha256(data)
    const hash2 = sha256(hash1)
    return Buffer.from(hash2).subarray(0, 4)
  }

  /**
   * Validate checksum
   */
  static validChecksum(data: Buffer, checksum: Buffer): boolean {
    const calculatedChecksum = this.checksum(data)
    return calculatedChecksum.equals(checksum)
  }

  /**
   * Base58 encode
   */
  private static base58Encode(buf: Buffer): string {
    if (buf.length === 0) return ''

    // Convert to base58
    let num = 0n
    for (let i = 0; i < buf.length; i++) {
      num = num * 256n + BigInt(buf[i])
    }

    let result = ''
    while (num > 0n) {
      result = ALPHABET[Number(num % 58n)] + result
      num = num / 58n
    }

    // Add leading '1's for leading zeros
    for (let i = 0; i < buf.length && buf[i] === 0; i++) {
      result = '1' + result
    }

    return result
  }

  /**
   * Base58 decode
   */
  private static base58Decode(str: string): Buffer {
    if (str.length === 0) return Buffer.alloc(0)

    let num = 0n
    let leadingZeros = 0

    // Convert from base58
    for (let i = 0; i < str.length; i++) {
      const char = str[i]
      if (ALPHABET_MAP[char] === undefined) {
        throw new Error(`Invalid character: ${char}`)
      }
      num = num * 58n + BigInt(ALPHABET_MAP[char])
    }

    // Count leading zeros
    for (let i = 0; i < str.length && str[i] === '1'; i++) {
      leadingZeros++
    }

    // Convert to bytes
    const bytes: number[] = []
    while (num > 0n) {
      bytes.unshift(Number(num % 256n))
      num = num / 256n
    }

    // Add leading zeros
    for (let i = 0; i < leadingZeros; i++) {
      bytes.unshift(0)
    }

    return Buffer.from(bytes)
  }
}

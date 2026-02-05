/**
 * Base58Check encoding/decoding utilities
 * Migrated from bitcore-lib-xpi with ESM support
 *
 * Uses @noble/hashes for browser compatibility and bs58 for Base58 encoding
 */

import { sha256 } from '@noble/hashes/sha2'
import bs58 from 'bs58'
import { BufferUtil } from '../util'
import type { Buffer } from 'buffer/'

/**
 * Base58Check encoding/decoding class
 *
 * Provides utilities for encoding and decoding data using Base58Check encoding,
 * which adds a 4-byte checksum to detect errors in addresses and other data.
 * This is commonly used in Lotus and other cryptocurrencies for addresses,
 * WIF private keys, and extended keys.
 *
 * @example
 * // Encode a buffer to Base58Check string
 * const encoded = Base58Check.encode(Buffer.from([0x00, ...pubkeyHash]))
 *
 * @example
 * // Decode a Base58Check string to buffer
 * const decoded = Base58Check.decode('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')
 */
export class Base58Check {
  /**
   * Encodes a buffer to a Base58Check string
   *
   * Appends a 4-byte checksum (first 4 bytes of double SHA-256) to the input
   * buffer before encoding with Base58.
   *
   * @param buf - Buffer to encode
   * @returns Base58Check encoded string
   * @throws Error if input is not a Buffer
   */
  static encode(buf: Buffer): string {
    if (!BufferUtil.isBuffer(buf)) {
      throw new Error('Input must be a Buffer')
    }

    // Add checksum
    const checksum = this.checksum(buf)
    const payload = BufferUtil.concat([buf, checksum])

    return bs58.encode(payload)
  }

  /**
   * Decodes a Base58Check string to a buffer
   *
   * Validates the checksum and returns the original data without the checksum bytes.
   *
   * @param str - Base58Check encoded string to decode
   * @returns Decoded buffer (without checksum)
   * @throws Error if input is not a string
   * @throws Error if input string is too short (less than 4 bytes)
   * @throws Error if checksum validation fails
   */
  static decode(str: string): Buffer {
    if (typeof str !== 'string') {
      throw new Error('Input must be a string')
    }

    const buf = BufferUtil.from(bs58.decode(str))

    if (buf.length < 4) {
      throw new Error('Input string too short')
    }

    const data = buf.slice(0, -4)
    const checksum = buf.slice(-4)

    if (!this.validChecksum(data, checksum)) {
      throw new Error('Invalid checksum')
    }

    return data
  }

  /**
   * Calculates the checksum for the given data
   *
   * The checksum is the first 4 bytes of the double SHA-256 hash of the data.
   *
   * @param data - Buffer to calculate checksum for
   * @returns 4-byte checksum buffer
   */
  static checksum(data: Buffer): Buffer {
    const hash = sha256(sha256(data))
    return BufferUtil.from(hash).slice(0, 4)
  }

  /**
   * Validates a checksum against the given data
   *
   * @param data - Original data buffer
   * @param checksum - Checksum buffer to validate (4 bytes)
   * @returns True if the checksum is valid, false otherwise
   */
  static validChecksum(data: Buffer, checksum: Buffer): boolean {
    const calculatedChecksum = this.checksum(data)
    return calculatedChecksum.equals(checksum)
  }
}

/**
 * Base32 encoding/decoding utility
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 *
 * @deprecated This is a legacy module retained for backward compatibility.
 * Lotus does **not** use Base32 encoding for addresses - Lotus XAddresses use {@link Base58}.
 *
 * This module is maintained solely for the CashWeb keyserver compatibility.
 *
 * These external services use bech32-style encoding which requires Base32.
 * For all Lotus-native operations, use {@link Base58} or {@link Base58Check} instead.
 *
 * @module base32
 * @see {@link Base58} For Lotus address encoding
 * @see {@link Base58Check} For Lotus address encoding with checksum
 */

import { Preconditions } from './preconditions.js'

/**
 * Charset containing the 32 symbols used in the base32 encoding.
 * This is the bech32 character set used by Bitcoin Cash cash addresses.
 * @deprecated Only used for CashWeb keyserver compatibility
 */
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

/**
 * Inverted index mapping each symbol into its index within the charset.
 * @deprecated Only used for CashWeb keyserver compatibility
 */
const CHARSET_INVERSE_INDEX: Record<string, number> = {
  'q': 0,
  'p': 1,
  'z': 2,
  'r': 3,
  'y': 4,
  '9': 5,
  'x': 6,
  '8': 7,
  'g': 8,
  'f': 9,
  '2': 10,
  't': 11,
  'v': 12,
  'd': 13,
  'w': 14,
  '0': 15,
  's': 16,
  '3': 17,
  'j': 18,
  'n': 19,
  '5': 20,
  '4': 21,
  'k': 22,
  'h': 23,
  'c': 24,
  'e': 25,
  '6': 26,
  'm': 27,
  'u': 28,
  'a': 29,
  '7': 30,
  'l': 31,
}

/**
 * Base32 encoding/decoding utility class.
 *
 * @deprecated This class is maintained for CashWeb keyserver compatibility only.
 * Lotus addresses use {@link Base58}, not Base32. Do not use for new Lotus features.
 *
 * @example
 * ```typescript
 * // For CashWeb keyserver compatibility only
 * const encoded = Base32.encode([0, 1, 2, 3])
 * const decoded = Base32.decode('qpzr')
 * ```
 */
export class Base32 {
  /**
   * Encodes the given array of 5-bit integers as a base32-encoded string.
   * Uses the bech32 character set (qpzry9x8gf2tvdw0s3jn54khce6mua7l).
   *
   * @param data Array of integers between 0 and 31 inclusive.
   * @returns Base32-encoded string
   * @deprecated Only for CashWeb keyserver compatibility
   *
   * @example
   * ```typescript
   * Base32.encode([0, 1, 2]) // returns 'qpz'
   * ```
   */
  static encode(data: number[]): string {
    Preconditions.checkArgument(Array.isArray(data), 'data', 'Must be Array')
    let base32 = ''
    for (let i = 0; i < data.length; i++) {
      const value = data[i]
      Preconditions.checkArgument(
        0 <= value && value < 32,
        'value',
        `value ${value}`,
      )
      base32 += CHARSET[value]
    }
    return base32
  }

  /**
   * Decodes the given base32-encoded string into an array of 5-bit integers.
   * @deprecated Only for CashWeb keyserver compatibility
   *
   * @param base32 Base32-encoded string using bech32 charset
   * @returns Array of 5-bit integers (0-31)
   * @throws Error if string contains invalid characters
   *
   * @example
   * ```typescript
   * Base32.decode('qpzr') // returns [0, 1, 2, 3]
   * ```
   */
  static decode(base32: string): number[] {
    Preconditions.checkArgument(
      typeof base32 === 'string',
      'base32',
      'Must be base32-encoded string',
    )
    const data: number[] = []
    for (let i = 0; i < base32.length; i++) {
      const value = base32[i]
      Preconditions.checkArgument(
        value in CHARSET_INVERSE_INDEX,
        'value',
        `value ${value}`,
      )
      data.push(CHARSET_INVERSE_INDEX[value])
    }
    return data
  }
}

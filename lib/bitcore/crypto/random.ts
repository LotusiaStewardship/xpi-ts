/**
 * Random number generation utilities
 * Migrated from bitcore-lib-xpi with ESM support
 *
 * Uses @noble/hashes for browser compatibility
 */

import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils'
import { BufferUtil } from '../util'
import type { Buffer } from 'buffer/'

/**
 * Random number generation utilities for cryptographic operations
 *
 * This class provides secure random number generation that works in both
 * Node.js and browser environments. It uses @noble/hashes which automatically
 * detects the environment and uses the appropriate cryptographic random source:
 * - Node.js: crypto.randomBytes
 * - Browser: crypto.getRandomValues
 *
 * @example
 * ```typescript
 * // Generate 32 random bytes for a private key
 * const randomBytes = Random.getRandomBuffer(32)
 *
 * // For non-critical uses where crypto may not be available
 * const pseudoRandom = Random.getPseudoRandomBuffer(16)
 * ```
 */
export class Random {
  /**
   * Secure random bytes - works in both Node.js and browser
   * Uses @noble/hashes which automatically detects the environment
   */
  static getRandomBuffer(size: number): Buffer {
    return BufferUtil.from(nobleRandomBytes(size))
  }

  /**
   * Node.js implementation - now uses @noble/hashes
   * @deprecated Use getRandomBuffer instead
   */
  static getRandomBufferNode(size: number): Buffer {
    return Random.getRandomBuffer(size)
  }

  /**
   * Browser implementation - now uses @noble/hashes
   * @deprecated Use getRandomBuffer instead
   */
  static getRandomBufferBrowser(size: number): Buffer {
    return Random.getRandomBuffer(size)
  }

  /**
   * Insecure random bytes, but it never fails
   *
   * This method uses Math.random() which is NOT cryptographically secure.
   * Only use this for non-security-critical purposes such as testing or
   * when cryptographic random sources are unavailable.
   *
   * @param size - Number of random bytes to generate
   * @returns Buffer containing pseudo-random bytes
   *
   * @warning Do NOT use for cryptographic keys, nonces, or any security-sensitive data
   */
  static getPseudoRandomBuffer(size: number): Buffer {
    const b32 = 0x100000000
    const b = BufferUtil.alloc(size)
    let r = 0

    for (let i = 0; i <= size; i++) {
      const j = Math.floor(i / 4)
      const k = i - j * 4
      if (k === 0) {
        r = Math.random() * b32
        b[i] = r & 0xff
      } else {
        r = r >>> 8
        b[i] = r & 0xff
      }
    }

    return b
  }
}

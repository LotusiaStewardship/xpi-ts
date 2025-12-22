/**
 * Random number generation utilities
 * Migrated from bitcore-lib-xpi with ESM support
 *
 * Uses @noble/hashes for browser compatibility
 */

import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils'

export class Random {
  /**
   * Secure random bytes - works in both Node.js and browser
   * Uses @noble/hashes which automatically detects the environment
   */
  static getRandomBuffer(size: number): Buffer {
    return Buffer.from(nobleRandomBytes(size))
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
   */
  static getPseudoRandomBuffer(size: number): Buffer {
    const b32 = 0x100000000
    const b = Buffer.alloc(size)
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

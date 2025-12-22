/**
 * PBKDF2 implementation for mnemonic seed generation
 * Migrated from @abcpros/bitcore-mnemonic with ESM support and TypeScript
 *
 * Uses @noble/hashes for browser compatibility
 */

import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2'
import { sha512 } from '@noble/hashes/sha512'

/**
 * PBKDF2 implementation using SHA512
 * Uses @noble/hashes for browser compatibility
 *
 * Credit to: https://github.com/stayradiated/pbkdf2-sha512
 * Copyright (c) 2014, JP Richardson Copyright (c) 2010-2011 Intalio Pte, All Rights Reserved
 */
export function pbkdf2(
  key: string | Buffer,
  salt: string | Buffer,
  iterations: number,
  dkLen: number,
): Buffer {
  const hLen = 64 // SHA512 Mac length
  if (dkLen > (Math.pow(2, 32) - 1) * hLen) {
    throw new Error('Requested key length too long')
  }

  if (typeof key !== 'string' && !Buffer.isBuffer(key)) {
    throw new TypeError('key must a string or Buffer')
  }

  if (typeof salt !== 'string' && !Buffer.isBuffer(salt)) {
    throw new TypeError('salt must a string or Buffer')
  }

  // Convert to Uint8Array for @noble/hashes
  const keyBytes =
    typeof key === 'string'
      ? new TextEncoder().encode(key)
      : new Uint8Array(key)
  const saltBytes =
    typeof salt === 'string'
      ? new TextEncoder().encode(salt)
      : new Uint8Array(salt)

  // Use @noble/hashes pbkdf2 with sha512
  const result = noblePbkdf2(sha512, keyBytes, saltBytes, {
    c: iterations,
    dkLen: dkLen,
  })

  return Buffer.from(result)
}

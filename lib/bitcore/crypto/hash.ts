/**
 * Cryptographic hash functions
 * Migrated from bitcore-lib-xpi with ESM support
 *
 * Uses @noble/hashes for browser compatibility
 */

import { ripemd160, sha1 } from '@noble/hashes/legacy'
import { sha256, sha512 } from '@noble/hashes/sha2'
import { BufferUtil } from '../util'
import type { Buffer } from 'buffer/'

/**
 * Hash function interface for cryptographic operations
 * Represents a hash function that can be used with HMAC
 */
interface HashFunction {
  /**
   * Compute the hash of a buffer
   * @param buf - Input buffer to hash
   * @returns Hash result as Buffer
   */
  (buf: Buffer): Buffer
  /**
   * Block size of the hash function in bits
   * Used for HMAC padding calculations
   */
  blocksize: number
}

/**
 * SHA-1 hash function with blocksize property for HMAC
 * @param buf - Input buffer to hash
 * @returns SHA-1 hash as Buffer
 */
const sha1Func: HashFunction = (buf: Buffer): Buffer => {
  if (!BufferUtil.isBuffer(buf)) {
    throw new Error('Argument must be a Buffer')
  }
  return BufferUtil.from(sha1(buf))
}
sha1Func.blocksize = 512

/**
 * SHA-256 hash function with blocksize property for HMAC
 * @param buf - Input buffer to hash
 * @returns SHA-256 hash as Buffer
 */
const sha256Func: HashFunction = (buf: Buffer): Buffer => {
  if (!BufferUtil.isBuffer(buf)) {
    console.log('sha256Func: buf is not a Buffer', buf, typeof buf)
    throw new Error('Argument must be a Buffer')
  }
  return BufferUtil.from(sha256(buf))
}
sha256Func.blocksize = 512

/**
 * SHA-512 hash function with blocksize property for HMAC
 * @param buf - Input buffer to hash
 * @returns SHA-512 hash as Buffer
 */
const sha512Func: HashFunction = (buf: Buffer): Buffer => {
  if (!BufferUtil.isBuffer(buf)) {
    throw new Error('Argument must be a Buffer')
  }
  return BufferUtil.from(sha512(buf))
}
sha512Func.blocksize = 1024

export class Hash {
  static sha1 = sha1Func
  static sha256 = sha256Func
  static sha512 = sha512Func

  /**
   * Compute double SHA-256 hash
   * @param buf - Input buffer to hash
   * @returns Double SHA-256 hash as Buffer
   */
  static sha256sha256 = function (buf: Buffer): Buffer {
    if (!BufferUtil.isBuffer(buf)) {
      throw new Error('Argument must be a Buffer')
    }
    return Hash.sha256(Hash.sha256(buf))
  }

  /**
   * Compute RIPEMD-160 hash
   * @param buf - Input buffer to hash
   * @returns RIPEMD-160 hash as Buffer
   */
  static ripemd160 = function (buf: Buffer): Buffer {
    if (!BufferUtil.isBuffer(buf)) {
      throw new Error('Argument must be a Buffer')
    }
    return BufferUtil.from(ripemd160(buf))
  }

  /**
   * Compute SHA-256 followed by RIPEMD-160 (Hash160)
   * Commonly used for Bitcoin address generation
   * @param buf - Input buffer to hash (typically a public key)
   * @returns SHA-256-RIPEMD-160 hash as Buffer
   */
  static sha256ripemd160 = function (buf: Buffer): Buffer {
    if (!BufferUtil.isBuffer(buf)) {
      throw new Error('Argument must be a Buffer')
    }
    return Hash.ripemd160(Hash.sha256(buf))
  }

  /**
   * Compute HMAC (Hash-based Message Authentication Code)
   * @see http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
   * @see http://tools.ietf.org/html/rfc4868#section-2
   * @param hashf - The hash function to use (sha256 or sha512)
   * @param data - The data to authenticate
   * @param key - The secret key
   * @returns The HMAC result
   */
  static hmac(hashf: HashFunction, data: Buffer, key: Buffer): Buffer {
    if (!BufferUtil.isBuffer(data)) {
      throw new Error('Data must be a Buffer')
    }
    if (!BufferUtil.isBuffer(key)) {
      throw new Error('Key must be a Buffer')
    }
    if (!hashf.blocksize) {
      throw new Error('Hash function must have blocksize property')
    }

    // Convert blocksize from bits to bytes
    const blocksize = hashf.blocksize / 8
    let processedKey = key

    // If key is longer than blocksize, hash it; if shorter, pad with zeros
    if (key.length > blocksize) {
      processedKey = hashf(key)
    } else if (key.length < blocksize) {
      const fill = BufferUtil.alloc(blocksize)
      fill.fill(0)
      key.copy(fill)
      processedKey = fill
    }

    // Outer and inner padding constants
    const o_key = BufferUtil.alloc(blocksize)
    o_key.fill(0x5c)

    const i_key = BufferUtil.alloc(blocksize)
    i_key.fill(0x36)

    // XOR key with padding constants
    const o_key_pad = BufferUtil.alloc(blocksize)
    const i_key_pad = BufferUtil.alloc(blocksize)

    // XOR processed key with outer and inner padding
    for (let i = 0; i < blocksize; i++) {
      o_key_pad[i] = o_key[i] ^ processedKey[i]
      i_key_pad[i] = i_key[i] ^ processedKey[i]
    }

    return hashf(
      BufferUtil.concat([
        o_key_pad,
        hashf(BufferUtil.concat([i_key_pad, data])),
      ]),
    )
  }

  /**
   * Compute HMAC-SHA256
   * @param data - The data to authenticate
   * @param key - The secret key
   * @returns The HMAC-SHA256 result
   */
  static sha256hmac(data: Buffer, key: Buffer): Buffer {
    return Hash.hmac(Hash.sha256, data, key)
  }

  /**
   * Compute HMAC-SHA512
   * @param data - The data to authenticate
   * @param key - The secret key
   * @returns The HMAC-SHA512 result
   */
  static sha512hmac(data: Buffer, key: Buffer): Buffer {
    return Hash.hmac(Hash.sha512, data, key)
  }
}

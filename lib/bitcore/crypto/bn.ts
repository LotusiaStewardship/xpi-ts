/**
 * BN (Big Number) wrapper class
 * Provides a simplified interface to the BN.js library
 * Migrated from bitcore-lib-xpi with ESM support
 */

import BN from 'bn.js'
import { BufferUtil } from '../util'
import type { Buffer } from 'buffer/'

export interface BNWrapperOptions {
  endian?: 'little' | 'big'
  size?: number
}

/**
 * BN (Big Number) wrapper class
 *
 * Provides a simplified interface to the BN.js library for arbitrary-precision
 * integer arithmetic. This class wraps the underlying BN.js implementation and
 * adds convenience methods for cryptographic operations commonly used in Lotus
 * and related protocols.
 *
 * Features:
 * - Conversion to/from Buffer, hex strings, and numbers
 * - Signed magnitude (SM) buffer encoding/decoding
 * - Arithmetic operations (add, sub, mul, div, mod, pow)
 * - Comparison operations (eq, lt, gt, lte, gte, cmp)
 * - Bitwise operations (and, neg)
 * - Modular arithmetic (umod, invm, modPow)
 *
 * @example
 * ```typescript
 * // Create from number
 * const bn1 = new BN(42)
 *
 * // Create from hex string
 * const bn2 = BN.fromString('ff', 'hex')
 *
 * // Create from buffer
 * const bn3 = BN.fromBuffer(BufferUtil.from([0x01, 0x02]))
 *
 * // Arithmetic
 * const sum = bn1.add(bn2)
 * const product = bn1.mul(bn2)
 * ```
 *
 * @remarks
 * Migrated from bitcore-lib-xpi with ESM support
 */
class BNWrapper {
  private _bn: BN

  // Static constants to match reference
  /** The number zero (0) */
  static readonly Zero = new BNWrapper(0)
  /** The number one (1) */
  static readonly One = new BNWrapper(1)
  /** The number negative one (-1) */
  static readonly Minus1 = new BNWrapper(-1)

  /**
   * Create a new BNWrapper instance
   *
   * @param n - The value to create the BN from. Can be a number, string, BN instance, or BufferUtil.
   * @param base - The base for string/buffer parsing. Can be a number (e.g., 10, 16), 'hex', 'le' (little-endian), or 'be' (big-endian).
   *
   * @example
   * ```typescript
   * // From number
   * const bn1 = new BN(42)
   *
   * // From hex string
   * const bn2 = new BN('ff', 'hex')
   *
   * // From buffer with little-endian
   * const bn3 = new BN(BufferUtil.from([0x01, 0x02]), 'le')
   * ```
   */
  constructor(
    n: number | string | BN | Buffer,
    base?: number | 'hex' | 'le' | 'be',
  ) {
    if (n instanceof BN) {
      this._bn = n.clone()
    } else if (BufferUtil.isBuffer(n)) {
      if (base === 'le' || base === 'be') {
        this._bn = new BN(n, undefined, base)
      } else {
        this._bn = new BN(n, base || 'hex')
      }
    } else {
      // For non-Buffer inputs, only allow number or 'hex' base
      const validBase =
        base === 'hex' || typeof base === 'number' ? base : undefined
      this._bn = new BN(n, validBase)
    }
  }

  /**
   * Create BN from string
   */
  static fromString(str: string, base?: 'hex' | number): BNWrapper {
    return new BNWrapper(str, base)
  }

  /**
   * Create BN from buffer
   */
  static fromBuffer(buf: Buffer, opts?: BNWrapperOptions): BNWrapper {
    let buffer = buf
    if (opts?.size) {
      // Ensure buffer is exactly the specified size
      buffer = BufferUtil.alloc(opts.size)
      buf.copy(buffer, opts.size - buf.length)
    }
    if (opts?.endian === 'little') {
      buffer = BNWrapper.reversebuf(buffer)
    }
    return new BNWrapper(buffer, 'hex')
  }

  /**
   * Instantiate a BigNumber from a "signed magnitude buffer"
   * (a buffer where the most significant bit represents the sign (0 = positive, -1 = negative))
   */
  static fromSM(buf: Buffer, opts?: BNWrapperOptions): BNWrapper {
    if (buf.length === 0) {
      return BNWrapper.fromBuffer(BufferUtil.from([0]))
    }

    let endian = 'big'
    if (opts) {
      endian = opts.endian || 'big'
    }
    let buffer = buf
    if (endian === 'little') {
      buffer = BNWrapper.reversebuf(buf)
    }

    let result: BNWrapper
    if (buffer[0] & 0x80) {
      buffer[0] = buffer[0] & 0x7f
      result = BNWrapper.fromBuffer(buffer)
      result = result.neg()
    } else {
      result = BNWrapper.fromBuffer(buffer)
    }
    return result
  }

  /**
   * Create a BN from a "ScriptNum":
   * This is analogous to the constructor for CScriptNum in bitcoind. Many ops in
   * bitcoind's script interpreter use CScriptNum, which is not really a proper
   * bignum. Instead, an error is thrown if trying to input a number bigger than
   * 4 bytes. We copy that behavior here. A third argument, `size`, is provided to
   * extend the hard limit of 4 bytes, as some usages require more than 4 bytes.
   */
  static fromScriptNumBuffer(
    buf: Buffer,
    fRequireMinimal?: boolean,
    size?: number,
  ): BNWrapper {
    const nMaxNumSize = size || 4
    if (buf.length > nMaxNumSize) {
      throw new Error('script number overflow')
    }

    if (fRequireMinimal && buf.length > 0) {
      // Check that the number is encoded with the minimum possible
      // number of bytes.
      //
      // If the most-significant-byte - excluding the sign bit - is zero
      // then we're not minimal. Note how this test also rejects the
      // negative-zero encoding, 0x80.
      if ((buf[buf.length - 1] & 0x7f) === 0) {
        // One exception: if there's more than one byte and the most
        // significant bit of the second-most-significant-byte is set
        // it would conflict with the sign bit. An example of this case
        // is +-255, which encode to 0xff00 and 0xff80 respectively.
        // (big-endian).
        if (buf.length <= 1 || (buf[buf.length - 2] & 0x80) === 0) {
          throw new Error('non-minimally encoded script number')
        }
      }
    }
    return BNWrapper.fromSM(buf, { endian: 'little' })
  }

  /**
   * Reverse buffer byte order
   */
  static reversebuf(buf: Buffer): Buffer {
    const buf2 = BufferUtil.alloc(buf.length)
    for (let i = 0; i < buf.length; i++) {
      buf2[i] = buf[buf.length - 1 - i]
    }
    return buf2
  }

  /**
   * Trim buffer to natural length
   */
  static trim(buf: Buffer, natlen: number): Buffer {
    return buf.slice(natlen - buf.length, buf.length)
  }

  /**
   * Pad buffer to specified size
   */
  static pad(buf: Buffer, natlen: number, size: number): Buffer {
    const rbuf = BufferUtil.alloc(size)
    for (let i = 0; i < buf.length; i++) {
      rbuf[rbuf.length - 1 - i] = buf[buf.length - 1 - i]
    }
    for (let i = 0; i < size - natlen; i++) {
      rbuf[i] = 0
    }
    return rbuf
  }

  /**
   * Create BN from number
   */
  static fromNumber(n: number): BNWrapper {
    return new BNWrapper(n)
  }

  /**
   * Convert to number
   */
  toNumber(): number {
    return parseInt(this.toString(10), 10)
  }

  /**
   * Add another BN
   */
  add(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.add(r._bn))
  }

  /**
   * Modulo operation
   */
  mod(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.mod(r._bn))
  }

  /**
   * Unsigned modulo operation
   */
  umod(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.umod(r._bn))
  }

  /**
   * Get the underlying BN instance
   */
  get bn(): BN {
    return this._bn
  }

  /**
   * Convert to string
   */
  toString(base?: number): string {
    return this._bn.toString(base)
  }

  /**
   * Converts the BN value to a Buffer with optional size and endianness control.
   * By default, returns big-endian format with natural length.
   *
   * @param opts - Optional configuration for buffer conversion
   * @param opts.size - Fixed size for the output buffer (will pad or trim as needed)
   * @param opts.endian - Byte order: 'little' for little-endian, 'big' for big-endian (default: 'big')
   * @returns Buffer containing the BN value in the specified format
   */
  toBuffer(opts?: BNWrapperOptions): Buffer {
    let hex = this._bn.toString('hex', 2)
    let buf = BufferUtil.from(hex, 'hex')

    if (opts?.size) {
      if (buf.length > opts.size) {
        // Trim from beginning (remove leading zeros)
        buf = buf.slice(buf.length - opts.size)
      } else if (buf.length < opts.size) {
        // Pad with zeros at beginning
        const padded = BufferUtil.alloc(opts.size)
        buf.copy(padded, opts.size - buf.length)
        buf = padded
      }
    }

    if (opts?.endian === 'little') {
      buf = BufferUtil.from(buf).reverse()
    }

    return buf
  }

  /**
   * Multiply by another BN
   * @param r - The BNWrapper to multiply with
   * @returns A new BNWrapper containing the product
   */
  mul(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.mul(r._bn))
  }

  /**
   * Subtract another BN
   * @param r - The BNWrapper to subtract
   * @returns A new BNWrapper containing the difference
   */
  sub(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.sub(r._bn))
  }

  /**
   * Power operation
   * @param r - The exponent as a BNWrapper
   * @returns A new BNWrapper containing this raised to the power of r
   */
  pow(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.pow(r._bn))
  }

  /**
   * Divide by another BN
   * @param r - The BNWrapper to divide by
   * @returns A new BNWrapper containing the quotient
   */
  div(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.div(r._bn))
  }

  /**
   * Modular exponentiation: computes (this^exponent) mod modulus
   * Uses BN.js red reduction context for efficient modular arithmetic
   * @param exponent - The exponent to raise this value to
   * @param modulus - The modulus for the operation
   * @returns A new BNWrapper containing (this^exponent) mod modulus
   */
  modPow(exponent: BNWrapper, modulus: BNWrapper): BNWrapper {
    // BN.js doesn't have a built-in modPow, so we implement square-and-multiply
    const red = BN.red(modulus._bn)
    const base = this._bn.toRed(red)
    const result = base.redPow(exponent._bn)
    return new BNWrapper(result.fromRed())
  }

  /**
   * Bitwise AND operation
   * @param other - The BNWrapper or number to AND with
   * @returns A new BNWrapper containing the result
   */
  and(other: BNWrapper | number): BNWrapper {
    const otherBN = other instanceof BNWrapper ? other._bn : new BN(other)
    return new BNWrapper(this._bn.and(otherBN))
  }

  /**
   * Negate the BN (return -this)
   * @returns A new BNWrapper containing the negated value
   */
  neg(): BNWrapper {
    return new BNWrapper(this._bn.neg())
  }

  /**
   * Compute the modular multiplicative inverse
   * Finds x such that (this * x) mod r = 1
   * @param r - The modulus
   * @returns A new BNWrapper containing the modular inverse
   */
  invm(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.invm(r._bn))
  }

  /**
   * Check if equal to another BN
   * @param other - The BNWrapper to compare with
   * @returns true if this equals other
   */
  eq(other: BNWrapper): boolean {
    return this._bn.eq(other._bn)
  }

  /**
   * Check if less than another BN
   * @param other - The BNWrapper to compare with
   * @returns true if this < other
   */
  lt(other: BNWrapper): boolean {
    return this._bn.lt(other._bn)
  }

  /**
   * Check if greater than another BN
   * @param other - The BNWrapper to compare with
   * @returns true if this > other
   */
  gt(other: BNWrapper): boolean {
    return this._bn.gt(other._bn)
  }

  /**
   * Check if less than or equal to another BN
   * @param other - The BNWrapper to compare with
   * @returns true if this <= other
   */
  lte(other: BNWrapper): boolean {
    return this._bn.lte(other._bn)
  }

  /**
   * Check if greater than or equal to another BN
   * @param other - The BNWrapper to compare with
   * @returns true if this >= other
   */
  gte(other: BNWrapper): boolean {
    return this._bn.gte(other._bn)
  }

  /**
   * Check if the value is zero
   * @returns true if this equals 0
   */
  isZero(): boolean {
    return this._bn.isZero()
  }

  /**
   * Check if the value is negative
   * @returns true if this < 0
   */
  isNeg(): boolean {
    return this._bn.isNeg()
  }

  /**
   * Check if the value is odd
   * @returns true if the least significant bit is 1
   */
  isOdd(): boolean {
    return this._bn.isOdd()
  }

  /**
   * Check if the value is even
   * @returns true if the least significant bit is 0
   */
  isEven(): boolean {
    return this._bn.isEven()
  }

  /**
   * Convert to signed magnitude buffer (big endian)
   */
  toSMBigEndian(): Buffer {
    let buf: Buffer
    if (this.cmp(BNWrapper.Zero) === -1) {
      buf = this.neg().toBuffer()
      if (buf[0] & 0x80) {
        buf = BufferUtil.concat([BufferUtil.from([0x80]), buf])
      } else {
        buf[0] = buf[0] | 0x80
      }
    } else {
      buf = this.toBuffer()
      if (buf[0] & 0x80) {
        buf = BufferUtil.concat([BufferUtil.from([0x00]), buf])
      }
    }

    if (buf.length === 1 && buf[0] === 0) {
      buf = BufferUtil.from([])
    }
    return buf
  }

  /**
   * Convert to signed magnitude buffer
   */
  toSM(opts?: BNWrapperOptions): Buffer {
    const endian = opts ? opts.endian : 'big'
    let buf = this.toSMBigEndian()

    if (endian === 'little') {
      buf = BNWrapper.reversebuf(buf)
    }
    return buf
  }

  /**
   * Convert to script number buffer
   */
  toScriptNumBuffer(): Buffer {
    return this.toSM({ endian: 'little' })
  }

  /**
   * Compare with another BN
   */
  cmp(other: BNWrapper): number {
    return this._bn.cmp(other._bn)
  }

  /**
   * Copy value from another BN
   */
  copy(other: BNWrapper): BNWrapper {
    this._bn = other._bn.clone()
    return this
  }

  /**
   * Clone the BN
   */
  clone(): BNWrapper {
    return new BNWrapper(this._bn.clone())
  }
}

// Export as BN for compatibility
export { BNWrapper as BN }

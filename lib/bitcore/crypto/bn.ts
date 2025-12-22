/**
 * BN (Big Number) wrapper class
 * Provides a simplified interface to the BN.js library
 * Migrated from bitcore-lib-xpi with ESM support
 */

import BN from 'bn.js'

export interface BNWrapperOptions {
  endian?: 'little' | 'big'
  size?: number
}

class BNWrapper {
  private _bn: BN

  // Static constants to match reference
  static readonly Zero = new BNWrapper(0)
  static readonly One = new BNWrapper(1)
  static readonly Minus1 = new BNWrapper(-1)

  constructor(
    n: number | string | BN | Buffer,
    base?: number | 'hex' | 'le' | 'be',
  ) {
    if (n instanceof BN) {
      this._bn = n.clone()
    } else if (Buffer.isBuffer(n)) {
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
  static fromString(str: string, base?: number): BNWrapper {
    return new BNWrapper(str, base)
  }

  /**
   * Create BN from buffer
   */
  static fromBuffer(buf: Buffer, opts?: BNWrapperOptions): BNWrapper {
    let buffer = buf
    if (opts?.size) {
      // Ensure buffer is exactly the specified size
      buffer = Buffer.alloc(opts.size)
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
      return BNWrapper.fromBuffer(Buffer.from([0]))
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
    const buf2 = Buffer.alloc(buf.length)
    for (let i = 0; i < buf.length; i++) {
      buf2[i] = buf[buf.length - 1 - i]
    }
    return buf2
  }

  /**
   * Trim buffer to natural length
   */
  static trim(buf: Buffer, natlen: number): Buffer {
    return buf.subarray(natlen - buf.length, buf.length)
  }

  /**
   * Pad buffer to specified size
   */
  static pad(buf: Buffer, natlen: number, size: number): Buffer {
    const rbuf = Buffer.alloc(size)
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
   * Convert to buffer
   */
  toBuffer(opts?: BNWrapperOptions): Buffer {
    let buf: Buffer

    if (opts && opts.size) {
      // Get the buffer without size specification first
      buf = this._bn.toArrayLike(Buffer, opts.endian === 'little' ? 'le' : 'be')

      // Then manually pad or trim to the correct size
      if (buf.length === opts.size) {
        // buf is already the right size
      } else if (buf.length > opts.size) {
        // Trim from the beginning (remove leading zeros)
        buf = buf.subarray(buf.length - opts.size)
      } else if (buf.length < opts.size) {
        // Pad with zeros at the beginning
        const padded = Buffer.alloc(opts.size)
        buf.copy(padded, opts.size - buf.length)
        buf = padded
      }
    } else {
      // Use BN.js toArrayLike method for default behavior
      buf = this._bn.toArrayLike(
        Buffer,
        opts?.endian === 'little' ? 'le' : 'be',
      )
    }

    return buf
  }

  /**
   * Convert to array-like object (compatibility with BN.js)
   */
  toArrayLike(
    ArrayType: typeof Buffer,
    endian?: 'le' | 'be',
    length?: number,
  ): Buffer {
    return this._bn.toArrayLike(ArrayType, endian || 'be', length)
  }

  /**
   * Multiply by another BN
   */
  mul(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.mul(r._bn))
  }

  /**
   * Subtract another BN
   */
  sub(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.sub(r._bn))
  }

  /**
   * Power operation
   */
  pow(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.pow(r._bn))
  }

  /**
   * Divide by another BN
   */
  div(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.div(r._bn))
  }

  /**
   * Modular exponentiation: computes (this^exponent) mod modulus
   * Uses square-and-multiply algorithm for efficiency
   */
  modPow(exponent: BNWrapper, modulus: BNWrapper): BNWrapper {
    // BN.js doesn't have a built-in modPow, so we implement square-and-multiply
    const red = BN.red(modulus._bn)
    const base = this._bn.toRed(red)
    const result = base.redPow(exponent._bn)
    return new BNWrapper(result.fromRed())
  }

  /**
   * Bitwise AND
   */
  and(other: BNWrapper | number): BNWrapper {
    const otherBN = other instanceof BNWrapper ? other._bn : new BN(other)
    return new BNWrapper(this._bn.and(otherBN))
  }

  /**
   * Negate the BN
   */
  neg(): BNWrapper {
    return new BNWrapper(this._bn.neg())
  }

  /**
   * Modular inverse
   */
  invm(r: BNWrapper): BNWrapper {
    return new BNWrapper(this._bn.invm(r._bn))
  }

  /**
   * Check if equal to another BN
   */
  eq(other: BNWrapper): boolean {
    return this._bn.eq(other._bn)
  }

  /**
   * Check if less than another BN
   */
  lt(other: BNWrapper): boolean {
    return this._bn.lt(other._bn)
  }

  /**
   * Check if greater than another BN
   */
  gt(other: BNWrapper): boolean {
    return this._bn.gt(other._bn)
  }

  /**
   * Check if less than or equal to another BN
   */
  lte(other: BNWrapper): boolean {
    return this._bn.lte(other._bn)
  }

  /**
   * Check if greater than or equal to another BN
   */
  gte(other: BNWrapper): boolean {
    return this._bn.gte(other._bn)
  }

  /**
   * Check if zero
   */
  isZero(): boolean {
    return this._bn.isZero()
  }

  /**
   * Check if negative
   */
  isNeg(): boolean {
    return this._bn.isNeg()
  }

  /**
   * Check if odd
   */
  isOdd(): boolean {
    return this._bn.isOdd()
  }

  /**
   * Check if even
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
        buf = Buffer.concat([Buffer.from([0x80]), buf])
      } else {
        buf[0] = buf[0] | 0x80
      }
    } else {
      buf = this.toBuffer()
      if (buf[0] & 0x80) {
        buf = Buffer.concat([Buffer.from([0x00]), buf])
      }
    }

    if (buf.length === 1 && buf[0] === 0) {
      buf = Buffer.from([])
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

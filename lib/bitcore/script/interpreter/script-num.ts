/**
 * Copyright 2025-2026 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * Script Number Arithmetic
 *
 * Implements the CScriptNum equivalent for Lotus script evaluation.
 * Script numbers are signed integers stored as variable-length
 * little-endian byte arrays with sign-magnitude encoding.
 *
 * Lotus uses 8-byte script numbers (int64 range), unlike Bitcoin's
 * 4-byte limit. The valid range is [-2^63+1, 2^63-1].
 *
 * Reference: lotusd/src/script/script.h (CScriptNum)
 *
 * @module ScriptNum
 */

import { BufferUtil } from '../../util/buffer'
import { SCRIPTNUM_MAX_ELEMENT_SIZE } from './types'
import type { Buffer } from 'buffer/'

/**
 * Error thrown when script number operations overflow or
 * encounter invalid encodings.
 */
export class ScriptNumError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ScriptNumError'
  }
}

/**
 * Script number representation for stack-based arithmetic.
 *
 * Wraps a bigint value with serialization/deserialization that
 * matches the lotusd CScriptNum wire format. All arithmetic
 * operations check for overflow within the int64 range.
 *
 * SECURITY: The value INT64_MIN (-2^63) is explicitly excluded
 * from the valid range to avoid undefined behavior in negation.
 */
export class ScriptNum {
  private static readonly INT64_MAX = (1n << 63n) - 1n
  private static readonly INT64_MIN_EXCLUSIVE = -(1n << 63n) + 1n

  /** The underlying numeric value */
  readonly value: bigint

  constructor(value: bigint) {
    this.value = value
  }

  /**
   * Decode a script number from its stack byte representation.
   *
   * @param buf - The byte array from the stack
   * @param requireMinimal - Require minimally-encoded numbers
   * @param maxSize - Maximum byte length (default: 8)
   * @returns A new ScriptNum
   * @throws {ScriptNumError} On overflow or non-minimal encoding
   */
  static fromBuffer(
    buf: Buffer,
    requireMinimal: boolean = true,
    maxSize: number = SCRIPTNUM_MAX_ELEMENT_SIZE,
  ): ScriptNum {
    if (buf.length > maxSize) {
      throw new ScriptNumError('script number overflow')
    }
    if (requireMinimal && !ScriptNum.isMinimallyEncoded(buf, maxSize)) {
      throw new ScriptNumError('non-minimally encoded script number')
    }
    return new ScriptNum(ScriptNum.decode(buf))
  }

  /**
   * Check if a byte array is minimally encoded as a script number.
   *
   * Minimal encoding rules:
   * - Empty array encodes 0
   * - No unnecessary leading zero bytes
   * - Sign bit uses the MSB of the last byte
   *
   * @param buf - The byte array to check
   * @param maxSize - Maximum allowed size
   * @returns true if minimally encoded
   */
  static isMinimallyEncoded(
    buf: Buffer,
    maxSize: number = SCRIPTNUM_MAX_ELEMENT_SIZE,
  ): boolean {
    if (buf.length > maxSize) {
      return false
    }
    if (buf.length === 0) {
      return true
    }
    // If the most-significant byte (excluding the sign bit) is zero,
    // then we're not minimal. The sign bit can cause an extra byte.
    if ((buf[buf.length - 1] & 0x7f) === 0) {
      if (buf.length <= 1 || (buf[buf.length - 2] & 0x80) === 0) {
        return false
      }
    }
    return true
  }

  /**
   * Minimally encode a byte array in-place.
   *
   * Removes unnecessary padding bytes while preserving the
   * numeric value and sign.
   *
   * @param data - Mutable byte array to encode minimally
   * @returns The minimally encoded buffer
   */
  static minimallyEncode(data: Buffer): Buffer {
    if (data.length === 0) {
      return data
    }

    // Trim trailing zero bytes, preserving sign
    let last = data[data.length - 1]
    if ((last & 0x7f) !== 0) {
      return data
    }

    // Find the last non-zero byte (excluding sign)
    let i = data.length - 1
    while (i > 0 && data[i] === 0) {
      i--
    }

    // If the remaining last byte has its sign bit set, we need
    // to keep one zero byte for the sign
    if (i === 0 && data[0] === 0) {
      return BufferUtil.alloc(0)
    }

    const result = BufferUtil.alloc(i + 1 + ((data[i] & 0x80) !== 0 ? 1 : 0))
    data.copy(result, 0, 0, i + 1)
    if ((data[i] & 0x80) !== 0) {
      result[result.length - 1] = last & 0x80
    } else {
      result[i] |= last & 0x80
    }
    return result
  }

  /**
   * Decode a little-endian sign-magnitude byte array to bigint.
   *
   * @param buf - The byte array to decode
   * @returns The decoded numeric value
   */
  private static decode(buf: Buffer): bigint {
    if (buf.length === 0) {
      return 0n
    }

    let result = 0n
    for (let i = 0; i < buf.length; i++) {
      result |= BigInt(buf[i]) << BigInt(8 * i)
    }

    // If the sign bit is set, mask it off and negate
    if (buf[buf.length - 1] & 0x80) {
      const mask = 0x80n << BigInt(8 * (buf.length - 1))
      return -(result & ~mask)
    }

    return result
  }

  /**
   * Serialize this script number to its stack byte representation.
   *
   * @returns Minimally-encoded little-endian sign-magnitude bytes
   */
  toBuffer(): Buffer {
    return ScriptNum.serialize(this.value)
  }

  /**
   * Serialize a bigint value to script number byte format.
   *
   * @param value - The numeric value to serialize
   * @returns Minimally-encoded byte array
   */
  static serialize(value: bigint): Buffer {
    if (value === 0n) {
      return BufferUtil.alloc(0)
    }

    const neg = value < 0n
    let absvalue = neg ? -value : value

    const result: number[] = []
    while (absvalue > 0n) {
      result.push(Number(absvalue & 0xffn))
      absvalue >>= 8n
    }

    // Add sign byte if needed
    if (result[result.length - 1] & 0x80) {
      result.push(neg ? 0x80 : 0x00)
    } else if (neg) {
      result[result.length - 1] |= 0x80
    }

    return BufferUtil.from(result)
  }

  /**
   * Get the value as a regular number (clamped to int32 range).
   *
   * @returns The value clamped to [-2^31, 2^31-1]
   */
  toNumber(): number {
    const MAX_INT = 2_147_483_647
    const MIN_INT = -2_147_483_648
    if (this.value > BigInt(MAX_INT)) {
      return MAX_INT
    }
    if (this.value < BigInt(MIN_INT)) {
      return MIN_INT
    }
    return Number(this.value)
  }

  // ─── Arithmetic Operations ──────────────────────────────────────

  /**
   * Add two script numbers with overflow checking.
   *
   * @throws {ScriptNumError} On int64 overflow
   */
  add(other: ScriptNum): ScriptNum {
    const result = this.value + other.value
    ScriptNum.checkOverflow(result)
    return new ScriptNum(result)
  }

  /**
   * Subtract two script numbers with overflow checking.
   *
   * @throws {ScriptNumError} On int64 overflow
   */
  sub(other: ScriptNum): ScriptNum {
    const result = this.value - other.value
    ScriptNum.checkOverflow(result)
    return new ScriptNum(result)
  }

  /** Negate this script number */
  negate(): ScriptNum {
    return new ScriptNum(-this.value)
  }

  /** Absolute value */
  abs(): ScriptNum {
    return this.value < 0n ? this.negate() : this
  }

  /** Integer division */
  div(other: ScriptNum): ScriptNum {
    return new ScriptNum(this.value / other.value)
  }

  /** Modulo */
  mod(other: ScriptNum): ScriptNum {
    return new ScriptNum(this.value % other.value)
  }

  /**
   * Multiply by power of 2 (OP_MULPOW2).
   *
   * Equivalent to value * 2^shift for positive shift,
   * or value / 2^|shift| for negative shift.
   *
   * @throws {ScriptNumError} On overflow
   */
  mulpow2(shift: ScriptNum): ScriptNum {
    if (this.value === 0n) {
      return new ScriptNum(0n)
    }
    const sign = this.value > 0n ? 1n : -1n
    const absval = this.value > 0n ? this.value : -this.value

    if (shift.value > 0n) {
      if (shift.value >= 63n) {
        throw new ScriptNumError('script number mulpow2 non-zero shift >= 63')
      }
      const overflowMask =
        ~((1n << (63n - shift.value)) - 1n) & ((1n << 64n) - 1n)
      if ((absval & overflowMask) !== 0n) {
        throw new ScriptNumError('script number mulpow2 overflow')
      }
      return new ScriptNum(sign * (absval << shift.value))
    } else {
      const rshift = -shift.value
      if (rshift >= 63n) {
        return new ScriptNum(0n)
      }
      return new ScriptNum(sign * (absval >> rshift))
    }
  }

  /** Bitwise AND */
  bitwiseAnd(mask: bigint): ScriptNum {
    return new ScriptNum(this.value & mask)
  }

  // ─── Comparison ─────────────────────────────────────────────────

  isZero(): boolean {
    return this.value === 0n
  }

  isNegative(): boolean {
    return this.value < 0n
  }

  lt(other: ScriptNum | bigint): boolean {
    const val = other instanceof ScriptNum ? other.value : other
    return this.value < val
  }

  gt(other: ScriptNum | bigint): boolean {
    const val = other instanceof ScriptNum ? other.value : other
    return this.value > val
  }

  lte(other: ScriptNum | bigint): boolean {
    const val = other instanceof ScriptNum ? other.value : other
    return this.value <= val
  }

  gte(other: ScriptNum | bigint): boolean {
    const val = other instanceof ScriptNum ? other.value : other
    return this.value >= val
  }

  eq(other: ScriptNum | bigint): boolean {
    const val = other instanceof ScriptNum ? other.value : other
    return this.value === val
  }

  neq(other: ScriptNum | bigint): boolean {
    const val = other instanceof ScriptNum ? other.value : other
    return this.value !== val
  }

  /**
   * Validate that a result is within the valid int64 range.
   *
   * INT64_MIN is excluded because negating it causes overflow.
   *
   * @throws {ScriptNumError} If value is out of range
   */
  private static checkOverflow(value: bigint): void {
    if (value > ScriptNum.INT64_MAX || value < ScriptNum.INT64_MIN_EXCLUSIVE) {
      throw new ScriptNumError('script number overflow')
    }
  }
}

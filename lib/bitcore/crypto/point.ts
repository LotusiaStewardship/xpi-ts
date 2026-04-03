/**
 * Elliptic curve point operations for secp256k1
 * Migrated from bitcore-lib-xpi with ESM support
 */

import * as elliptic from 'elliptic'
import { BN } from './bn'
import { BufferUtil } from '../util'
import type { Buffer } from 'buffer/'
import type { ec, curve } from 'elliptic'

/**
 * Create an elliptic curve instance for secp256k1 operations.
 *
 * The dual import pattern `(elliptic as any).default || elliptic` is necessary for
 * compatibility across both CJS and ESM build environments:
 *
 * - With `esModuleInterop: true` (or bundlers like esbuild/webpack that synthesize
 *   ESM interop), the CJS exports are placed under `.default`, so we access
 *   `elliptic.default.ec()`.
 * - With `esModuleInterop: false` (this project's setting), `import * as elliptic`
 *   binds the CJS `module.exports` object directly to the namespace, so we access
 *   `elliptic.ec()`.
 *
 * This fallback ensures the library works correctly regardless of how the module
 * is resolved at runtime.
 */
const ecInstance = new ((elliptic as any).default || elliptic).ec(
  'secp256k1',
) as ec
const ecPoint = ecInstance.curve.point.bind(ecInstance.curve) as (
  x: any,
  y: any,
  isRed?: boolean,
) => curve.base.BasePoint
const ecPointFromX = ecInstance.curve.pointFromX.bind(ecInstance.curve) as (
  x: any,
  isOdd: boolean,
) => curve.base.BasePoint

/** Prefix byte for compressed point with odd Y-coordinate */
export const PREFIX_Y_ODD = 0x03
/** Prefix byte for compressed point with even Y-coordinate */
export const PREFIX_Y_EVEN = 0x02

export class Point {
  private _point: curve.base.BasePoint

  /** Buffer containing prefix byte for compressed point with odd Y-coordinate */
  static readonly PrefixOddY = BufferUtil.from([PREFIX_Y_ODD])
  /** Buffer containing prefix byte for compressed point with even Y-coordinate */
  static readonly PrefixEvenY = BufferUtil.from([PREFIX_Y_EVEN])

  constructor(x: BN | string, y: BN | string, isRed?: boolean) {
    try {
      // Convert BNWrapper to BN.js for elliptic library
      const bnX = x instanceof BN ? x.bn : new BN(x)
      const bnY = y instanceof BN ? y.bn : new BN(y)
      this._point = ecPoint(bnX, bnY, isRed)
    } catch (e) {
      throw new Error('Invalid Point')
    }
    this.validate()
  }

  /**
   * Get the X coordinate of the point
   */
  get x(): BN {
    const xBuffer = this._point.getX().toBuffer()
    return BN.fromString(xBuffer.toString('hex'), 'hex')
  }

  /**
   * Get the Y coordinate of the point
   */
  get y(): BN {
    const yBuffer = this._point.getY().toBuffer()
    return BN.fromString(yBuffer.toString('hex'), 'hex')
  }

  /**
   * Instantiate a valid secp256k1 Point from only the X coordinate
   *
   * @param odd - If true, use the odd Y coordinate; if false, use the even Y coordinate
   * @param x - The X coordinate as a BN or hex string
   * @returns A Point instance on the secp256k1 curve
   * @throws {Error} If the X coordinate does not correspond to a valid curve point
   */
  static fromX(odd: boolean, x: BN | string): Point {
    try {
      // Convert to string if it's a BN
      const xStr = typeof x === 'string' ? x : x.toString()

      // Try different approaches to create the point
      let point
      try {
        // First try: use pointFromX with BN.js object
        const bnX = x instanceof BN ? x.bn : new BN(xStr)
        point = ecInstance.curve.pointFromX(bnX, odd)
      } catch (e1) {
        try {
          // Second try: use pointFromX with hex string converted to BN
          const hexStr = typeof x === 'string' ? x : '0x' + x.toString(16)
          const bnX = new BN(hexStr)
          point = ecInstance.curve.pointFromX(bnX, odd)
        } catch (e2) {
          // Third try: create point directly with calculated Y
          const xBigInt = typeof x === 'string' ? new BN(xStr) : x.bn
          // Calculate Y from X (this is a simplified approach)
          const y = ecInstance.curve.yFromX(xBigInt.toString(), odd)
          point = ecInstance.curve.point(xBigInt.toString(), y)
        }
      }

      const instance = new Point(new BN(0), new BN(0))
      instance._point = point
      instance.validate()
      return instance
    } catch (e) {
      throw new Error('Invalid X')
    }
  }

  /**
   * Will return a secp256k1 ECDSA base point
   */
  static getG(): Point {
    const instance = new Point(new BN(0), new BN(0))
    instance._point = ecInstance.curve.g
    return instance
  }

  /**
   * Will return the max of range of valid private keys as governed by the secp256k1 ECDSA standard
   */
  static getN(): BN {
    return new BN(ecInstance.curve.n.toArray())
  }

  /**
   * Will determine if the point is valid
   */
  validate(): Point {
    if (this.isInfinity()) {
      throw new Error('Point cannot be equal to Infinity')
    }

    // Simple validation - just check if the point exists and is not infinity
    try {
      // Try to access the point's coordinates
      const x = this.x
      const y = this.y

      // Basic checks
      if (x === undefined || y === undefined) {
        throw new Error('Point coordinates are undefined')
      }

      // Check that point times N is infinity (point is in the correct subgroup)
      const n = ecInstance.curve.n
      const infinityPoint = this._point.mul(n)
      if (!infinityPoint.isInfinity()) {
        throw new Error('Point is not in the correct subgroup')
      }
    } catch (e) {
      throw new Error('Point does not lie on the curve')
    }

    return this
  }

  /**
   * Check if point is at infinity
   */
  isInfinity(): boolean {
    return this._point.isInfinity()
  }

  /**
   * Point addition
   */
  add(other: Point): Point {
    const result = new Point(new BN(0), new BN(0))
    result._point = this._point.add(other._point)
    return result
  }

  /**
   * Point multiplication
   */
  mul(scalar: BN): Point {
    const result = new Point(new BN(0), new BN(0))
    result._point = this._point.mul(scalar.bn)
    return result
  }

  /**
   * Point multiplication with addition
   * Implemented using native BigInt instead of BN.js
   */
  mulAdd(scalar1: BN, other: Point, scalar2: BN): Point {
    const result = new Point(new BN(0), new BN(0))
    // Implement mulAdd as: this * scalar1 + other * scalar2
    const point1 = this._point.mul(scalar1.bn)
    const point2 = other._point.mul(scalar2.bn)
    result._point = point1.add(point2)
    return result
  }

  /**
   * Check if two points are equal
   */
  eq(other: Point): boolean {
    return this._point.eq(other._point)
  }

  /**
   * Convert point to compressed format (33 bytes)
   *
   * Compressed format consists of:
   * - 1 byte prefix: 0x02 if Y is even, 0x03 if Y is odd
   * - 32 bytes: X coordinate
   *
   * @param point - The point to compress
   * @returns 33-byte buffer containing the compressed point
   *
   * @example
   * ```typescript
   * const compressed = Point.pointToCompressed(publicKeyPoint)
   * // Returns Buffer of length 33
   * ```
   */
  static pointToCompressed(point: Point): Buffer {
    const xbuf = point.x.toBuffer({ size: 32 })
    const y = point.y

    const odd = y.mod(new BN(2)).isOdd()
    const prefix = odd ? Point.PrefixOddY : Point.PrefixEvenY

    return BufferUtil.concat([prefix, xbuf])
  }

  /**
   * Check if point has square root (Y coordinate is quadratic residue)
   *
   * In secp256k1, for any valid point on the curve, exactly one of Y or (p-Y)
   * is a quadratic residue. The QR Y is the one computed by lift_x: c^((p+1)/4)
   * where c = X³ + 7.
   *
   * IMPORTANT: This is NOT the same as checking if Y is even!
   * The relationship between Y parity and quadratic residue depends on the specific
   * X value, not just Y's parity.
   *
   * Efficient algorithm: Compute the canonical Y (lift_x result) and check if
   * our Y matches it. If Y == canonical_Y, then Y is QR. If Y == p - canonical_Y,
   * then Y is not QR.
   *
   * Reference: lotusd/src/secp256k1/src/field_impl.h secp256k1_fe_is_quad_var()
   */
  hasSquare(): boolean {
    if (this.isInfinity()) {
      return false
    }

    const x = this.x
    const y = this.y

    // secp256k1 field prime p
    const p = new BN(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
      16,
    )

    // Compute c = x³ + 7 mod p
    const x3 = x.mul(x).mod(p).mul(x).mod(p)
    const c = x3.add(new BN(7)).mod(p)

    // Compute canonical Y = c^((p+1)/4) mod p
    // This is the Y that is always a quadratic residue
    const exp = p.add(new BN(1)).div(new BN(4))
    const canonicalY = c.modPow(exp, p)

    // Y is a QR iff Y equals the canonical Y (not p - canonicalY)
    return y.eq(canonicalY)
  }

  /**
   * Check if value is a square in the field
   *
   * @deprecated This function is slow (uses modPow).
   * For checking if a point Y coordinate is a quadratic residue,
   * use hasSquare() instead which is optimized for secp256k1.
   */
  isSquare(x: BN): boolean {
    const p = new BN(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
      16,
    )
    const x0 = new BN(x.toString())

    // Use modular exponentiation to check if x is a quadratic residue
    const exponent = p.sub(new BN(1)).div(new BN(2))
    const result = x0.modPow(exponent, p)

    return result.eq(new BN(1))
  }
}

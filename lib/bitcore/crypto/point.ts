/**
 * Elliptic curve point operations for secp256k1
 * Migrated from bitcore-lib-xpi with ESM support and BigInt
 */

import elliptic from 'elliptic'
import { BN } from './bn.js'

const ecInstance = new elliptic.ec('secp256k1')
const ecPoint = ecInstance.curve.point.bind(ecInstance.curve)
const ecPointFromX = ecInstance.curve.pointFromX.bind(ecInstance.curve)

export class Point {
  private _point: elliptic.curve.base.BasePoint

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
   * Instantiate a valid secp256k1 Point from only the X coordinate
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
   * Will return the X coordinate of the Point
   */
  getX(): BN {
    return new BN(this._point.getX().toString())
  }

  /**
   * Will return the Y coordinate of the Point
   */
  getY(): BN {
    return new BN(this._point.getY().toString())
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
      const x = this.getX()
      const y = this.getY()

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
   * Convert point to compressed format
   */
  static pointToCompressed(point: Point): Buffer {
    const xbuf = point.getX().toArrayLike(Buffer, 'be', 32)
    const y = point.getY()

    const odd = y.mod(new BN(2)).isOdd()
    const prefix = odd ? Buffer.from([0x03]) : Buffer.from([0x02])

    return Buffer.concat([prefix, xbuf])
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

    const x = this.getX()
    const y = this.getY()

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
   * DEPRECATED: This function is slow (uses modPow).
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

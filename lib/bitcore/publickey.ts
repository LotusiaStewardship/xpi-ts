/**
 * PublicKey implementation for Lotus
 * Migrated from bitcore-lib-xpi with ESM support and BigInt
 */
import { BN } from './crypto/bn'
import { Point } from './crypto/point'
import { Hash } from './crypto/hash'
import { BufferUtil } from './util/buffer'
import { JSUtil } from './util/js'
import {
  Network,
  get as getNetwork,
  defaultNetwork,
  type NetworkName,
} from './networks'
import { PrivateKey } from './privatekey'
import { Address } from './address'
import type { Buffer } from 'buffer/'

/**
 * Internal data structure for public key information
 * Used during public key construction and transformation
 */
export interface PublicKeyData {
  /** The elliptic curve point representing the public key */
  point: Point
  /** Whether the public key is in compressed format */
  compressed: boolean
  /** Optional network the public key is associated with */
  network?: Network
}

/**
 * Additional options for public key construction
 */
export interface PublicKeyExtra {
  /** Network to associate with the public key */
  network?: Network | NetworkName
  /** Whether to use compressed format (default: true) */
  compressed?: boolean
}

/**
 * Plain object representation of a public key with hex-encoded coordinates
 */
export interface PublicKeyObject {
  /** X coordinate as a hex string */
  x: string
  /** Y coordinate as a hex string */
  y: string
  /** Whether the public key is in compressed format */
  compressed: boolean
}

/**
 * Serialized format of a public key for JSON export
 */
export interface PublicKeySerialized {
  /** X coordinate as a 64-character hex string (zero-padded) */
  x: string
  /** Y coordinate as a 64-character hex string (zero-padded) */
  y: string
  /** Whether the public key is in compressed format */
  compressed: boolean
}

/**
 * Valid input types for PublicKey constructor
 * - Point: An elliptic curve point
 * - PublicKeyObject: Object with x/y hex coordinates
 * - string: Hex-encoded DER public key
 * - Buffer: DER-encoded public key buffer
 * - PrivateKey: Derive public key from private key
 */
export type PublicKeyInput =
  | Point
  | PublicKeyObject
  | string
  | Buffer
  | PrivateKey

/** Prefix byte for compressed public key with even Y-coordinate */
export const PUBKEY_PREFIX_EVEN = 0x02
/** Prefix byte for compressed public key with odd Y-coordinate */
export const PUBKEY_PREFIX_ODD = 0x03
/** Prefix byte for uncompressed public key */
export const PUBKEY_PREFIX_UNCOMPRESSED = 0x04

/**
 * PublicKey class for Lotus cryptocurrency
 *
 * Represents a public key on the secp256k1 elliptic curve. Public keys can be
 * created from private keys, DER-encoded buffers, hex strings, or Point objects.
 *
 * Public keys can be in compressed (33 bytes) or uncompressed (65 bytes) format:
 * - Compressed: prefix byte (0x02 for even Y, 0x03 for odd Y) + 32-byte X coordinate
 * - Uncompressed: prefix byte (0x04) + 32-byte X + 32-byte Y coordinates
 *
 * @example
 * ```typescript
 * // From private key
 * const privKey = new PrivateKey()
 * const pubKey = PublicKey.fromPrivateKey(privKey)
 *
 * // From hex string
 * const pubKey = new PublicKey('02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc')
 *
 * // From buffer
 * const pubKey = PublicKey.fromBuffer(buffer)
 *
 * // Get address
 * const address = pubKey.toAddress()
 * ```
 */
export class PublicKey {
  /** The elliptic curve point representing this public key */
  readonly point!: Point
  /** Whether this public key uses compressed format (33 bytes vs 65 bytes) */
  readonly compressed!: boolean
  /** The network this public key is associated with */
  readonly network!: Network

  /** Prefix byte for compressed public key with odd Y-coordinate (0x03) */
  static readonly PrefixOddY = BufferUtil.from([PUBKEY_PREFIX_ODD])
  /** Prefix byte for compressed public key with even Y-coordinate (0x02) */
  static readonly PrefixEvenY = BufferUtil.from([PUBKEY_PREFIX_EVEN])
  /** Prefix byte for uncompressed public key (0x04) */
  static readonly PrefixUncompressed = BufferUtil.from([
    PUBKEY_PREFIX_UNCOMPRESSED,
  ])

  constructor(data: PublicKeyInput, extra?: PublicKeyExtra) {
    if (data instanceof PublicKey) {
      // Return copy, but as it's an immutable object, return same argument
      return data
    }

    if (!data) {
      throw new Error(
        'First argument is required, please include public key data.',
      )
    }

    extra = extra || {}
    const info = this._classifyArgs(data, extra)

    // Validation
    info.point?.validate()

    JSUtil.defineImmutable(this, {
      point: info.point,
      compressed: info.compressed,
      network: info.network || defaultNetwork,
    })
  }

  /**
   * Internal function to differentiate between arguments passed to the constructor.
   * Handles Point objects, PublicKeyObject with x/y coordinates, hex strings,
   * DER-encoded buffers, and PrivateKey instances.
   *
   * @param data - The input data to classify and transform
   * @param extra - Additional options like network and compression preference
   * @returns The classified public key data with point, compressed flag, and optional network
   * @throws {TypeError} If the data format is not recognized
   * @throws {Error} If a valid point cannot be derived from the input
   */
  private _classifyArgs(
    data: PublicKeyInput,
    extra: PublicKeyExtra,
  ): PublicKeyData {
    const info: Partial<PublicKeyData> = {
      compressed: extra.compressed === undefined ? true : extra.compressed,
    }

    // Detect type of data
    if (data instanceof Point) {
      info.point = data
    } else if (
      typeof data === 'object' &&
      data !== null &&
      'x' in data &&
      'y' in data
    ) {
      const objectInfo = PublicKey._transformObject(data as PublicKeyObject)
      Object.assign(info, objectInfo)
    } else if (typeof data === 'string') {
      const derInfo = PublicKey._transformDER(BufferUtil.from(data, 'hex'))
      Object.assign(info, derInfo)
    } else if (PublicKey._isBuffer(data)) {
      const derInfo = PublicKey._transformDER(data)
      Object.assign(info, derInfo)
    } else if (PublicKey._isPrivateKey(data)) {
      const privkeyInfo = PublicKey._transformPrivateKey(data)
      Object.assign(info, privkeyInfo)
    } else {
      throw new TypeError('First argument is an unrecognized data format.')
    }

    if (!info.network) {
      info.network = extra.network ? getNetwork(extra.network) : undefined
    }

    // Ensure we have a valid point
    if (!info.point) {
      throw new Error('Failed to derive a valid point from the input data')
    }

    return info as PublicKeyData
  }

  /**
   * Internal function to detect if an object is a PrivateKey
   */
  private static _isPrivateKey(param: unknown): param is PrivateKey {
    return param instanceof PrivateKey
  }

  /**
   * Internal function to detect if an object is a Buffer
   */
  private static _isBuffer(param: unknown): param is Buffer {
    return BufferUtil.isBuffer(param) || param instanceof Uint8Array
  }

  /**
   * Internal function to transform a private key into a public key point
   */
  private static _transformPrivateKey(privkey: PrivateKey): PublicKeyData {
    if (!PublicKey._isPrivateKey(privkey)) {
      throw new Error('Must be an instance of PrivateKey')
    }
    return {
      point: Point.getG().mul(privkey.bn),
      compressed: privkey.compressed,
      network: privkey.network,
    }
  }

  /**
   * Internal function to transform DER-encoded buffer into a public key point
   *
   * Handles three DER encoding formats:
   * - 0x04: Uncompressed (65 bytes: prefix + 32-byte X + 32-byte Y)
   * - 0x02: Compressed with even Y (33 bytes: prefix + 32-byte X)
   * - 0x03: Compressed with odd Y (33 bytes: prefix + 32-byte X)
   *
   * In non-strict mode, also accepts:
   * - 0x06, 0x07: Hybrid format (treated as uncompressed)
   *
   * @param buf - DER-encoded public key buffer
   * @param strict - If true, only accept standard prefixes (0x02, 0x03, 0x04)
   * @returns Public key data with point and compression flag
   * @throws {Error} If buffer is not a valid buffer type
   * @throws {TypeError} If buffer length is invalid or prefix is unrecognized
   */
  private static _transformDER(
    buf: Buffer,
    strict: boolean = true,
  ): PublicKeyData {
    if (!PublicKey._isBuffer(buf)) {
      throw new Error('Must be a hex buffer of DER encoded public key')
    }

    let point: Point
    let compressed: boolean

    let x: BN
    let y: BN
    let xbuf: Buffer
    let ybuf: Buffer

    // Handle uncompressed format (0x04) or hybrid format in non-strict mode (0x06, 0x07)
    // Uncompressed: 65 bytes = 1 byte prefix + 32 bytes X + 32 bytes Y
    if (
      buf[0] === PUBKEY_PREFIX_UNCOMPRESSED ||
      (!strict && (buf[0] === 0x06 || buf[0] === 0x07))
    ) {
      // Extract X and Y coordinates from buffer
      xbuf = buf.slice(1, 33)
      ybuf = buf.slice(33, 65)

      // Validate buffer lengths
      if (xbuf.length !== 32 || ybuf.length !== 32 || buf.length !== 65) {
        throw new TypeError('Length of x and y must be 32 bytes')
      }

      // Convert buffers to big numbers and create point
      x = BN.fromBuffer(xbuf)
      y = BN.fromBuffer(ybuf)
      point = new Point(x, y)
      compressed = false
    }
    // Handle compressed format (0x02 for even Y, 0x03 for odd Y)
    // Compressed: 33 bytes = 1 byte prefix + 32 bytes X coordinate
    // The Y coordinate is derived from X using the curve equation
    else if (buf[0] === PUBKEY_PREFIX_ODD || buf[0] === PUBKEY_PREFIX_EVEN) {
      xbuf = buf.slice(1)
      x = BN.fromBuffer(xbuf)
      // Determine Y parity from prefix byte and derive full point
      const isOdd = buf[0] === PUBKEY_PREFIX_ODD
      const xInfo = PublicKey._transformX(isOdd, x)
      point = xInfo.point
      compressed = true
    }
    // Unrecognized prefix byte
    else {
      throw new TypeError('Invalid DER format public key')
    }

    return {
      point,
      compressed,
    }
  }

  /**
   * Internal function to transform X into a public key point
   */
  private static _transformX(odd: boolean, x: BN): PublicKeyData {
    if (typeof odd !== 'boolean') {
      throw new Error('Must specify whether y is odd or not (true or false)')
    }
    return {
      point: Point.fromX(odd, x),
      compressed: true,
    }
  }

  /**
   * Internal function to transform a JSON into a public key point
   */
  private static _transformObject(json: PublicKeyObject): PublicKeyData {
    const x = BN.fromString(json.x, 'hex')
    const y = BN.fromString(json.y, 'hex')
    const point = new Point(x, y)
    return {
      point: point,
      compressed: json.compressed,
    }
  }

  /**
   * Instantiate a PublicKey from a PrivateKey
   */
  static fromPrivateKey(privkey: PrivateKey): PublicKey {
    if (!PublicKey._isPrivateKey(privkey)) {
      throw new Error('Must be an instance of PrivateKey')
    }
    const info = PublicKey._transformPrivateKey(privkey)
    return new PublicKey(info.point, {
      compressed: info.compressed,
      network: info.network,
    })
  }

  /**
   * Instantiate a PublicKey from a Buffer
   */
  static fromDER(buf: Buffer, strict?: boolean): PublicKey {
    if (!PublicKey._isBuffer(buf)) {
      throw new Error('Must be a hex buffer of DER encoded public key')
    }
    const info = PublicKey._transformDER(buf, strict)
    return new PublicKey(info.point, {
      compressed: info.compressed,
    })
  }

  /**
   * Instantiate a PublicKey from a Buffer (alias for fromDER)
   */
  static fromBuffer(buf: Buffer, strict?: boolean): PublicKey {
    return PublicKey.fromDER(buf, strict)
  }

  /**
   * Instantiate a PublicKey from a Point
   */
  static fromPoint(point: Point, compressed?: boolean): PublicKey {
    if (!(point instanceof Point)) {
      throw new Error('First argument must be an instance of Point.')
    }
    return new PublicKey(point, {
      compressed: compressed,
    })
  }

  /**
   * Instantiate a PublicKey from a DER hex encoded string
   */
  static fromString(str: string, encoding?: BufferEncoding): PublicKey {
    const buf = BufferUtil.from(str, encoding || 'hex')
    const info = PublicKey._transformDER(buf)
    return new PublicKey(info.point, {
      compressed: info.compressed,
    })
  }

  /**
   * Instantiate a PublicKey from an X Point
   */
  static fromX(odd: boolean, x: BN): PublicKey {
    const info = PublicKey._transformX(odd, x)
    return new PublicKey(info.point, {
      compressed: info.compressed,
    })
  }

  /**
   * Check if there would be any errors when initializing a PublicKey
   */
  static getValidationError(data: PublicKeyInput): Error | null {
    try {
      new PublicKey(data)
      return null
    } catch (e) {
      return e as Error
    }
  }

  /**
   * Check if the parameters are valid
   */
  static isValid(data: PublicKeyInput): boolean
  static isValid(data: PublicKey): boolean
  static isValid(data: PublicKeyInput | PublicKey): boolean {
    if (data instanceof PublicKey) {
      return true // A PublicKey instance is always valid
    }
    return !PublicKey.getValidationError(data)
  }

  /**
   * Returns a plain object of the PublicKey
   */
  toObject(): PublicKeySerialized {
    return {
      x: this.point.x.toString(16).padStart(64, '0'),
      y: this.point.y.toString(16).padStart(64, '0'),
      compressed: this.compressed,
    }
  }

  /**
   * Returns a JSON representation (same as toObject)
   */
  toJSON(): PublicKeySerialized {
    return this.toObject()
  }

  /**
   * Will return the public key as a BN instance
   */
  toBigNumber(): BN {
    return this.point.x
  }

  /**
   * Will output the PublicKey to a DER Buffer
   */
  toBuffer(): Buffer {
    return this.toDER()
  }

  /**
   * Will output the PublicKey to a DER Buffer
   */
  toDER(): Buffer {
    const x = this.point.x
    const y = this.point.y

    const xbuf = x.toBuffer({ size: 32 })
    const ybuf = y.toBuffer({ size: 32 })

    let prefix: Buffer
    if (!this.compressed) {
      prefix = BufferUtil.from([0x04])
      return BufferUtil.concat([prefix, xbuf, ybuf])
    } else {
      const odd = y.mod(new BN(2)).eq(BN.One)
      if (odd) {
        prefix = PublicKey.PrefixOddY
      } else {
        prefix = PublicKey.PrefixEvenY
      }
      return BufferUtil.concat([prefix, xbuf])
    }
  }

  /**
   * Will return a sha256 + ripemd160 hash of the serialized public key
   */
  _getID(): Buffer {
    return Hash.sha256ripemd160(this.toBuffer())
  }

  /**
   * Will return an address for the public key
   */
  toAddress(network?: Network | NetworkName): Address {
    return Address.fromPublicKey(this, network)
  }

  /**
   * Will output the PublicKey to a DER encoded hex string
   */
  toString(): string {
    return this.toDER().toString('hex')
  }

  /**
   * Will return a string formatted for the console
   */
  inspect(): string {
    return `<PublicKey: ${this.toString()}${this.compressed ? '' : ', uncompressed'}>`
  }

  /**
   * Add a scalar to this public key (for Taproot tweaking)
   *
   * Computes: this_pubkey + scalar * G
   *
   * This is used in Taproot to compute the tweaked public key:
   * tweaked_pubkey = internal_pubkey + tagged_hash("TapTweak", ...) * G
   *
   * Reference: lotusd/src/pubkey.cpp CPubKey::AddScalar()
   *
   * @param scalar - 32-byte scalar value (as Buffer or BN)
   * @returns New tweaked public key
   * @throws Error if tweak results in invalid key
   */
  addScalar(scalar: Buffer | BN): PublicKey {
    const scalarBN = BufferUtil.isBuffer(scalar) ? new BN(scalar) : scalar

    // Compute scalar * G
    const G = Point.getG()
    const tweakPoint = G.mul(scalarBN)

    // Add to current public key point
    const tweakedPoint = this.point.add(tweakPoint)

    // Validate the result
    tweakedPoint.validate()

    // Create new public key with tweaked point
    return new PublicKey(tweakedPoint, {
      compressed: this.compressed,
      network: this.network,
    })
  }

  /**
   * Get the secp256k1 curve order N
   *
   * The curve order N is the number of points on the elliptic curve.
   * All scalar operations (private keys, tweaks, nonces) must be performed modulo N.
   *
   * N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
   *
   * Used for:
   * - Validating private keys are in range [1, N-1]
   * - Modular arithmetic in signature generation (k, s values)
   * - Computing low-S form: if s > N/2, use N - s
   * - Taproot scalar tweaking operations
   *
   * @returns The curve order as a BN instance
   */
  static getN(): BN {
    return Point.getN()
  }
}

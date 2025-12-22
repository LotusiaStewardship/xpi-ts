/**
 * PublicKey implementation for Lotus
 * Migrated from bitcore-lib-xpi with ESM support and BigInt
 */

import { BN } from './crypto/bn.js'
import { Point } from './crypto/point.js'
import { Hash } from './crypto/hash.js'
import { JSUtil } from './util/js.js'
import { Network, get as getNetwork, defaultNetwork } from './networks.js'
import { PrivateKey } from './privatekey.js'
import { Address } from './address.js'

export interface PublicKeyData {
  point: Point
  compressed: boolean
  network?: Network
}

export interface PublicKeyExtra {
  network?: Network | string
  compressed?: boolean
}

export interface PublicKeyObject {
  x: string
  y: string
  compressed: boolean
}

export interface PublicKeySerialized {
  x: string
  y: string
  compressed: boolean
}

export type PublicKeyInput =
  | Point
  | PublicKeyObject
  | string
  | Buffer
  | PrivateKey

export class PublicKey {
  readonly point!: Point
  readonly compressed!: boolean
  readonly network!: Network

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
   * Internal function to differentiate between arguments passed to the constructor
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
      const derInfo = PublicKey._transformDER(Buffer.from(data, 'hex'))
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
    return Buffer.isBuffer(param) || param instanceof Uint8Array
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
   * Internal function to transform DER into a public key point
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

    if (buf[0] === 0x04 || (!strict && (buf[0] === 0x06 || buf[0] === 0x07))) {
      xbuf = buf.subarray(1, 33)
      ybuf = buf.subarray(33, 65)
      if (xbuf.length !== 32 || ybuf.length !== 32 || buf.length !== 65) {
        throw new TypeError('Length of x and y must be 32 bytes')
      }
      x = new BN(xbuf, 'be')
      y = new BN(ybuf, 'be')
      point = new Point(x, y)
      compressed = false
    } else if (buf[0] === 0x03) {
      xbuf = buf.subarray(1)
      x = new BN(xbuf, 'be')
      const xInfo = PublicKey._transformX(true, x) // 0x03 means Y is odd
      point = xInfo.point
      compressed = true
    } else if (buf[0] === 0x02) {
      xbuf = buf.subarray(1)
      x = new BN(xbuf, 'be')
      const xInfo = PublicKey._transformX(false, x) // 0x02 means Y is even
      point = xInfo.point
      compressed = true
    } else {
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
    const x = new BN(json.x, 16)
    const y = new BN(json.y, 16)
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
  static fromString(str: string, encoding?: string): PublicKey {
    const buf = Buffer.from(str, (encoding as BufferEncoding) || 'hex')
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
      x: this.point.getX().toString(16).padStart(64, '0'),
      y: this.point.getY().toString(16).padStart(64, '0'),
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
    return this.point.getX()
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
    const x = this.point.getX()
    const y = this.point.getY()

    const xbuf = x.toArrayLike(Buffer, 'be', 32)
    const ybuf = y.toArrayLike(Buffer, 'be', 32)

    let prefix: Buffer
    if (!this.compressed) {
      prefix = Buffer.from([0x04])
      return Buffer.concat([prefix, xbuf, ybuf])
    } else {
      const odd = y.mod(new BN(2)).eq(new BN(1))
      if (odd) {
        prefix = Buffer.from([0x03])
      } else {
        prefix = Buffer.from([0x02])
      }
      return Buffer.concat([prefix, xbuf])
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
  toAddress(network?: Network | string): Address {
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
    const scalarBN = Buffer.isBuffer(scalar) ? new BN(scalar) : scalar

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
   * Get the curve order N (for modular arithmetic)
   */
  static getN(): BN {
    return Point.getN()
  }
}

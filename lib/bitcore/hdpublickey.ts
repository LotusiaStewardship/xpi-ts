/**
 * HDPublicKey implementation for Hierarchical Deterministic public keys
 * Migrated from bitcore-lib-xpi with ESM support
 */

import { BN } from './crypto/bn.js'
import { PublicKey } from './publickey.js'
import { HDPrivateKey } from './hdprivatekey.js'
import { Network, get as getNetwork, defaultNetwork } from './networks.js'
import { Hash } from './crypto/hash.js'
import { Base58Check } from './encoding/base58check.js'
import { JSUtil } from './util/js.js'
import { Preconditions } from './util/preconditions.js'
import { Point } from './crypto/point.js'
import type { HDPrivateKeyBuffers } from './hdprivatekey.js'

export interface HDPublicKeyData {
  xpubkey?: string
  network?: Network
  depth?: number
  parentFingerPrint?: Buffer
  childIndex?: number
  chainCode?: Buffer
  publicKey?: PublicKey
}

export interface HDPublicKeyObject {
  xpubkey: string
  network: string
  depth: number
  fingerPrint: string
  parentFingerPrint: string
  childIndex: number
  chainCode: string
  publicKey: string
}

export interface HDPublicKeyBuffers {
  version: Buffer
  depth: Buffer
  parentFingerPrint: Buffer
  childIndex: Buffer
  chainCode: Buffer
  publicKey: Buffer
  checksum?: Buffer
  xpubkey?: Buffer
  privateKey?: Buffer
  xprivkey?: Buffer
}

export class HDPublicKey {
  readonly xpubkey!: Buffer
  readonly network!: Network
  readonly depth!: number
  readonly publicKey!: PublicKey
  readonly fingerPrint!: Buffer
  readonly parentFingerPrint!: Buffer
  readonly childIndex!: number
  readonly chainCode!: Buffer
  private _buffers!: HDPublicKeyBuffers // Internal buffers for serialization

  // Constants to match reference
  static readonly Hardened = 0x80000000
  static readonly RootElementAlias = ['m', 'M']
  static readonly VersionSize = 4
  static readonly DepthSize = 1
  static readonly ParentFingerPrintSize = 4
  static readonly ChildIndexSize = 4
  static readonly ChainCodeSize = 32
  static readonly PublicKeySize = 33
  static readonly CheckSumSize = 4
  static readonly DataSize = 78
  static readonly SerializedByteSize = 82

  // Buffer position constants
  static readonly VersionStart = 0
  static readonly VersionEnd =
    HDPublicKey.VersionStart + HDPublicKey.VersionSize
  static readonly DepthStart = HDPublicKey.VersionEnd
  static readonly DepthEnd = HDPublicKey.DepthStart + HDPublicKey.DepthSize
  static readonly ParentFingerPrintStart = HDPublicKey.DepthEnd
  static readonly ParentFingerPrintEnd =
    HDPublicKey.ParentFingerPrintStart + HDPublicKey.ParentFingerPrintSize
  static readonly ChildIndexStart = HDPublicKey.ParentFingerPrintEnd
  static readonly ChildIndexEnd =
    HDPublicKey.ChildIndexStart + HDPublicKey.ChildIndexSize
  static readonly ChainCodeStart = HDPublicKey.ChildIndexEnd
  static readonly ChainCodeEnd =
    HDPublicKey.ChainCodeStart + HDPublicKey.ChainCodeSize
  static readonly PublicKeyStart = HDPublicKey.ChainCodeEnd
  static readonly PublicKeyEnd =
    HDPublicKey.PublicKeyStart + HDPublicKey.PublicKeySize
  static readonly ChecksumStart = HDPublicKey.PublicKeyEnd
  static readonly ChecksumEnd =
    HDPublicKey.ChecksumStart + HDPublicKey.CheckSumSize

  constructor(
    arg: string | Buffer | HDPublicKeyData | HDPublicKeyObject | HDPrivateKey,
  ) {
    if (arg instanceof HDPublicKey) {
      return arg
    }
    if (!(this instanceof HDPublicKey)) {
      return new HDPublicKey(arg)
    }
    if (arg) {
      if (typeof arg === 'string' || Buffer.isBuffer(arg)) {
        const error = HDPublicKey.getSerializedError(arg)
        if (!error) {
          return this._buildFromSerialized(arg)
        } else if (
          Buffer.isBuffer(arg) &&
          !HDPublicKey.getSerializedError(arg.toString())
        ) {
          return this._buildFromSerialized(arg.toString())
        } else {
          throw error
        }
      } else {
        if (typeof arg === 'object' && arg !== null) {
          if (arg instanceof HDPrivateKey) {
            return this._buildFromPrivate(arg)
          } else {
            return this._buildFromObject(
              arg as HDPublicKeyData | HDPublicKeyObject,
            )
          }
        } else {
          throw new Error('Unrecognized argument')
        }
      }
    } else {
      throw new Error('Must supply an argument to create a HDPublicKey')
    }
  }

  /**
   * Verifies that a given path is valid
   */
  static isValidPath(arg: string | number): boolean {
    if (typeof arg === 'string') {
      // Simplified implementation since HDPrivateKey._getDerivationIndexes is not available
      const indexes = arg.split('/').slice(1).map(Number)
      return indexes.every(HDPublicKey.isValidPath)
    }

    if (typeof arg === 'number') {
      return arg >= 0 && arg < HDPublicKey.Hardened
    }

    return false
  }

  /**
   * Verifies that a given serialized public key in base58 with checksum format is valid
   */
  static isValidSerialized(
    data: string | Buffer,
    network?: string | Network,
  ): boolean {
    return HDPublicKey.getSerializedError(data, network) === null
  }

  /**
   * Checks what's the error that causes the validation of a serialized public key to fail
   */
  static getSerializedError(
    data: string | Buffer,
    network?: string | Network,
  ): Error | null {
    if (!(typeof data === 'string' || Buffer.isBuffer(data))) {
      return new Error('expected buffer or string')
    }
    if (typeof data === 'string' && !JSUtil.isHexa(data)) {
      try {
        Base58Check.decode(data)
      } catch (e) {
        return new Error('Invalid base58 checksum')
      }
    }
    if (Buffer.isBuffer(data) && data.length !== HDPublicKey.DataSize) {
      return new Error('Invalid length')
    }
    if (typeof data === 'string') {
      const decoded = Base58Check.decode(data)
      if (decoded.length !== HDPublicKey.DataSize) {
        return new Error('Invalid length')
      }
    }
    if (network !== undefined) {
      const error = HDPublicKey._validateNetwork(data, network)
      if (error) {
        return error
      }
    }
    return null
  }

  /**
   * Validate network
   */
  private static _validateNetwork(
    data: string | Buffer,
    networkArg: string | Network,
  ): Error | null {
    const network = getNetwork(networkArg)
    if (!network) {
      return new Error('Invalid network argument')
    }
    const version = Buffer.isBuffer(data)
      ? data.subarray(HDPublicKey.VersionStart, HDPublicKey.VersionEnd)
      : Buffer.from(
          Base58Check.decode(data).subarray(
            HDPublicKey.VersionStart,
            HDPublicKey.VersionEnd,
          ),
        )
    if (version.readUInt32BE(0) !== network.xpubkey) {
      return new Error('Invalid network')
    }
    return null
  }

  /**
   * Create HDPublicKey from string
   */
  static fromString(arg: string): HDPublicKey {
    Preconditions.checkArgument(
      typeof arg === 'string',
      'No valid string was provided',
    )
    return new HDPublicKey(arg)
  }

  /**
   * Create HDPublicKey from object
   */
  static fromObject(arg: HDPublicKeyData | HDPublicKeyObject): HDPublicKey {
    Preconditions.checkArgument(
      typeof arg === 'object',
      'No valid argument was provided',
    )
    return new HDPublicKey(arg)
  }

  /**
   * Create HDPublicKey from buffer
   */
  static fromBuffer(arg: Buffer): HDPublicKey {
    return new HDPublicKey(arg)
  }

  private _classifyArguments(
    arg: string | Buffer | HDPublicKeyData | HDPublicKeyObject,
  ): HDPublicKeyData {
    if (typeof arg === 'string') {
      return HDPublicKey._transformString(arg)
    } else if (Buffer.isBuffer(arg)) {
      return HDPublicKey._transformBuffer(arg)
    } else if (typeof arg === 'object' && arg !== null) {
      if ('xpubkey' in arg) {
        return HDPublicKey._transformObject(arg as HDPublicKeyObject)
      } else {
        return arg as HDPublicKeyData
      }
    } else {
      throw new Error('Invalid HDPublicKey data')
    }
  }

  private static _transformString(str: string): HDPublicKeyData {
    if (!JSUtil.isHexa(str)) {
      return HDPublicKey._transformSerialized(str)
    }
    return HDPublicKey._transformBuffer(Buffer.from(str, 'hex'))
  }

  private static _transformSerialized(str: string): HDPublicKeyData {
    const buf = Base58Check.decode(str)
    return HDPublicKey._transformBuffer(buf)
  }

  private static _transformBuffer(buf: Buffer): HDPublicKeyData {
    if (buf.length !== 78) {
      throw new Error('Invalid HDPublicKey buffer length')
    }

    const version = buf.readUInt32BE(0)
    const network = getNetwork(version, 'xpubkey')
    if (!network) {
      throw new Error('Invalid HDPublicKey network')
    }

    const depth = buf.readUInt8(4)
    const parentFingerPrint = buf.subarray(5, 9)
    const childIndex = buf.readUInt32BE(9)
    const chainCode = buf.subarray(13, 45)
    const publicKeyBuffer = buf.subarray(45, 78)

    return {
      network,
      depth,
      parentFingerPrint,
      childIndex,
      chainCode,
      publicKey: PublicKey.fromBuffer(publicKeyBuffer),
    }
  }

  private static _transformObject(obj: HDPublicKeyObject): HDPublicKeyData {
    const network = getNetwork(obj.network)
    if (!network) {
      throw new Error('Invalid network')
    }

    return {
      network,
      depth: obj.depth,
      parentFingerPrint: Buffer.from(obj.parentFingerPrint, 'hex'),
      childIndex: obj.childIndex,
      chainCode: Buffer.from(obj.chainCode, 'hex'),
      publicKey: PublicKey.fromBuffer(Buffer.from(obj.publicKey, 'hex')),
    }
  }

  /**
   * Build from HDPrivateKey
   */
  private _buildFromPrivate(arg: HDPrivateKey): HDPublicKey {
    const args: HDPublicKeyBuffers = {
      version: arg._buffers.version,
      depth: arg._buffers.depth,
      parentFingerPrint: arg._buffers.parentFingerPrint,
      childIndex: arg._buffers.childIndex,
      chainCode: arg._buffers.chainCode,
      publicKey: Point.pointToCompressed(
        Point.getG().mul(new BN(arg._buffers.privateKey)),
      ),
      checksum: arg._buffers.checksum,
    }
    return this._buildFromBuffers(args)
  }

  /**
   * Build from serialized data
   */
  private _buildFromSerialized(arg: string | Buffer): HDPublicKey {
    const decoded = typeof arg === 'string' ? Base58Check.decode(arg) : arg
    const buffers: HDPublicKeyBuffers = {
      version: decoded.subarray(
        HDPublicKey.VersionStart,
        HDPublicKey.VersionEnd,
      ),
      depth: decoded.subarray(HDPublicKey.DepthStart, HDPublicKey.DepthEnd),
      parentFingerPrint: decoded.subarray(
        HDPublicKey.ParentFingerPrintStart,
        HDPublicKey.ParentFingerPrintEnd,
      ),
      childIndex: decoded.subarray(
        HDPublicKey.ChildIndexStart,
        HDPublicKey.ChildIndexEnd,
      ),
      chainCode: decoded.subarray(
        HDPublicKey.ChainCodeStart,
        HDPublicKey.ChainCodeEnd,
      ),
      publicKey: decoded.subarray(
        HDPublicKey.PublicKeyStart,
        HDPublicKey.PublicKeyEnd,
      ),
      checksum: decoded.subarray(
        HDPublicKey.ChecksumStart,
        HDPublicKey.ChecksumEnd,
      ),
      xpubkey: typeof arg === 'string' ? Buffer.from(arg) : arg,
    }
    return this._buildFromBuffers(buffers)
  }

  /**
   * Build from buffers
   */
  private _buildFromBuffers(arg: HDPublicKeyBuffers): HDPublicKey {
    HDPublicKey._validateBufferArguments(arg)

    JSUtil.defineImmutable(this, {
      _buffers: arg,
    })

    const sequence = [
      arg.version,
      arg.depth,
      arg.parentFingerPrint,
      arg.childIndex,
      arg.chainCode,
      arg.publicKey,
    ]
    const concat = Buffer.concat(sequence)
    const checksum = Base58Check.checksum(concat)
    if (!arg.checksum || !arg.checksum.length) {
      arg.checksum = checksum
    } else {
      if (arg.checksum.toString('hex') !== checksum.toString('hex')) {
        throw new Error('Invalid base58 checksum')
      }
    }
    const network = getNetwork(arg.version.readUInt32BE(0))

    const xpubkey = Base58Check.encode(Buffer.concat(sequence))
    arg.xpubkey = Buffer.from(xpubkey)

    const publicKey = new PublicKey(arg.publicKey, { network })
    const size = HDPublicKey.ParentFingerPrintSize
    const fingerPrint = Hash.sha256ripemd160(publicKey.toBuffer()).subarray(
      0,
      size,
    )

    JSUtil.defineImmutable(this, {
      xpubkey: xpubkey,
      network: network,
      depth: arg.depth.readUInt8(0),
      publicKey: publicKey,
      fingerPrint: fingerPrint,
    })

    return this
  }

  /**
   * Validate buffer arguments
   */
  private static _validateBufferArguments(arg: HDPublicKeyBuffers): void {
    const checkBuffer = (name: string, size: number) => {
      const buff = arg[name as keyof HDPublicKeyBuffers]
      if (!Buffer.isBuffer(buff)) {
        throw new Error(`${name} argument is not a buffer, it's ${typeof buff}`)
      }
      if (buff.length !== size) {
        throw new Error(
          `${name} has not the expected size: found ${buff.length}, expected ${size}`,
        )
      }
    }
    checkBuffer('version', HDPublicKey.VersionSize)
    checkBuffer('depth', HDPublicKey.DepthSize)
    checkBuffer('parentFingerPrint', HDPublicKey.ParentFingerPrintSize)
    checkBuffer('childIndex', HDPublicKey.ChildIndexSize)
    checkBuffer('chainCode', HDPublicKey.ChainCodeSize)
    checkBuffer('publicKey', HDPublicKey.PublicKeySize)
    if (arg.checksum && arg.checksum.length) {
      checkBuffer('checksum', HDPublicKey.CheckSumSize)
    }
  }

  private _buildFromObject(
    arg: HDPublicKeyData | HDPublicKeyObject,
  ): HDPublicKey {
    const buffers: HDPublicKeyBuffers = {
      version: Buffer.alloc(4),
      depth:
        typeof arg.depth === 'number'
          ? Buffer.from([arg.depth])
          : Buffer.alloc(1), // Default empty buffer
      parentFingerPrint:
        typeof arg.parentFingerPrint === 'number'
          ? Buffer.from([arg.parentFingerPrint])
          : Buffer.isBuffer(arg.parentFingerPrint)
            ? arg.parentFingerPrint
            : Buffer.alloc(4),
      childIndex: Buffer.alloc(4), // Default empty buffer
      chainCode:
        typeof arg.chainCode === 'string'
          ? Buffer.from(arg.chainCode, 'hex')
          : Buffer.isBuffer(arg.chainCode)
            ? arg.chainCode
            : Buffer.alloc(32),
      publicKey:
        typeof arg.publicKey === 'string'
          ? Buffer.from(arg.publicKey, 'hex')
          : Buffer.isBuffer(arg.publicKey)
            ? arg.publicKey
            : arg.publicKey?.toBuffer() || Buffer.alloc(33),
      checksum: undefined, // Will be calculated automatically
    }

    // Write the version as a 32-bit big-endian integer
    if (arg.network) {
      const network = getNetwork(arg.network)
      if (network) {
        buffers.version.writeUInt32BE(network.xpubkey, 0)
      }
    }

    // Write the childIndex as a 32-bit big-endian integer
    if (typeof arg.childIndex === 'number') {
      buffers.childIndex.writeUInt32BE(arg.childIndex, 0)
    }
    return this._buildFromBuffers(buffers)
  }

  /**
   * Derive child key
   */
  derive(arg: string | number, hardened?: boolean): HDPublicKey {
    return this.deriveChild(arg, hardened)
  }

  /**
   * Derive child key (main implementation)
   */
  deriveChild(arg: string | number, hardened?: boolean): HDPublicKey {
    if (typeof arg === 'number') {
      return this._deriveWithNumber(arg, hardened)
    } else if (typeof arg === 'string') {
      return this._deriveFromString(arg)
    } else {
      throw new Error('Invalid derivation argument')
    }
  }

  /**
   * Derive with number
   */
  private _deriveWithNumber(index: number, hardened?: boolean): HDPublicKey {
    if (index >= HDPublicKey.Hardened || hardened) {
      throw new Error('Cannot derive hardened keys from public key')
    }
    if (index < 0) {
      throw new Error('Invalid path')
    }

    // Create 4-byte big-endian index buffer (BIP32 standard)
    const indexBuffer = Buffer.alloc(4)
    indexBuffer.writeUInt32BE(index, 0)
    const data = Buffer.concat([this.publicKey.toBuffer(), indexBuffer])
    const hash = Hash.sha512hmac(data, this._buffers.chainCode)
    const leftPart = new BN(hash.subarray(0, 32))
    const chainCode = hash.subarray(32, 64)

    let publicKey: PublicKey
    try {
      publicKey = PublicKey.fromPoint(
        Point.getG().mul(leftPart).add(this.publicKey.point),
      )
    } catch (e) {
      return this._deriveWithNumber(index + 1)
    }

    const derived = new HDPublicKey({
      network: this.network,
      depth: this.depth + 1,
      parentFingerPrint: this.fingerPrint,
      childIndex: index,
      chainCode: chainCode,
      publicKey: publicKey,
    })

    return derived
  }

  /**
   * Derive from string path
   */
  private _deriveFromString(path: string): HDPublicKey {
    if (path.includes("'")) {
      throw new Error('Cannot derive hardened keys from public key')
    } else if (!HDPublicKey.isValidPath(path)) {
      throw new Error('Invalid path')
    }

    // For now, we'll implement a simplified version since HDPrivateKey._getDerivationIndexes is not available
    const indexes = path.split('/').slice(1).map(Number)
    const derived = indexes.reduce((prev: HDPublicKey, index: number) => {
      return prev._deriveWithNumber(index)
    }, this)

    return derived
  }

  /**
   * Convert to string
   */
  toString(): string {
    return this.xpubkey.toString()
  }

  /**
   * Convert to buffer
   */
  toBuffer(): Buffer {
    return Buffer.from(this._buffers.xpubkey || Buffer.alloc(0))
  }

  /**
   * Convert to object
   */
  toObject(): HDPublicKeyObject {
    return {
      network: this.network.name,
      depth: this.depth,
      fingerPrint: this.fingerPrint.toString('hex'),
      parentFingerPrint: this._buffers.parentFingerPrint.toString('hex'),
      childIndex: this._buffers.childIndex.readUInt32BE(0),
      chainCode: this._buffers.chainCode.toString('hex'),
      publicKey: this.publicKey.toString(),
      xpubkey: this.xpubkey.toString(),
    }
  }

  /**
   * Convert to JSON
   */
  toJSON(): string {
    return JSON.stringify(this.toObject())
  }

  /**
   * Get string representation for console
   */
  inspect(): string {
    return '<HDPublicKey: ' + this.xpubkey + '>'
  }
}

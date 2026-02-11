/**
 * HDPublicKey implementation for Hierarchical Deterministic public keys
 * Migrated from bitcore-lib-xpi with ESM support
 */
import { BN } from './crypto/bn'
import { PublicKey } from './publickey'
import { HDPrivateKey } from './hdprivatekey'
import { Network, get as getNetwork, type NetworkName } from './networks'
import { Hash } from './crypto/hash'
import { Base58Check } from './encoding/base58check'
import { JSUtil, BufferUtil } from './util'
import { Preconditions } from './util/preconditions'
import { Point } from './crypto/point'
import type { Buffer } from 'buffer/'

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
  network: NetworkName
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

export type HDPublicKeyInput =
  | string
  | Buffer
  | HDPublicKeyData
  | HDPublicKeyObject

/**
 * Hierarchical Deterministic Public Key (BIP32)
 *
 * Represents an extended public key that can derive child public keys
 * without access to the corresponding private key. This enables watch-only
 * wallets and public key derivation for non-hardened paths.
 *
 * @example
 * ```typescript
 * // Create from xpub string
 * const hdPubKey = new HDPublicKey('xpub...')
 *
 * // Create from HDPrivateKey
 * const hdPubKey = hdPrivKey.hdPublicKey
 *
 * // Derive child keys (non-hardened only)
 * const child = hdPubKey.derive("m/0/1")
 * const childByIndex = hdPubKey.deriveChild(0)
 * ```
 */
export class HDPublicKey {
  /** The Base58Check-encoded extended public key string */
  readonly xpubkey!: Buffer
  /** The network this key belongs to */
  readonly network!: Network
  /** The depth in the HD tree (0 for master key) */
  readonly depth!: number
  /** The public key */
  readonly publicKey!: PublicKey
  /** The fingerprint of this key (first 4 bytes of HASH160 of public key) */
  readonly fingerPrint!: Buffer
  /** The fingerprint of the parent key */
  readonly parentFingerPrint!: Buffer
  /** The child index used to derive this key */
  readonly childIndex!: number
  /** The chain code used for child key derivation */
  readonly chainCode!: Buffer
  /** Internal buffers for serialization */
  private _buffers!: HDPublicKeyBuffers

  /** Hardened key derivation threshold (2^31) */
  static readonly Hardened = 0x80000000
  /** Valid aliases for the root element in derivation paths */
  static readonly RootElementAlias = ['m', 'M']
  /** Size of the version field in bytes */
  static readonly VersionSize = 4
  /** Size of the depth field in bytes */
  static readonly DepthSize = 1
  /** Size of the parent fingerprint field in bytes */
  static readonly ParentFingerPrintSize = 4
  /** Size of the child index field in bytes */
  static readonly ChildIndexSize = 4
  /** Size of the chain code field in bytes */
  static readonly ChainCodeSize = 32
  /** Size of the public key field in bytes */
  static readonly PublicKeySize = 33
  /** Size of the checksum field in bytes */
  static readonly CheckSumSize = 4
  /** Total size of the data portion (without checksum) in bytes */
  static readonly DataSize = 78
  /** Total size of the serialized key (with checksum) in bytes */
  static readonly SerializedByteSize = 82

  /** Start position of version field in serialized buffer */
  static readonly VersionStart = 0
  /** End position of version field in serialized buffer */
  static readonly VersionEnd =
    HDPublicKey.VersionStart + HDPublicKey.VersionSize
  /** Start position of depth field in serialized buffer */
  static readonly DepthStart = HDPublicKey.VersionEnd
  /** End position of depth field in serialized buffer */
  static readonly DepthEnd = HDPublicKey.DepthStart + HDPublicKey.DepthSize
  /** Start position of parent fingerprint field in serialized buffer */
  static readonly ParentFingerPrintStart = HDPublicKey.DepthEnd
  /** End position of parent fingerprint field in serialized buffer */
  static readonly ParentFingerPrintEnd =
    HDPublicKey.ParentFingerPrintStart + HDPublicKey.ParentFingerPrintSize
  /** Start position of child index field in serialized buffer */
  static readonly ChildIndexStart = HDPublicKey.ParentFingerPrintEnd
  /** End position of child index field in serialized buffer */
  static readonly ChildIndexEnd =
    HDPublicKey.ChildIndexStart + HDPublicKey.ChildIndexSize
  /** Start position of chain code field in serialized buffer */
  static readonly ChainCodeStart = HDPublicKey.ChildIndexEnd
  /** End position of chain code field in serialized buffer */
  static readonly ChainCodeEnd =
    HDPublicKey.ChainCodeStart + HDPublicKey.ChainCodeSize
  /** Start position of public key field in serialized buffer */
  static readonly PublicKeyStart = HDPublicKey.ChainCodeEnd
  /** End position of public key field in serialized buffer */
  static readonly PublicKeyEnd =
    HDPublicKey.PublicKeyStart + HDPublicKey.PublicKeySize
  /** Start position of checksum field in serialized buffer */
  static readonly ChecksumStart = HDPublicKey.PublicKeyEnd
  /** End position of checksum field in serialized buffer */
  static readonly ChecksumEnd =
    HDPublicKey.ChecksumStart + HDPublicKey.CheckSumSize

  /**
   * Creates a new HDPublicKey instance.
   *
   * @param data - The data to create the HDPublicKey from. Can be:
   *   - A Base58Check-encoded xpub string
   *   - A Buffer containing the serialized key
   *   - An HDPublicKeyData object with key components
   *   - An HDPublicKeyObject with string representations
   *   - An HDPrivateKey to extract the public key from
   * @throws Error if the data is invalid or cannot be parsed
   *
   * @example
   * ```typescript
   * // From xpub string
   * const hdPubKey = new HDPublicKey('xpub...')
   *
   * // From HDPrivateKey
   * const hdPubKey = new HDPublicKey(hdPrivateKey)
   *
   * // From object
   * const hdPubKey = new HDPublicKey({
   *   network: 'mainnet',
   *   depth: 0,
   *   parentFingerPrint: BufferUtil.alloc(4),
   *   childIndex: 0,
   *   chainCode: chainCodeBuffer,
   *   publicKey: publicKey
   * })
   * ```
   */
  constructor(data: HDPublicKeyInput) {
    if (data instanceof HDPublicKey) {
      return data
    }

    // Allow calling HDPublicKey() without 'new' keyword by
    // detecting when 'this' is not an instance and recursively
    // calling the constructor with 'new'
    if (!(this instanceof HDPublicKey)) {
      return new HDPublicKey(data)
    }

    Preconditions.checkArgument(
      data !== undefined && data !== null,
      'Must supply an argument to create a HDPublicKey',
    )

    // Handle HDPrivateKey specially before classification
    if (data instanceof HDPrivateKey) {
      return this._buildFromPrivate(data)
    }

    // Handle serialized data (string or buffer) directly
    if (typeof data === 'string' || BufferUtil.isBuffer(data)) {
      return this._buildFromSerialized(data)
    }

    // Classify and transform object arguments
    const info = this._classifyArguments(
      data as HDPublicKeyData | HDPublicKeyObject,
    )

    return this._buildFromObject(info)
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
    if (!(typeof data === 'string' || BufferUtil.isBuffer(data))) {
      return new Error('expected buffer or string')
    }
    if (typeof data === 'string' && !JSUtil.isHexa(data)) {
      try {
        Base58Check.decode(data)
      } catch (e) {
        return new Error('Invalid base58 checksum')
      }
    }
    if (BufferUtil.isBuffer(data) && data.length !== HDPublicKey.DataSize) {
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
    const version = BufferUtil.isBuffer(data)
      ? data.slice(HDPublicKey.VersionStart, HDPublicKey.VersionEnd)
      : BufferUtil.from(
          Base58Check.decode(data).slice(
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
    } else if (BufferUtil.isBuffer(arg)) {
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
    return HDPublicKey._transformBuffer(BufferUtil.from(str, 'hex'))
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
    const parentFingerPrint = buf.slice(5, 9)
    const childIndex = buf.readUInt32BE(9)
    const chainCode = buf.slice(13, 45)
    const publicKeyBuffer = buf.slice(45, 78)

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
      parentFingerPrint: BufferUtil.from(obj.parentFingerPrint, 'hex'),
      childIndex: obj.childIndex,
      chainCode: BufferUtil.from(obj.chainCode, 'hex'),
      publicKey: PublicKey.fromBuffer(BufferUtil.from(obj.publicKey, 'hex')),
    }
  }

  /**
   * Build from HDPrivateKey
   */
  private _buildFromPrivate(arg: HDPrivateKey): HDPublicKey {
    // Convert xprivkey version to xpubkey version
    // The HDPrivateKey stores xprivkey version, but we need xpubkey version
    const xpubkeyVersion = BufferUtil.alloc(4)
    xpubkeyVersion.writeUInt32BE(arg.network.xpubkey, 0)

    const args: HDPublicKeyBuffers = {
      version: xpubkeyVersion,
      depth: arg._buffers.depth,
      parentFingerPrint: arg._buffers.parentFingerPrint,
      childIndex: arg._buffers.childIndex,
      chainCode: arg._buffers.chainCode,
      publicKey: Point.pointToCompressed(
        Point.getG().mul(BN.fromBuffer(arg._buffers.privateKey)),
      ),
      checksum: undefined, // Recalculate checksum with new version
    }
    return this._buildFromBuffers(args)
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
    const concat = BufferUtil.concat(sequence)
    const checksum = Base58Check.checksum(concat)
    if (!arg.checksum || !arg.checksum.length) {
      arg.checksum = checksum
    } else {
      if (arg.checksum.toString('hex') !== checksum.toString('hex')) {
        throw new Error('Invalid base58 checksum')
      }
    }
    const network = getNetwork(arg.version.readUInt32BE(0), 'xpubkey')
    if (!network) {
      throw new Error(
        `Invalid HDPublicKey version: 0x${arg.version.toString('hex')}`,
      )
    }

    const xpubkey = Base58Check.encode(BufferUtil.concat(sequence))
    arg.xpubkey = BufferUtil.from(xpubkey)

    const publicKey = new PublicKey(arg.publicKey, { network })
    const size = HDPublicKey.ParentFingerPrintSize
    const fingerPrint = Hash.sha256ripemd160(publicKey.toBuffer()).slice(
      0,
      size,
    )

    JSUtil.defineImmutable(this, {
      xpubkey: xpubkey,
      network: network,
      depth: arg.depth.readUInt8(0),
      publicKey: publicKey,
      fingerPrint: fingerPrint,
      parentFingerPrint: arg.parentFingerPrint,
      childIndex: arg.childIndex.readUInt32BE(0),
      chainCode: arg.chainCode,
    })

    return this
  }

  /**
   * Validate buffer arguments
   */
  private static _validateBufferArguments(arg: HDPublicKeyBuffers): void {
    const checkBuffer = (name: string, size: number) => {
      const buff = arg[name as keyof HDPublicKeyBuffers]
      if (!BufferUtil.isBuffer(buff)) {
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
    // Resolve network first - it's required for proper version encoding
    const network = arg.network ? getNetwork(arg.network) : undefined
    if (!network) {
      throw new Error(
        'Network is required when building HDPublicKey from object',
      )
    }

    // Build buffers from the classified data
    const buffers: HDPublicKeyBuffers = {
      // Version bytes (4 bytes) - will be set below based on network
      version: BufferUtil.alloc(4),
      // Depth in the derivation path (1 byte)
      depth: BufferUtil.isBuffer(arg.depth)
        ? (arg.depth as Buffer)
        : BufferUtil.from([arg.depth ?? 0]),
      // Fingerprint of the parent key (4 bytes)
      parentFingerPrint: BufferUtil.isBuffer(arg.parentFingerPrint)
        ? (arg.parentFingerPrint as Buffer)
        : arg.parentFingerPrint
          ? BufferUtil.from(arg.parentFingerPrint as string, 'hex')
          : BufferUtil.alloc(4),
      // Child index in the derivation path (4 bytes) - will be set below
      childIndex: BufferUtil.alloc(4),
      // Chain code for child key derivation (32 bytes)
      chainCode: BufferUtil.isBuffer(arg.chainCode)
        ? (arg.chainCode as Buffer)
        : arg.chainCode
          ? BufferUtil.from(arg.chainCode as string, 'hex')
          : BufferUtil.alloc(32),
      // Compressed public key (33 bytes)
      publicKey: BufferUtil.isBuffer(arg.publicKey)
        ? (arg.publicKey as Buffer)
        : arg.publicKey instanceof PublicKey
          ? arg.publicKey.toBuffer()
          : arg.publicKey
            ? BufferUtil.from(arg.publicKey as string, 'hex')
            : BufferUtil.alloc(33),
      // Checksum (4 bytes) - will be calculated automatically in _buildFromBuffers
      checksum: undefined,
    }

    // Write the xpubkey version as a 32-bit big-endian integer
    buffers.version.writeUInt32BE(network.xpubkey, 0)

    // Write the childIndex as a 32-bit big-endian integer
    if (typeof arg.childIndex === 'number') {
      buffers.childIndex.writeUInt32BE(arg.childIndex, 0)
    }

    return this._buildFromBuffers(buffers)
  }

  /**
   * Build from serialized data (Base58Check-encoded xpub string or raw buffer)
   * This method is called when deserializing an existing HDPublicKey
   */
  private _buildFromSerialized(arg: string | Buffer): HDPublicKey {
    const decoded = typeof arg === 'string' ? Base58Check.decode(arg) : arg
    const buffers: HDPublicKeyBuffers = {
      version: decoded.slice(HDPublicKey.VersionStart, HDPublicKey.VersionEnd),
      depth: decoded.slice(HDPublicKey.DepthStart, HDPublicKey.DepthEnd),
      parentFingerPrint: decoded.slice(
        HDPublicKey.ParentFingerPrintStart,
        HDPublicKey.ParentFingerPrintEnd,
      ),
      childIndex: decoded.slice(
        HDPublicKey.ChildIndexStart,
        HDPublicKey.ChildIndexEnd,
      ),
      chainCode: decoded.slice(
        HDPublicKey.ChainCodeStart,
        HDPublicKey.ChainCodeEnd,
      ),
      publicKey: decoded.slice(
        HDPublicKey.PublicKeyStart,
        HDPublicKey.PublicKeyEnd,
      ),
      checksum: decoded.slice(
        HDPublicKey.ChecksumStart,
        HDPublicKey.ChecksumEnd,
      ),
      xpubkey: typeof arg === 'string' ? BufferUtil.from(arg) : arg,
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
    const indexBuffer = BufferUtil.alloc(4)
    indexBuffer.writeUInt32BE(index, 0)
    const data = BufferUtil.concat([this.publicKey.toBuffer(), indexBuffer])
    const hash = Hash.sha512hmac(data, this._buffers.chainCode)
    const leftPart = BN.fromBuffer(hash.slice(0, 32))
    const chainCode = hash.slice(32, 64)

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
    return BufferUtil.from(this._buffers.xpubkey || BufferUtil.alloc(0))
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

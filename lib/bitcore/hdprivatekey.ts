/**
 * HDPrivateKey implementation for Hierarchical Deterministic keys
 * Migrated from bitcore-lib-xpi with ESM support
 */

import { BN } from './crypto/bn.js'
import { PrivateKey } from './privatekey.js'
import { PublicKey } from './publickey.js'
import { Point } from './crypto/point.js'
// Forward declaration - will be imported after HDPublicKey is defined
import {
  Network,
  get as getNetwork,
  defaultNetwork,
  Networks,
} from './networks.js'
import { Hash } from './crypto/hash.js'
import { Random } from './crypto/random.js'
import { Base58Check } from './encoding/base58check.js'
import { JSUtil } from './util/js.js'
import { Preconditions } from './util/preconditions.js'
import { HDPublicKey } from './hdpublickey.js'

export interface HDPrivateKeyData {
  xprivkey?: string
  network?: Network
  depth?: number
  parentFingerPrint?: Buffer
  childIndex?: number
  chainCode?: Buffer
  privateKey?: PrivateKey
}

export interface HDPrivateKeyObject {
  xprivkey: string
  network: string
  depth: number
  parentFingerPrint: string
  childIndex: number
  chainCode: string
  privateKey: string
}

export interface HDPrivateKeyBuffers {
  version: Buffer
  depth: Buffer
  parentFingerPrint: Buffer
  childIndex: Buffer
  chainCode: Buffer
  privateKey: Buffer
  checksum?: Buffer
  xprivkey?: Buffer
}

export class HDPrivateKey {
  readonly privateKey!: PrivateKey
  readonly network!: Network
  readonly depth!: number
  readonly parentFingerPrint!: Buffer
  readonly childIndex!: number
  readonly chainCode!: Buffer
  readonly fingerPrint!: Buffer
  readonly publicKey!: PublicKey
  readonly xprivkey!: string
  private _hdPublicKey!: HDPublicKey
  public _buffers!: HDPrivateKeyBuffers // Internal buffers for serialization (public for HDPublicKey access)

  // Constants
  static readonly Hardened = 0x80000000
  static readonly MaxIndex = 2 * HDPrivateKey.Hardened
  static readonly RootElementAlias = ['m', 'M', "m'", "M'"]

  constructor(data?: string | Buffer | HDPrivateKeyData | HDPrivateKeyObject) {
    if (data instanceof HDPrivateKey) {
      return data
    }

    if (data === undefined) {
      data = HDPrivateKey._getRandomData()
    }

    const info = this._classifyArguments(data)
    this._buildFromObject(info)
  }

  get hdPublicKey(): HDPublicKey {
    return this._hdPublicKey!
  }

  get xpubkey(): Buffer {
    return this._hdPublicKey!.xpubkey
  }

  private _classifyArguments(
    data: string | Buffer | HDPrivateKeyData | HDPrivateKeyObject,
  ): HDPrivateKeyData {
    if (typeof data === 'string') {
      return HDPrivateKey._transformString(data)
    } else if (Buffer.isBuffer(data)) {
      // Check if the buffer is a valid Base58Check-encoded string
      const str = data.toString()
      if (HDPrivateKey.isValidSerialized(str)) {
        return HDPrivateKey._transformSerialized(str)
      } else {
        return HDPrivateKey._transformBuffer(data)
      }
    } else if (typeof data === 'object' && data !== null) {
      if ('xprivkey' in data) {
        return HDPrivateKey._transformObject(data as HDPrivateKeyObject)
      } else {
        return data as HDPrivateKeyData
      }
    } else {
      throw new Error('Invalid HDPrivateKey data')
    }
  }

  private static _transformString(str: string): HDPrivateKeyData {
    if (!JSUtil.isHexa(str)) {
      return HDPrivateKey._transformSerialized(str)
    }
    return HDPrivateKey._transformBuffer(Buffer.from(str, 'hex'))
  }

  private static _transformSerialized(str: string): HDPrivateKeyData {
    const buf = Base58Check.decode(str)
    return HDPrivateKey._transformBuffer(buf)
  }

  private static _transformBuffer(buf: Buffer): HDPrivateKeyData {
    if (buf.length !== 78) {
      throw new Error('Invalid HDPrivateKey buffer length')
    }

    const version = buf.readUInt32BE(0)
    const network = getNetwork(version, 'xprivkey')
    if (!network) {
      throw new Error('Invalid HDPrivateKey network')
    }

    const depth = buf.readUInt8(4)
    const parentFingerPrint = buf.subarray(5, 9)
    const childIndex = buf.readUInt32BE(9)
    const chainCode = buf.subarray(13, 45)
    const privateKeyBuffer = buf.subarray(46, 78) // Skip the 1-byte gap at position 45

    // Check for compressed flag (should be 0x01 at position 45)
    const compressed = buf[45] === 0x01

    return {
      network,
      depth,
      parentFingerPrint,
      childIndex,
      chainCode,
      privateKey: new PrivateKey(
        { buf: privateKeyBuffer, compressed },
        network,
      ),
    }
  }

  private static _transformObject(obj: HDPrivateKeyObject): HDPrivateKeyData {
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
      privateKey: new PrivateKey(obj.privateKey, network),
    }
  }

  private static _getRandomData(): HDPrivateKeyData {
    const seed = Random.getRandomBuffer(64)
    return HDPrivateKey._fromSeed(seed)
  }

  private static _fromSeed(seed: Buffer): HDPrivateKeyData {
    const hash = Hash.sha512hmac(seed, Buffer.from('Bitcoin seed'))
    const privateKeyBuffer = hash.subarray(0, 32)
    const chainCode = hash.subarray(32, 64)

    return {
      network: defaultNetwork,
      depth: 0,
      parentFingerPrint: Buffer.alloc(4),
      childIndex: 0,
      chainCode,
      privateKey: new PrivateKey(privateKeyBuffer, defaultNetwork),
    }
  }

  private _buildFromObject(info: HDPrivateKeyData): void {
    Preconditions.checkArgument(
      !!info.network,
      'network',
      'Network is required',
    )
    Preconditions.checkArgument(
      !!info.privateKey,
      'privateKey',
      'Private key is required',
    )
    Preconditions.checkArgument(
      !!info.chainCode,
      'chainCode',
      'Chain code is required',
    )

    // Create buffers for serialization
    const buffers: HDPrivateKeyBuffers = {
      version: Buffer.alloc(4),
      depth: Buffer.from([info.depth || 0]),
      parentFingerPrint: info.parentFingerPrint || Buffer.alloc(4),
      childIndex: Buffer.alloc(4),
      chainCode: info.chainCode!,
      privateKey: info.privateKey!.toBuffer(),
      checksum: undefined, // Will be calculated automatically
    }

    // Write the version as a 32-bit big-endian integer
    buffers.version.writeUInt32BE(info.network!.xprivkey, 0)

    // Write the childIndex as a 32-bit big-endian integer
    buffers.childIndex.writeUInt32BE(info.childIndex || 0, 0)

    // Create the xprivkey (Base58Check-encoded extended private key)
    // Use the same approach as toBuffer() method
    const version = info.network!.xprivkey
    const depth = info.depth || 0
    const parentFingerPrint = info.parentFingerPrint || Buffer.alloc(4)
    const childIndex = info.childIndex || 0
    const chainCode = info.chainCode!
    const privateKeyBuffer = info.privateKey!.toBuffer()

    const buf = Buffer.alloc(78)
    buf.writeUInt32BE(version, 0)
    buf.writeUInt8(depth, 4)
    parentFingerPrint.copy(buf, 5)
    buf.writeUInt32BE(childIndex, 9)
    chainCode.copy(buf, 13)
    // Leave 1 byte empty at position 45 (as per BIP32 spec)
    privateKeyBuffer.copy(buf, 46)

    const xprivkey = Base58Check.encode(buf)

    JSUtil.defineImmutable(this, {
      network: info.network,
      depth: info.depth || 0,
      parentFingerPrint: info.parentFingerPrint || Buffer.alloc(4),
      childIndex: info.childIndex || 0,
      chainCode: info.chainCode,
      privateKey: info.privateKey,
      publicKey: PublicKey.fromPoint(
        info.privateKey!.toPublicKey().point,
        true,
      ),
      fingerPrint: Hash.sha256ripemd160(
        PublicKey.fromPoint(
          info.privateKey!.toPublicKey().point,
          true,
        ).toBuffer(),
      ).subarray(0, 4),
      xprivkey: xprivkey,
      _buffers: buffers,
    })

    // Create HDPublicKey
    this._hdPublicKey = new HDPublicKey({
      network: this.network,
      depth: this.depth,
      parentFingerPrint: this.parentFingerPrint,
      childIndex: this.childIndex,
      chainCode: this.chainCode,
      publicKey: this.publicKey,
    })
  }

  /**
   * Check if path is valid
   */
  isValidPath(arg: string | number, hardened?: boolean): boolean {
    if (typeof arg === 'string') {
      const indexes = HDPrivateKey._getDerivationIndexes(arg)
      return indexes !== null && indexes.every(index => this.isValidPath(index))
    }

    if (typeof arg === 'number') {
      if (arg < HDPrivateKey.Hardened && hardened === true) {
        arg += HDPrivateKey.Hardened
      }
      return arg >= 0 && arg < HDPrivateKey.MaxIndex
    }

    return false
  }

  /**
   * Internal function that splits a string path into a derivation index array.
   * It will return null if the string path is malformed.
   * It does not validate if indexes are in bounds.
   */
  private static _getDerivationIndexes(path: string): number[] | null {
    const steps = path.split('/')

    // Special cases:
    if (HDPrivateKey.RootElementAlias.includes(path)) {
      return []
    }

    if (!HDPrivateKey.RootElementAlias.includes(steps[0])) {
      return null
    }

    const indexes = steps.slice(1).map(step => {
      const isHardened = step.slice(-1) === "'"
      if (isHardened) {
        step = step.slice(0, -1)
      }
      if (!step || step[0] === '-') {
        return NaN
      }
      let index = +step // cast to number
      if (isHardened) {
        index += HDPrivateKey.Hardened
      }

      return index
    })

    return indexes.some(isNaN) ? null : indexes
  }

  /**
   * Check if serialized data is valid
   */
  static isValidSerialized(
    data: string | Buffer,
    network?: Network | string,
  ): boolean {
    try {
      HDPrivateKey._transformString(
        typeof data === 'string' ? data : data.toString('hex'),
      )
      return true
    } catch (e) {
      return false
    }
  }

  /**
   * Get serialization error
   */
  getSerializedError(
    data: string | Buffer,
    network?: Network | string,
  ): Error | null {
    try {
      HDPrivateKey._transformString(
        typeof data === 'string' ? data : data.toString('hex'),
      )
      return null
    } catch (e) {
      return e as Error
    }
  }

  /**
   * Derive child key
   */
  derive(arg: string | number, hardened?: boolean): HDPrivateKey {
    return this.deriveNonCompliantChild(arg, hardened)
  }

  /**
   * Derive from string path
   */
  private _deriveFromString(
    path: string,
    nonCompliant?: boolean,
  ): HDPrivateKey {
    if (!this.isValidPath(path)) {
      throw new Error('Invalid derivation path')
    }

    const indexes = HDPrivateKey._getDerivationIndexes(path)
    if (indexes === null) {
      throw new Error('Invalid derivation path')
    }

    return indexes.reduce((prev, index) => {
      return prev._deriveWithNumber(index, undefined, nonCompliant)
    }, this as HDPrivateKey)
  }

  /**
   * Derive with number index
   */
  private _deriveWithNumber(
    index: number,
    hardened?: boolean,
    nonCompliant?: boolean,
  ): HDPrivateKey {
    if (!this.isValidPath(index, hardened)) {
      throw new Error('Invalid derivation path')
    }

    hardened = index >= HDPrivateKey.Hardened ? true : hardened
    if (index < HDPrivateKey.Hardened && hardened === true) {
      index += HDPrivateKey.Hardened
    }

    const indexBuffer = Buffer.from([
      index >> 24,
      index >> 16,
      index >> 8,
      index,
    ])

    let data: Buffer
    if (hardened && nonCompliant) {
      // The private key serialization in this case will not be exactly 32 bytes and can be
      // any value less, and the value is not zero-padded.
      const nonZeroPadded = this.privateKey.bn.toBuffer()
      data = Buffer.concat([Buffer.from([0]), nonZeroPadded, indexBuffer])
    } else if (hardened) {
      // Use 32-byte zero-padded serialization of the private key
      const privateKeyBuffer = this.privateKey.bn.toBuffer({ size: 32 })
      data = Buffer.concat([Buffer.from([0]), privateKeyBuffer, indexBuffer])
    } else {
      data = Buffer.concat([this.publicKey.toBuffer(), indexBuffer])
    }

    const hash = Hash.sha512hmac(data, this.chainCode)
    const leftPart = BN.fromBuffer(hash.subarray(0, 32), { size: 32 })
    const childChainCode = hash.subarray(32, 64)

    const childPrivateKey = leftPart
      .add(this.privateKey.toBigNumber())
      .umod(Point.getN())
      .toBuffer({ size: 32 })

    if (!PrivateKey.isValid(childPrivateKey)) {
      // Index at this point is already hardened, we can pass null as the hardened arg
      return this._deriveWithNumber(index + 1, undefined, nonCompliant)
    }

    return new HDPrivateKey({
      network: this.network,
      depth: this.depth + 1,
      parentFingerPrint: Hash.sha256ripemd160(
        this.privateKey.toPublicKey().toBuffer(),
      ).subarray(0, 4),
      childIndex: index,
      chainCode: childChainCode,
      privateKey: new PrivateKey({
        bn: childPrivateKey.toString('hex'),
        network: this.network.name,
        compressed: this.privateKey.compressed,
      }),
    })
  }

  /**
   * Derive child key (alias for derive)
   */
  deriveChild(arg: string | number, hardened?: boolean): HDPrivateKey {
    if (typeof arg === 'string') {
      return this._deriveFromString(arg, false)
    } else if (typeof arg === 'number') {
      return this._deriveWithNumber(arg, hardened, false)
    } else {
      throw new Error('Invalid derivation argument')
    }
  }

  /**
   * Derive non-compliant child (for compatibility)
   */
  deriveNonCompliantChild(
    arg: string | number,
    hardened?: boolean,
  ): HDPrivateKey {
    if (typeof arg === 'string') {
      return this._deriveFromString(arg, true)
    } else if (typeof arg === 'number') {
      return this._deriveWithNumber(arg, hardened, true)
    } else {
      throw new Error('Invalid derivation argument')
    }
  }

  /**
   * Convert to string
   */
  toString(): string {
    return this.xprivkey
  }

  /**
   * Convert to object
   */
  toObject(): HDPrivateKeyObject {
    return {
      xprivkey: this.xprivkey,
      network: this.network.toString(),
      depth: this.depth,
      parentFingerPrint: this.parentFingerPrint.toString('hex'),
      childIndex: this.childIndex,
      chainCode: this.chainCode.toString('hex'),
      privateKey: this.privateKey.toString(),
    }
  }

  /**
   * Convert to JSON
   */
  toJSON(): HDPrivateKeyObject {
    return this.toObject()
  }

  /**
   * Convert to buffer
   */
  toBuffer(): Buffer {
    if (this._buffers.xprivkey) {
      return this._buffers.xprivkey
    }

    const version = this.network.xprivkey
    const depth = this.depth
    const parentFingerPrint = this.parentFingerPrint
    const childIndex = this.childIndex
    const chainCode = this.chainCode
    const privateKeyBuffer = this.privateKey.toBuffer()

    const buf = Buffer.alloc(78)
    buf.writeUInt32BE(version, 0)
    buf.writeUInt8(depth, 4)
    parentFingerPrint.copy(buf, 5)
    buf.writeUInt32BE(childIndex, 9)
    chainCode.copy(buf, 13)
    // Leave 1 byte empty at position 45 (as per BIP32 spec)
    privateKeyBuffer.copy(buf, 46)

    this._buffers.xprivkey = buf
    return buf
  }

  /**
   * Create from buffer
   */
  static fromBuffer(arg: Buffer): HDPrivateKey {
    return new HDPrivateKey(arg.toString('hex'))
  }

  /**
   * Create from string
   */
  static fromString(arg: string): HDPrivateKey {
    return new HDPrivateKey(arg)
  }

  /**
   * Create from object
   */
  static fromObject(obj: HDPrivateKeyObject): HDPrivateKey {
    return new HDPrivateKey(obj)
  }

  /**
   * Create from seed
   */
  static fromSeed(
    hexa: string | Buffer,
    network?: Network | string,
  ): HDPrivateKey {
    const seed = typeof hexa === 'string' ? Buffer.from(hexa, 'hex') : hexa
    const data = HDPrivateKey._fromSeed(seed)
    if (network) {
      data.network = getNetwork(network) || defaultNetwork
    }
    return new HDPrivateKey(data)
  }

  /**
   * Get string representation for console
   */
  inspect(): string {
    return `<HDPrivateKey: ${this.xprivkey}, network: ${this.network}>`
  }
}

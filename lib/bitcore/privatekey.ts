/**
 * PrivateKey implementation for Lotus
 * Migrated from bitcore-lib-xpi with ESM support and BigInt
 */

import { BN } from './crypto/bn.js'
import { Point } from './crypto/point.js'
import { Random } from './crypto/random.js'
import { Base58Check } from './encoding/base58check.js'
import { JSUtil } from './util/js.js'
import {
  Network,
  get as getNetwork,
  defaultNetwork,
  Networks,
} from './networks.js'
import { PublicKey } from './publickey.js'
import { Address } from './address.js'

export interface PrivateKeyData {
  bn?: BN
  compressed?: boolean
  network?: Network
}

export interface PrivateKeyObject {
  bn: string
  network: string
  compressed: boolean
}

export interface PrivateKeySerialized {
  bn: string
  compressed: boolean
  network: string
}

export interface HDPrivateKeyDerivedData {
  buf: Buffer
  compressed: boolean
}

export type PrivateKeyInput =
  | string
  | Buffer
  | PrivateKeyData
  | BN
  | PrivateKeyObject
  | HDPrivateKeyDerivedData

export class PrivateKey {
  readonly bn!: BN
  readonly compressed!: boolean
  readonly network!: Network
  private _pubkey?: PublicKey

  constructor(data?: PrivateKeyInput, network?: Network | string) {
    if (data instanceof PrivateKey) {
      return data
    }

    const info = this._classifyArguments(data!, network)

    // Validation
    if (!info.bn || info.bn.isZero()) {
      throw new TypeError(
        'Number can not be equal to zero, undefined, null or false',
      )
    }
    if (!info.bn.lt(Point.getN())) {
      throw new TypeError('Number must be less than N')
    }
    if (!info.network) {
      throw new TypeError('Must specify the network ("livenet" or "testnet")')
    }

    JSUtil.defineImmutable(this, {
      bn: info.bn,
      compressed: info.compressed,
      network: info.network,
    })
  }

  get publicKey(): PublicKey {
    return this.toPublicKey()
  }

  /**
   * Internal helper to instantiate PrivateKey internal `info` object from
   * different kinds of arguments passed to the constructor.
   */
  private _classifyArguments(
    data: PrivateKeyInput,
    network?: Network | string,
  ): PrivateKeyData {
    const info: PrivateKeyData = {
      compressed: true,
      network: network ? getNetwork(network) || defaultNetwork : defaultNetwork,
    }

    // Detect type of data
    if (data === undefined || data === null) {
      info.bn = PrivateKey._getRandomBN()
    } else if (data instanceof BN) {
      info.bn = data
    } else if (Buffer.isBuffer(data)) {
      const bufferInfo = PrivateKey._transformBuffer(data, network)
      Object.assign(info, bufferInfo)
    } else if (
      typeof data === 'object' &&
      data !== null &&
      'compressed' in data &&
      'buf' in data
    ) {
      info.compressed = data.compressed
      info.bn = new BN(data.buf, 'be')
    } else if (
      typeof data === 'object' &&
      data !== null &&
      'bn' in data &&
      'network' in data
    ) {
      const objectInfo = PrivateKey._transformObject(data as PrivateKeyObject)
      Object.assign(info, objectInfo)
    } else if (!network && typeof data === 'string' && getNetwork(data)) {
      info.bn = PrivateKey._getRandomBN()
      info.network = getNetwork(data)!
    } else if (typeof data === 'string') {
      if (JSUtil.isHexa(data)) {
        info.bn = new BN(data, 16)
      } else {
        const wifInfo = PrivateKey._transformWIF(data, network)
        Object.assign(info, wifInfo)
      }
    } else {
      throw new TypeError('First argument is an unrecognized data type.')
    }
    return info
  }

  /**
   * Internal function to get a random BigInt (synchronous version)
   */
  private static _getRandomBN(): BN {
    let bn: BN
    do {
      const privbuf = Random.getPseudoRandomBuffer(32)
      bn = new BN(privbuf, 'be')
    } while (!bn.lt(Point.getN()))
    return bn
  }

  /**
   * Internal function to transform a WIF Buffer into a private key
   */
  private static _transformBuffer(
    buf: Buffer,
    network?: Network | string,
  ): PrivateKeyData {
    const info: PrivateKeyData = {}

    if (buf.length === 32) {
      return PrivateKey._transformBNBuffer(buf, network)
    }

    const detectedNetwork = getNetwork(buf[0], 'privatekey')
    if (!detectedNetwork) {
      throw new Error('Invalid network')
    }

    info.network = detectedNetwork

    if (network) {
      const specifiedNetwork = getNetwork(network)
      if (specifiedNetwork && info.network !== specifiedNetwork) {
        // Allow testnet/regtest compatibility since they use the same private key prefix
        const isCompatible =
          (info.network.name === 'testnet' &&
            specifiedNetwork.name === 'regtest') ||
          (info.network.name === 'regtest' &&
            specifiedNetwork.name === 'testnet')

        if (!isCompatible) {
          throw new TypeError('Private key network mismatch')
        }
        // Use the specified network instead of detected network
        info.network = specifiedNetwork
      }
    }

    if (buf.length === 1 + 32 + 1 && buf[1 + 32 + 1 - 1] === 1) {
      info.compressed = true
    } else if (buf.length === 1 + 32) {
      info.compressed = false
    } else {
      throw new Error(
        'Length of buffer must be 33 (uncompressed) or 34 (compressed)',
      )
    }

    info.bn = new BN(buf.subarray(1, 32 + 1), 'be')
    return info
  }

  /**
   * Internal function to transform a BN buffer into a private key
   */
  private static _transformBNBuffer(
    buf: Buffer,
    network?: Network | string,
  ): PrivateKeyData {
    network ||= defaultNetwork
    return {
      network: getNetwork(network),
      bn: new BN(buf, 'be'),
      compressed: true,
    }
  }

  /**
   * Internal function to transform a WIF string into a private key
   */
  private static _transformWIF(
    str: string,
    network?: Network | string,
  ): PrivateKeyData {
    return PrivateKey._transformBuffer(Base58Check.decode(str), network)
  }

  /**
   * Internal function to transform a JSON string or plain object into a private key
   */
  private static _transformObject(json: PrivateKeyObject): PrivateKeyData {
    const bn = new BN(json.bn, 16)
    const network = getNetwork(json.network)
    return {
      bn: bn,
      network: network || defaultNetwork,
      compressed: json.compressed,
    }
  }

  /**
   * Instantiate a PrivateKey from a Buffer with the DER or WIF representation
   */
  static fromBuffer(arg: Buffer, network?: Network | string): PrivateKey {
    return new PrivateKey(arg, network)
  }

  /**
   * Instantiate a PrivateKey from a WIF string
   */
  static fromString(str: string, network?: Network | string): PrivateKey {
    if (typeof str !== 'string') {
      throw new Error('First argument is expected to be a string.')
    }
    return new PrivateKey(str, network)
  }

  /**
   * Instantiate a PrivateKey from a WIF string (alias for fromString)
   * Automatically detects compressed vs uncompressed WIF format
   * Always uses Lotus network for consistency
   */
  static fromWIF(str: string, network?: Network | string): PrivateKey {
    return PrivateKey.fromString(str, network ?? defaultNetwork)
  }

  /**
   * Instantiate a PrivateKey from a plain JavaScript object
   */
  static fromObject(
    obj: PrivateKeyObject,
    network?: Network | string,
  ): PrivateKey {
    if (typeof obj !== 'object') {
      throw new Error('First argument is expected to be an object.')
    }
    return new PrivateKey(obj, network)
  }

  /**
   * Instantiate a PrivateKey from random bytes
   */
  static fromRandom(network?: Network | string): PrivateKey {
    const bn = PrivateKey._getRandomBN()
    return new PrivateKey(bn, network)
  }

  /**
   * Check if there would be any errors when initializing a PrivateKey
   */
  static getValidationError(
    data: PrivateKeyInput,
    network?: Network | string,
  ): Error | null {
    try {
      new PrivateKey(data, network)
      return null
    } catch (e) {
      return e as Error
    }
  }

  /**
   * Check if the parameters are valid
   */
  static isValid(data: PrivateKeyInput, network?: Network | string): boolean {
    if (!data) {
      return false
    }
    return !PrivateKey.getValidationError(data, network)
  }

  /**
   * Will output the PrivateKey encoded as hex string
   */
  toString(): string {
    return this.toBuffer().toString('hex')
  }

  /**
   * Will output the PrivateKey to a WIF string
   * @param compressed - If true (default), outputs compressed WIF (K/L prefix)
   *                     If false, outputs uncompressed WIF (5 prefix)
   */
  toWIF(compressed: boolean = true): string {
    let buf: Buffer
    if (compressed) {
      buf = Buffer.concat([
        Buffer.from([this.network.privatekey]),
        this.bn.toArrayLike(Buffer, 'be', 32),
        Buffer.from([0x01]),
      ])
    } else {
      buf = Buffer.concat([
        Buffer.from([this.network.privatekey]),
        this.bn.toArrayLike(Buffer, 'be', 32),
      ])
    }

    return Base58Check.encode(buf)
  }

  /**
   * Will return the private key as a BN instance
   */
  toBigNumber(): BN {
    return this.bn
  }

  /**
   * Will return the private key as a Buffer
   */
  toBuffer(): Buffer {
    return this.bn.toArrayLike(Buffer, 'be', 32)
  }

  /**
   * Will return the private key as a Buffer without leading zero padding
   */
  toBufferNoPadding(): Buffer {
    return this.bn.toArrayLike(Buffer, 'be')
  }

  /**
   * Will return the corresponding public key
   */
  toPublicKey(): PublicKey {
    if (!this._pubkey) {
      this._pubkey = PublicKey.fromPrivateKey(this)
    }
    return this._pubkey
  }

  /**
   * Will return an address for the private key
   * @param network - optional parameter specifying the desired network for the address
   * @returns An address generated from the private key
   */
  toAddress(network?: Network | string): Address {
    const pubkey = this.toPublicKey()
    return Address.fromPublicKey(pubkey, network ?? this.network.name)
  }

  /**
   * Returns a plain object representation
   */
  toObject(): PrivateKeySerialized {
    return {
      bn: this.bn.toString(16),
      compressed: this.compressed,
      network: this.network.toString(),
    }
  }

  /**
   * Returns a JSON representation (same as toObject)
   */
  toJSON(): PrivateKeySerialized {
    return this.toObject()
  }

  /**
   * Will return a string formatted for the console
   */
  inspect(): string {
    const uncompressed = !this.compressed ? ', uncompressed' : ''
    return `<PrivateKey: ${this.toString()}, network: ${this.network}${uncompressed}>`
  }
}

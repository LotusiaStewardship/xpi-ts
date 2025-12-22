/**
 * XAddress implementation
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import { Preconditions } from './util/preconditions.js'
import { BitcoreError } from './errors.js'
import { Base58 } from './encoding/base58.js'
import { Base58Check } from './encoding/base58check.js'
import { BufferReader } from './encoding/bufferreader.js'
import { BufferWriter } from './encoding/bufferwriter.js'
import { Network, Networks } from './networks.js'
import { Hash } from './crypto/hash.js'
import { JSUtil } from './util/js.js'
import { BufferUtil } from './util/buffer.js'
import { PublicKey } from './publickey.js'

/**
 * The default token or network prefix name for Lotus addresses.
 * Typically used as the starting character or set prefix in address strings.
 */
const TOKEN_NAME = 'lotus'

/**
 * The Base58 alphabet used for encoding Lotus XAddresses.
 * Excludes easily confused characters: 0 (zero), O (capital o), I (capital i), and l (lower case L).
 * This alphabet is compatible with Bitcoin's traditional Base58 encoding.
 */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/**
 * Represents the data to create, validate, or serialize an XAddress.
 * This structure contains all the information needed to construct or check an xaddress.
 */
export interface XAddressData {
  /**
   * Buffer containing the hash that the address refers to.
   */
  hashBuffer?: Buffer

  /**
   * Network object describing the network (livenet, testnet, regtest).
   */
  network?: Network

  /**
   * String indicating what the address refers to. Valid values are:
   * - 'pubkeyhash' for a public key hash / Pay-to-Public-Key-Hash
   * - 'scripthash' for a script hash / Pay-to-Script-Hash
   */
  type?: string

  /**
   * Token or network prefix to be used in the address.
   */
  prefix?: string
}

/**
 * Interface type definition for describing components of an address object.
 * This structure represents the minimal information needed to reconstruct an address object.
 */
export interface XAddressObject {
  /**
   * The hex-encoded string representing the hash of the payload (the public key or script).
   * This corresponds to the second part of the serialized address (after the type byte and network character).
   */
  hash: string

  /**
   * The type of the address, either "pubkeyhash" or "scripthash".
   * This is the third part of the serialized address (the type byte).
   */
  type: string

  /**
   * The network identifier of the address (e.g., 'livenet', 'testnet', or 'regtest').
   * This corresponds to the network character in the address.
   */
  network: string

  /**
   * The prefix of the address, which is the part before the network character.
   * The default prefix is 'lotus' for mainnet, but can be customized.
   */
  prefix?: string
}

export type XAddressInput = string | Buffer | XAddressData | PublicKey

export class XAddress {
  /**
   * The type of address that refers to a Pay-to-Public-Key-Hash (P2PKH)
   */
  static readonly PayToPublicKeyHash = 'pubkeyhash'
  /**
   * The type of address that refers to a Pay-to-Script-Hash (P2SH)
   */
  static readonly PayToScriptHash = 'scripthash'
  /**
   * The type of address that refers to Pay-to-Taproot (P2TR)
   */
  static readonly PayToTaproot = 'taproot'

  readonly prefix!: string
  readonly hashBuffer!: Buffer
  readonly network!: Network
  readonly type!: string

  constructor(
    data?: XAddressInput,
    network?: Network | string,
    type?: string,
    prefix: string = TOKEN_NAME,
  ) {
    if (data instanceof XAddress) {
      // Immutable instance
      return data
    }

    Preconditions.checkArgument(
      data !== undefined,
      'data',
      'First argument is required, please include address data.',
      'guide/address.html',
    )

    // Track if network was explicitly provided - if not, we'll accept any network from the address
    const networkExplicitlyProvided = network !== undefined

    // default to mainnet if no network is provided
    network ||= Networks.defaultNetwork.name

    if (network && !Networks.get(network)) {
      throw new TypeError(
        'Second argument must be "livenet", "testnet", or "regtest".',
      )
    }

    if (
      type &&
      type !== XAddress.PayToPublicKeyHash &&
      type !== XAddress.PayToScriptHash &&
      type !== XAddress.PayToTaproot
    ) {
      throw new TypeError(
        'Third argument must be "pubkeyhash", "scripthash", or "taproot".',
      )
    }

    const info = this._classifyArguments(
      data!,
      network,
      type,
      prefix,
      networkExplicitlyProvided,
    )

    // set defaults if not set
    info.network =
      info.network || Networks.get(network) || Networks.defaultNetwork
    info.type = info.type || type || XAddress.PayToPublicKeyHash

    JSUtil.defineImmutable(this, {
      prefix: info.prefix,
      hashBuffer: info.hashBuffer,
      network: info.network,
      type: info.type,
    })
  }

  /**
   * Classifies the input data and returns a transformed object containing address components.
   *
   * @param data - The input data, which can be a string, buffer, object, or PublicKey.
   * @param network - The network configuration (optional).
   * @param type - The address type (optional).
   * @param prefix - The address prefix (optional).
   * @param networkExplicitlyProvided - Whether the network was explicitly provided by the caller.
   * @returns An object containing the address hash, network, type, and prefix.
   * @throws Throws a TypeError if the data format is unrecognized.
   */
  private _classifyArguments(
    data: XAddressInput,
    network?: Network | string,
    type?: string,
    prefix?: string,
    networkExplicitlyProvided: boolean = true,
  ): XAddressData {
    // transform and validate input data
    if (typeof data === 'string') {
      // When network was not explicitly provided, pass undefined to allow any network from the address
      return XAddress._transformString(
        data,
        networkExplicitlyProvided ? network : undefined,
        type,
      )
    } else if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
      return XAddress._transformBuffer(data, network, type, prefix)
    } else if (typeof data === 'object' && data !== null) {
      return XAddress._transformObject(data as XAddressData)
    } else {
      throw new TypeError('First argument is an unrecognized data format.')
    }
  }

  /**
   * Deserializes an address serialized through `XAddress#toObject()`
   */
  private static _transformObject(data: XAddressData): XAddressData {
    Preconditions.checkArgument(
      data.hashBuffer !== undefined,
      'data',
      'Must provide a `hash` or `hashBuffer` property',
    )
    Preconditions.checkArgument(
      data.type !== undefined,
      'data',
      'Must provide a `type` property',
    )
    return {
      hashBuffer:
        data.hashBuffer || Buffer.from(data.hashBuffer!.toString(), 'hex'),
      network: Networks.get(data.network!) || Networks.defaultNetwork,
      type: data.type,
      prefix: data.prefix,
    }
  }

  /**
   * Internal function to discover the network and type based on the first data byte
   */
  private static _classifyFromVersion(buffer: Buffer): {
    network?: Network
    type?: string
  } {
    // @TODO Currently incorrect, the format of xaddress is different
    const version: { network?: Network; type?: string } = {}

    const pubkeyhashNetwork = Networks.get(buffer[0], 'pubkeyhash')
    const scripthashNetwork = Networks.get(buffer[0], 'scripthash')

    if (pubkeyhashNetwork) {
      version.network = pubkeyhashNetwork
      version.type = XAddress.PayToPublicKeyHash
    } else if (scripthashNetwork) {
      version.network = scripthashNetwork
      version.type = XAddress.PayToScriptHash
    }

    return version
  }

  /**
   * Internal function to transform a lotus address string
   */
  private static _transformString(
    data: string,
    network?: Network | string,
    type?: string,
  ): XAddressData {
    if (typeof data !== 'string') {
      throw new TypeError('data parameter supplied is not a string.')
    }

    data = data.trim()
    const networkObj = Networks.get(network!)

    if (network && !networkObj) {
      throw new TypeError('Unknown network')
    }

    const info = XAddress._decode(data)
    if (
      !info.network ||
      (networkObj && networkObj.name !== info.network.name)
    ) {
      throw new TypeError('Address has mismatched network type.')
    }
    return info
  }

  /**
   * Internal function to transform a lotus address buffer
   */
  private static _transformBuffer(
    buffer: Buffer | Uint8Array,
    network?: Network | string,
    type?: string,
    prefix: string = TOKEN_NAME,
  ): XAddressData {
    const info: XAddressData = {}
    if (!Buffer.isBuffer(buffer) && !(buffer instanceof Uint8Array)) {
      throw new TypeError('XAddress supplied is not a buffer.')
    }

    const networkObj = Networks.get(network!)

    if (network && !networkObj) {
      throw new TypeError('Unknown network')
    }

    if (type === undefined) {
      throw new TypeError('Unknown type.')
    }

    info.prefix = prefix
    info.hashBuffer = Buffer.from(buffer)
    info.network = networkObj || Networks.defaultNetwork
    info.type = type
    return info
  }

  /**
   * Instantiate an xaddress from an address string
   */
  static fromString(
    str: string,
    network?: Network | string,
    type?: string,
  ): XAddress {
    const info = XAddress._transformString(str, network, type)
    return new XAddress(info.hashBuffer, info.network, info.type)
  }

  /**
   * Instantiate an xaddress from an Object
   */
  static fromObject(obj: XAddressObject): XAddress {
    Preconditions.checkState(
      JSUtil.isHexa(obj.hash),
      'Unexpected hash property, "' + obj.hash + '", expected to be hex.',
    )
    const hashBuffer = Buffer.from(obj.hash, 'hex')
    return new XAddress(hashBuffer, obj.network, obj.type, obj.prefix)
  }

  /**
   * Will return a validation error if exists
   */
  static getValidationError(
    data: XAddressInput,
    network?: Network | string,
    type?: string,
  ): Error | null {
    try {
      new XAddress(data, network, type)
      return null
    } catch (e) {
      return e as Error
    }
  }

  /**
   * Will return a boolean if an address is valid
   */
  static isValid(
    data: XAddressInput,
    network?: Network | string,
    type?: string,
  ): boolean {
    return !XAddress.getValidationError(data, network, type)
  }

  /**
   * Decode an xaddress string into its components
   */
  static _decode(address: string): XAddressData {
    return decode(address)
  }

  /**
   * Will return a buffer representation of the xaddress
   */
  toBuffer(): Buffer {
    const version = Buffer.from([
      this.network[this.type as keyof Network] as number,
    ])
    const buf = Buffer.concat([version, this.hashBuffer])
    return buf
  }

  /**
   * Returns a plain object with the xaddress information
   */
  toObject(): XAddressObject {
    return {
      prefix: this.prefix,
      hash: this.hashBuffer.toString('hex'),
      type: this.type,
      network: this.network.toString(),
    }
  }

  toJSON(): XAddressObject {
    return this.toObject()
  }

  /**
   * Converts the XAddress instance to an address string according to the XAddress specification.
   * This method should build the address string by combining the prefix, network character, and encoded content.
   *
   * @returns {string} The properly formatted address string
   */
  toXAddress(): string {
    const prefix = this.prefix
    const networkChar = getNetworkChar(this.network)
    const networkByte = Buffer.from(networkChar)
    const typeByte = Buffer.from([getTypeByte(this.type)])
    const payload = this.hashBuffer
    const checksum = createChecksum(prefix, networkByte, typeByte, payload)
    const encodedPayload = encodePayload(typeByte, payload, checksum)
    return prefix + networkChar + encodedPayload
  }

  /**
   * Wrapper function for `XAddress.toXAddress()`
   * @returns
   */
  toString(): string {
    return this.toXAddress()
  }

  /**
   * Check if this is a Pay-To-Public-Key-Hash address
   */
  isPayToPublicKeyHash(): boolean {
    return this.type === XAddress.PayToPublicKeyHash
  }

  /**
   * Check if this is a Pay-To-Script-Hash address
   */
  isPayToScriptHash(): boolean {
    return this.type === XAddress.PayToScriptHash
  }

  /**
   * Check if this is a Pay-To-Taproot address
   */
  isPayToTaproot(): boolean {
    return this.type === XAddress.PayToTaproot
  }

  /**
   * Will return a string formatted for the console
   */
  inspect(): string {
    return '<XAddress: ' + this.toString() + ', type: ' + this.type + '>'
  }
}

function createChecksum(
  prefix: string,
  networkByte: Buffer,
  typeByte: Buffer,
  payload: Buffer,
): Buffer {
  const data = BufferUtil.concat([
    Buffer.from(prefix),
    networkByte,
    typeByte,
    payload,
  ])
  return Hash.sha256(data).subarray(0, 4)
}

function createChecksumLegacy(
  prefix: string,
  networkByte: Buffer,
  typeByte: Buffer,
  payload: Buffer,
): Buffer {
  const bw = new BufferWriter()
  bw.writeVarintNum(prefix.length)
  bw.write(Buffer.from(prefix))
  bw.writeUInt8(networkByte[0])
  bw.writeUInt8(typeByte[0])
  bw.writeVarintNum(payload.length)
  bw.write(payload)
  const buf = bw.concat()
  return Hash.sha256(buf).subarray(0, 4)
}

function getType(typeByte: number): string {
  switch (typeByte) {
    case 0:
      return 'pubkeyhash'
    case 1:
      return 'scripthash'
    case 2:
      return 'taproot'
  }
  return 'pubkeyhash'
}

function getTypeByte(type: string): number {
  switch (type) {
    case 'pubkeyhash':
    case 'scripthash': // P2SH uses same type byte: https://lotusia.org/docs/specs/addresses#payload
      return 0
    case 'taproot':
      return 2
  }
  return 0
}

/**
 * Returns the Network object corresponding to the given network character.
 *
 * @param networkChar - The network identifier character.
 *   '_' for livenet/mainnet, 'T' for testnet, 'R' for regtest.
 * @returns The corresponding Network object.
 * @throws If the network character is unknown.
 */
function getNetworkFromChar(networkChar: string): Network {
  switch (networkChar) {
    case '_':
      return Networks.get('livenet')!
    case 'T':
      return Networks.get('testnet')!
    case 'R':
      return Networks.get('regtest')!
    default:
      throw new TypeError('Unknown network type: ' + networkChar)
  }
}

/**
 * Returns the network character corresponding to the given Network object.
 *
 * @param network The Network object.
 * @returns The network character.
 * @throws If the network is unknown.
 */
function getNetworkChar(network: Network): string {
  if (network.name === 'livenet') {
    return '_'
  } else if (network.name === 'testnet') {
    return 'T'
  } else if (network.name === 'regtest') {
    return 'R'
  } else {
    throw new TypeError('Unknown network: ' + network.name)
  }
}

/**
 * Encodes the address payload (type byte, payload hash, and checksum) into a Base58 string.
 *
 * @param typeByte A Buffer containing the type byte of the address (e.g. 0 for P2PKH).
 * @param payload A Buffer containing the main payload (typically the hash of the public key or script).
 * @param checksum A Buffer containing the checksum (usually 4 bytes created from a hash of the components).
 * @returns The Base58-encoded string representing the full XAddress payload.
 */
function encodePayload(
  typeByte: Buffer,
  payload: Buffer,
  checksum: Buffer,
): string {
  const bw = new BufferWriter()
  bw.writeUInt8(typeByte[0])
  bw.write(payload)
  bw.write(checksum)
  const buf = bw.concat()
  return Base58.encode(buf)
}

function decode(address: string): XAddressData {
  const match = /[A-Z]|_/.exec(address)

  const splitLocation = match ? match.index : 0

  const prefix = address.substring(0, splitLocation)
  const networkChar = address.substring(splitLocation, splitLocation + 1)
  const networkByte = Buffer.from(networkChar)
  const encodedPayload = address.substring(splitLocation + 1)
  const decodedBytes = Base58.decode(encodedPayload)
  const typeByte = decodedBytes.subarray(0, 1)
  const payload = decodedBytes.subarray(1, decodedBytes.length - 4)
  const decodedChecksum = decodedBytes.subarray(decodedBytes.length - 4)

  const checksum = createChecksum(prefix, networkByte, typeByte, payload)
  /* const legacyChecksum = createChecksumLegacy(
    prefix,
    networkByte,
    typeByte,
    payload,
  ) */

  Preconditions.checkArgument(
    checksum.toString('hex') === decodedChecksum.toString('hex'),
    'checksum',
    'Invalid checksum: ' + address,
  )

  /* Preconditions.checkArgument(
    legacyChecksum.toString('hex') === decodedChecksum.toString('hex'),
    'typeByte',
    'Invalid type byte: ' + typeByte[0],
  ) */

  const info: XAddressData = {}
  info.hashBuffer = payload
  info.network = getNetworkFromChar(networkChar)
  info.type = getType(typeByte[0])
  info.prefix = prefix

  return info
}

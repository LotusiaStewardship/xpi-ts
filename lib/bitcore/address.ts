/**
 * Address implementation
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import { Preconditions } from './util/preconditions.js'
import { BitcoreError } from './errors.js'
import { Base58Check } from './encoding/base58check.js'
import { Network, get as getNetwork, defaultNetwork } from './networks.js'
import { Hash } from './crypto/hash.js'
import { JSUtil } from './util/js.js'
import { PublicKey } from './publickey.js'
import { XAddress } from './xaddress.js'
import { Script } from './script.js'

export interface AddressData {
  hashBuffer?: Buffer
  network?: Network
  type?: string
}

export interface AddressObject {
  hash: string
  type: string
  network: string
}

export interface CashAddressDecoding {
  readonly network: Network
  readonly type: string
  readonly hashBuffer: Buffer
}

export type AddressInput =
  | string
  | Buffer
  | AddressData
  | PublicKey
  | PublicKey[]
  | Script

export class Address {
  static readonly PayToPublicKeyHash = 'pubkeyhash'
  static readonly PayToScriptHash = 'scripthash'
  static readonly PayToTaproot = 'taproot'

  readonly hashBuffer!: Buffer
  readonly network!: Network
  readonly type!: string

  constructor(data?: AddressInput, network?: Network | string, type?: string) {
    if (Array.isArray(data) && typeof network === 'number') {
      return Address.createMultisig(data as PublicKey[], network, type)
    }

    if (data instanceof Address) {
      // Immutable instance
      return data
    }

    Preconditions.checkArgument(
      data !== undefined,
      'data',
      'First argument is required, please include address data.',
      'guide/address.html',
    )

    if (network && !getNetwork(network)) {
      throw new TypeError(
        'Second argument must be "livenet", "testnet", or "regtest".',
      )
    }

    // Track if network was explicitly provided - if not, we'll accept any network from the address
    const networkExplicitlyProvided = network !== undefined

    // if network is not provided, default to livenet (but we'll override with address's network if parsing a string)
    network ||= defaultNetwork

    if (
      type &&
      type !== Address.PayToPublicKeyHash &&
      type !== Address.PayToScriptHash &&
      type !== Address.PayToTaproot
    ) {
      throw new TypeError(
        'Third argument must be "pubkeyhash", "scripthash", or "taproot".',
      )
    }

    const info = this._classifyArguments(
      data!,
      network,
      type,
      networkExplicitlyProvided,
    )

    // set defaults if not set
    info.network = info.network || getNetwork(network!) || defaultNetwork
    info.type = info.type || type || Address.PayToPublicKeyHash

    JSUtil.defineImmutable(this, {
      hashBuffer: info.hashBuffer,
      network: info.network,
      type: info.type,
    })
  }

  private _classifyArguments(
    data: AddressInput,
    network: Network | string,
    type?: string,
    networkExplicitlyProvided: boolean = true,
  ): AddressData {
    if (typeof network === 'string') {
      const networkObj = getNetwork(network)
      if (!networkObj) {
        throw new TypeError('Unknown network')
      }
      network = networkObj
    }

    // transform and validate input data
    if (
      (Buffer.isBuffer(data) || data instanceof Uint8Array) &&
      data.length === 20
    ) {
      return Address._transformHash(data)
    } else if (
      (Buffer.isBuffer(data) || data instanceof Uint8Array) &&
      data.length === 21
    ) {
      return Address._transformBuffer(data, network, type)
    } else if (
      (Buffer.isBuffer(data) || data instanceof Uint8Array) &&
      data.length === 33
    ) {
      // 33-byte buffer is a Taproot commitment
      return {
        hashBuffer: Buffer.from(data),
        network: typeof network === 'string' ? getNetwork(network)! : network,
        type: type || Address.PayToTaproot,
      }
    } else if (data instanceof PublicKey) {
      return Address._transformPublicKey(data, network)
    } else if (data instanceof Script) {
      return Address._transformScript(data, network)
    } else if (typeof data === 'string') {
      return Address._transformString(
        data,
        networkExplicitlyProvided ? network : undefined,
        type,
      )
    } else if (Array.isArray(data)) {
      // This case is handled in constructor for multisig
      throw new Error(
        'Multisig addresses should be created with createMultisig',
      )
    } else if (typeof data === 'object' && data !== null) {
      return Address._transformObject(data as AddressData)
    } else {
      throw new TypeError('First argument is an unrecognized data format.')
    }
  }

  /**
   * Internal function to discover the network and type based on the first data byte
   */
  private static _classifyFromVersion(buffer: Buffer): {
    network?: Network
    type?: string
  } {
    const version: { network?: Network; type?: string } = {}

    const pubkeyhashNetwork = getNetwork(buffer[0], 'pubkeyhash')
    const scripthashNetwork = getNetwork(buffer[0], 'scripthash')

    if (pubkeyhashNetwork) {
      version.network = pubkeyhashNetwork
      version.type = Address.PayToPublicKeyHash
    } else if (scripthashNetwork) {
      version.network = scripthashNetwork
      version.type = Address.PayToScriptHash
    }

    return version
  }

  /**
   * Internal function to transform a Lotus address string
   */
  private static _transformString(
    data: string,
    network?: Network | string,
    type?: string,
  ): AddressData {
    if (typeof data !== 'string') {
      throw new TypeError('data parameter supplied is not a string.')
    }

    data = data.trim()
    const networkObj = getNetwork(network!)

    if (network && !networkObj) {
      throw new TypeError('Unknown network')
    }

    // Check if it's a cash address
    if (data.indexOf(':') !== -1) {
      const info = Address.decodeCashAddress(data)
      if (
        !info.network ||
        (networkObj && networkObj.name !== info.network.name)
      ) {
        throw new TypeError('Address has mismatched network type.')
      }
      return {
        hashBuffer: Buffer.from(info.hashBuffer!),
        network: info.network,
        type: info.type,
      }
    }

    // Check if it's an XAddress
    if (Address._isXAddress(data)) {
      const info = Address._transformXAddressString(data, network, type)
      if (
        !info.network ||
        (networkObj && networkObj.name !== info.network.name)
      ) {
        throw new TypeError('Address has mismatched network type.')
      }
      return info
    }

    // Legacy address
    const info = Address._transformLegacyString(data, network, type)
    if (
      !info.network ||
      (networkObj && networkObj.name !== info.network.name)
    ) {
      throw new TypeError('Address has mismatched network type.')
    }
    return info
  }

  /**
   * Internal function to transform a legacy bitcoin address string
   */
  private static _transformLegacyString(
    data: string,
    network?: Network | string,
    type?: string,
  ): AddressData {
    const info: AddressData = {}
    const decoded = Base58Check.decode(data)
    const version = Address._classifyFromVersion(decoded)

    if (!version.network || !version.type) {
      throw new TypeError('Address has invalid version.')
    }

    info.hashBuffer = decoded.subarray(1)
    info.network = version.network
    info.type = version.type

    return info
  }

  /**
   * Check if a string is an XAddress format
   */
  private static _isXAddress(data: string): boolean {
    // XAddress format: prefix + networkChar + base58EncodedPayload
    // Network chars are: '_' (livenet), 'T' (testnet), 'R' (regtest)
    const match = /[A-Z]|_/.exec(data)
    return match !== null && match.index! > 0
  }

  /**
   * Internal function to transform an XAddress string
   */
  private static _transformXAddressString(
    data: string,
    network?: Network | string,
    type?: string,
  ): AddressData {
    if (typeof network === 'string') {
      network = getNetwork(network)
    }
    // default to mainnet if network still not yet
    network ||= defaultNetwork

    // Use the XAddress decode function
    const decodedXAddress = XAddress._decode(data)
    if (!decodedXAddress.hashBuffer) {
      throw new TypeError('Invalid XAddress.')
    }

    let hashBuffer = decodedXAddress.hashBuffer

    // Use the network from the decoded XAddress, not the parameter
    const decodedNetwork = decodedXAddress.network || network

    // The XAddress stores different data based on type
    // Check the decoded type first
    const decodedType = decodedXAddress.type

    // If type is 'taproot', the payload is the 33-byte commitment (not a script)
    if (decodedType === 'taproot' || decodedType === Address.PayToTaproot) {
      // XAddress might store full script (36 bytes) or just commitment (33 bytes)
      if (
        hashBuffer!.length === 36 &&
        hashBuffer[0] === 0x62 && // OP_SCRIPTTYPE
        hashBuffer[1] === 0x51 && // OP_1
        hashBuffer[2] === 0x21
      ) {
        // Full P2TR script stored - extract commitment
        hashBuffer = hashBuffer.subarray(3, 36)
      } else if (hashBuffer!.length === 33) {
        // Just the commitment - use as is
        // hashBuffer is already correct
      } else {
        throw new TypeError(
          `Taproot address has invalid payload length: ${hashBuffer!.length} bytes (expected 33 or 36)`,
        )
      }
      return {
        hashBuffer: hashBuffer,
        network: decodedNetwork,
        type: Address.PayToTaproot,
      }
    }

    // The XAddress stores the full script buffer, but we need to extract the hash buffer
    // If the stored buffer is a P2PKH script, extract the hash from it
    if (
      hashBuffer!.length === 25 &&
      hashBuffer[0] === 0x76 &&
      hashBuffer[1] === 0xa9 &&
      hashBuffer[2] === 0x14
    ) {
      // P2PKH script: OP_DUP OP_HASH160 OP_PUSH20 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
      hashBuffer = hashBuffer.subarray(3, 23) // Extract the 20-byte hash (skip push byte)
    }
    // If the stored buffer is a P2SH script, extract the hash from it
    else if (
      hashBuffer.length === 23 &&
      hashBuffer[0] === 0xa9 &&
      hashBuffer[1] === 0x14 &&
      hashBuffer[22] === 0x87
    ) {
      // P2SH script: OP_HASH160 OP_PUSH20 <20-byte-hash> OP_EQUAL
      hashBuffer = hashBuffer.subarray(2, 22) // Extract the 20-byte hash (skip push byte)
      return {
        hashBuffer: hashBuffer,
        network: decodedNetwork,
        type: Address.PayToScriptHash,
      }
    }

    return {
      hashBuffer: hashBuffer,
      network: decodedNetwork,
      type: type ?? Address.PayToPublicKeyHash,
    }
  }

  /**
   * Internal function to transform a hash buffer (20 bytes)
   */
  private static _transformHash(hash: Buffer | Uint8Array): AddressData {
    const info: AddressData = {}
    if (!Buffer.isBuffer(hash) && !(hash instanceof Uint8Array)) {
      throw new TypeError('Address supplied is not a buffer.')
    }
    if (hash.length !== 20) {
      throw new TypeError('Address hashbuffers must be exactly 20 bytes.')
    }
    info.hashBuffer = Buffer.from(hash)
    return info
  }

  /**
   * Internal function to transform a bitcoin address buffer (21 bytes)
   */
  private static _transformBuffer(
    buffer: Buffer | Uint8Array,
    network?: Network | string,
    type?: string,
  ): AddressData {
    const info: AddressData = {}
    if (!Buffer.isBuffer(buffer) && !(buffer instanceof Uint8Array)) {
      throw new TypeError('Address supplied is not a buffer.')
    }
    if (buffer.length !== 21) {
      throw new TypeError('Address buffers must be exactly 21 bytes.')
    }

    const networkObj = getNetwork(network!)
    const bufferVersion = Address._classifyFromVersion(Buffer.from(buffer))

    if (network && !networkObj) {
      throw new TypeError('Unknown network')
    }

    if (
      !bufferVersion.network ||
      (networkObj && networkObj !== bufferVersion.network)
    ) {
      throw new TypeError('Address has mismatched network type.')
    }

    if (!bufferVersion.type || (type && type !== bufferVersion.type)) {
      throw new TypeError('Address has mismatched type.')
    }

    info.hashBuffer = Buffer.from(buffer).subarray(1)
    info.network = bufferVersion.network
    info.type = bufferVersion.type
    return info
  }

  /**
   * Internal function to transform a public key
   */
  private static _transformPublicKey(
    pubkey: PublicKey,
    network?: Network,
  ): AddressData {
    const info: AddressData = {}
    if (!(pubkey instanceof PublicKey)) {
      throw new TypeError('Address must be an instance of PublicKey.')
    }
    info.hashBuffer = Hash.sha256ripemd160(pubkey.toBuffer())
    info.type = Address.PayToPublicKeyHash
    info.network = network ?? defaultNetwork
    return info
  }

  /**
   * Internal function to transform a Script into an info object
   */
  private static _transformScript(
    script: Script,
    network?: Network | string,
  ): AddressData {
    Preconditions.checkArgument(
      script instanceof Script,
      'script',
      'script must be a Script instance',
    )
    const address = script.getAddressInfo()

    if (!address) {
      throw new BitcoreError.Script.CantDeriveAddress(
        'Cannot derive address from script',
      )
    }

    // if network is provided, get the Network object
    if (typeof network === 'string') {
      network = getNetwork(network)
    }
    // if we have a network object and the network doesn't
    // match the address network, throw an error
    if (network && network !== address.network) {
      throw new TypeError(
        'Provided network does not match the Address network.',
      )
    }

    return {
      hashBuffer: address.hashBuffer,
      network: address.network,
      type: address.type,
    }
  }

  /**
   * Deserializes an address serialized through `Address#toObject()`
   */
  private static _transformObject(data: AddressData): AddressData {
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
      network: getNetwork(data.network!) || defaultNetwork,
      type: data.type,
    }
  }

  /**
   * Create a multisig address
   */
  static createMultisig(
    publicKeys: PublicKey[],
    threshold: number,
    network?: Network | string,
  ): Address {
    const networkObj = network || publicKeys[0].network || defaultNetwork
    return Address.payingTo(
      Script.buildMultisigOut(publicKeys, threshold, {}),
      networkObj,
    )
  }

  /**
   * Create address from public key
   */
  static fromPublicKey(data: PublicKey, network?: Network | string): Address {
    const networkObj = getNetwork(network!) || defaultNetwork
    const info = Address._transformPublicKey(data, networkObj)
    return new Address(info.hashBuffer, info.network, info.type)
  }

  /**
   * Create address from public key hash
   */
  static fromPublicKeyHash(hash: Buffer, network?: Network | string): Address {
    const networkObj = getNetwork(network!) || defaultNetwork
    return new Address(hash, networkObj, Address.PayToPublicKeyHash)
  }

  /**
   * Create address from script hash
   */
  static fromScriptHash(hash: Buffer, network?: Network | string): Address {
    const networkObj = getNetwork(network!) || defaultNetwork
    return new Address(hash, networkObj, Address.PayToScriptHash)
  }

  /**
   * Create Taproot address from commitment public key
   *
   * For Taproot, the "hash" is actually the 33-byte commitment public key.
   *
   * @param commitment - 33-byte commitment public key (tweaked)
   * @param network - Network (livenet, testnet, regtest)
   * @returns Taproot address
   */
  static fromTaprootCommitment(
    commitment: PublicKey | Buffer,
    network?: Network | string,
  ): Address {
    const networkObj = getNetwork(network!) || defaultNetwork
    const commitmentBuf =
      commitment instanceof PublicKey ? commitment.toBuffer() : commitment

    if (commitmentBuf.length !== 33) {
      throw new Error(
        'Taproot commitment must be 33-byte compressed public key',
      )
    }

    return new Address(commitmentBuf, networkObj, Address.PayToTaproot)
  }

  /**
   * Create address from buffer
   */
  static fromBuffer(
    buffer: Buffer,
    network?: Network | string,
    type?: string,
  ): Address {
    const info = Address._transformBuffer(buffer, network, type)
    return new Address(info.hashBuffer, info.network, info.type)
  }

  /**
   * Takes an address string and transforms it into an `AddressData` object which
   * contains the `hashBuffer`, `network`, and `type` parameters to instantiate the
   * new `Address` object.
   */
  static fromString(str: string, network?: Network | string): Address {
    const info = Address._transformString(str, network)
    return new Address(info.hashBuffer, info.network, info.type)
  }

  /**
   * Create address from object
   */
  static fromObject(obj: AddressObject): Address {
    Preconditions.checkState(
      JSUtil.isHexa(obj.hash),
      'Unexpected hash property, "' + obj.hash + '", expected to be hex.',
    )
    const hashBuffer = Buffer.from(obj.hash, 'hex')
    return new Address(hashBuffer, obj.network, obj.type)
  }

  /**
   * Extract address from a Script. The script must be of one
   * of the following types: p2pkh input, p2pkh output, p2sh input
   * or p2sh output.
   */
  static fromScript(script: Script, network?: Network | string): Address {
    Preconditions.checkArgument(
      script instanceof Script,
      'script',
      'script must be a Script instance',
    )
    const info = Address._transformScript(script, network)
    return new Address(info.hashBuffer, network, info.type)
  }

  /**
   * Builds a p2sh address paying to script. This will hash the script and
   * use that to create the address.
   */
  static payingTo(script: Script, network?: Network | string): Address {
    Preconditions.checkArgument(script !== null, 'script', 'script is required')
    Preconditions.checkArgument(
      script instanceof Script,
      'script',
      'script must be instance of Script',
    )

    return Address.fromScriptHash(
      Hash.sha256ripemd160(script.toBuffer()),
      network,
    )
  }

  /**
   * Will return a validation error if exists
   */
  static getValidationError(
    data: AddressInput,
    network?: Network | string,
    type?: string,
  ): Error | null {
    try {
      new Address(data, network, type)
      return null
    } catch (e) {
      return e as Error
    }
  }

  /**
   * Will return a boolean if an address is valid
   */
  static isValid(
    data: AddressInput,
    network?: Network | string,
    type?: string,
  ): boolean {
    return !Address.getValidationError(data, network, type)
  }

  /**
   * Check if address is pay to public key hash
   */
  isPayToPublicKeyHash(): boolean {
    return this.type === Address.PayToPublicKeyHash
  }

  /**
   * Check if address is pay to script hash
   */
  isPayToScriptHash(): boolean {
    return this.type === Address.PayToScriptHash
  }

  /**
   * Check if address is pay to taproot
   */
  isPayToTaproot(): boolean {
    return this.type === Address.PayToTaproot
  }

  /**
   * Will return a buffer representation of the address (hash buffer only)
   */
  toBuffer(): Buffer {
    return this.hashBuffer
  }

  /**
   * Will return a full buffer representation of the address (version + hash)
   */
  toFullBuffer(): Buffer {
    const version = Buffer.from([
      this.network[this.type as keyof Network] as number,
    ])
    const buf = Buffer.concat([version, this.hashBuffer])
    return buf
  }

  /**
   * Will return a cash address buffer representation
   */
  toCashBuffer(): Buffer {
    // Simplified implementation - would need full cash address logic
    return this.toBuffer()
  }

  /**
   * Returns a plain object with the address information
   */
  toObject(): AddressObject {
    return {
      hash: this.hashBuffer.toString('hex'),
      type: this.type,
      network: this.network.toString(),
    }
  }

  toJSON(): AddressObject {
    return this.toObject()
  }

  /**
   * Wrapper method for `Address.toXAddress` method
   */
  toString(network?: Network | string): string {
    /* const version = this.network[this.type as keyof Network] as number
    const payload = Buffer.concat([Buffer.from([version]), this.hashBuffer])
    return Base58Check.encode(payload) */
    return this.toXAddress(network)
  }

  /**
   * Will return a legacy address string
   */
  toLegacyAddress(): string {
    return this.toString()
  }

  /**
   * Will return a cash address string
   */
  toCashAddress(): string {
    // Simplified implementation - would need full cash address logic
    return this.toString()
  }

  /**
   * Will return an X address string
   */
  toXAddress(network?: Network | string): string {
    // For Taproot addresses, XAddress encodes only the 33-byte commitment,
    // not the full script. This matches lotusd's implementation.
    // Reference: lotusd/src/addresses/xaddress.cpp:175-180
    if (this.isPayToTaproot()) {
      const xaddr = new XAddress(
        this.hashBuffer, // 33-byte commitment only
        network ?? this.network,
        this.type,
      )
      return xaddr.toString()
    }

    // For other address types, use the full script
    const script = Script.fromAddress(this)
    const xaddr = new XAddress(
      script.toBuffer(),
      network ?? this.network,
      this.type,
    )
    return xaddr.toString()
  }

  /**
   * Decode cash address
   */
  static decodeCashAddress(address: string): CashAddressDecoding {
    // Simplified implementation - would need full cash address decoding logic
    const info = Address._transformString(address)
    return {
      network: info.network!,
      type: info.type!,
      hashBuffer: info.hashBuffer!,
    }
  }

  /**
   * Inspect method for debugging
   */
  inspect(): string {
    return (
      '<Address: ' +
      this.toString() +
      ', type: ' +
      this.type +
      ', network: ' +
      this.network +
      '>'
    )
  }
}

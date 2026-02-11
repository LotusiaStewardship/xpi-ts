/**
 * Message class for signing and verifying Bitcoin messages
 * Migrated from bitcore-lib-xpi with ESM support
 */
import { Hash } from './crypto/hash'
import { ECDSA } from './crypto/ecdsa'
import { Signature } from './crypto/signature'
import { PrivateKey } from './privatekey'
import { PublicKey } from './publickey'
import { Address } from './address'
import { BufferUtil } from './util/buffer'
import { JSUtil } from './util/js'
import { BufferWriter } from './encoding/bufferwriter'
import { Preconditions } from './util/preconditions'
import type { Buffer } from 'buffer/'

/**
 * Message class for signing and verifying Bitcoin-style messages.
 *
 * Implements the Bitcoin message signing standard using ECDSA signatures
 * with recovery. Messages are prefixed with a magic string before hashing
 * to prevent signing arbitrary data that could be interpreted as transactions.
 *
 * The signature format includes a recovery flag that allows the public key
 * to be recovered from the signature, enabling verification using only
 * the message, signature, and expected address.
 *
 * @example
 * ```typescript
 * // Sign a message
 * const message = new Message('Hello, Lotus!')
 * const privateKey = new PrivateKey()
 * const signature = message.sign(privateKey)
 *
 * // Verify with address
 * const address = privateKey.toAddress()
 * const verified = message.verify(address, signature)
 *
 * // Recover public key from signature
 * const recoveredPubKey = message.recoverPublicKey(address, signature)
 * ```
 */
export class Message {
  private _message: string
  public error?: string // Match reference: error property for verification failures

  // Constants to match reference
  // Note: Lotus uses "Bitcoin Signed Message:\n" for compatibility with Bitcoin message signing standard
  // This matches lotusd/src/util/message.cpp:22 MESSAGE_MAGIC
  static readonly MAGIC_BYTES = BufferUtil.from('Bitcoin Signed Message:\n')

  constructor(message: string) {
    Preconditions.checkArgument(
      typeof message === 'string',
      'First argument should be a string',
    )
    this._message = message
  }

  /**
   * Get the magic hash for signing
   */
  magicHash(): Buffer {
    const prefix1 = BufferWriter.varintBufNum(Message.MAGIC_BYTES.length)
    const messageBuffer = BufferUtil.from(this._message)
    const prefix2 = BufferWriter.varintBufNum(messageBuffer.length)
    const buf = BufferUtil.concat([
      prefix1,
      Message.MAGIC_BYTES,
      prefix2,
      messageBuffer,
    ])
    const hash = Hash.sha256sha256(buf)
    return hash
  }

  /**
   * Internal sign method
   */
  private _sign(privateKey: PrivateKey): Signature {
    Preconditions.checkArgument(
      privateKey instanceof PrivateKey,
      'First argument should be an instance of PrivateKey',
    )
    const hash = this.magicHash()
    const ecdsa = new ECDSA()
    ecdsa.hashbuf = hash
    ecdsa.privkey = privateKey
    ecdsa.pubkey = privateKey.toPublicKey()
    ecdsa.signRandomK()
    ecdsa.calci()
    return ecdsa.sig
  }

  /**
   * Sign the message with a private key
   */
  sign(privateKey: PrivateKey): string {
    const signature = this._sign(privateKey)
    return signature.toCompact().toString('base64') // Match reference: base64 format
  }

  /**
   * Internal verify method
   */
  private _verify(publicKey: PublicKey, signature: Signature): boolean {
    Preconditions.checkArgument(
      publicKey instanceof PublicKey,
      'First argument should be an instance of PublicKey',
    )
    Preconditions.checkArgument(
      signature instanceof Signature,
      'Second argument should be an instance of Signature',
    )
    const hash = this.magicHash()
    const verified = ECDSA.verify(hash, signature, publicKey)
    if (!verified) {
      this.error = 'The signature was invalid'
    }
    return verified
  }

  /**
   * Verify a signature against a Bitcoin address
   */
  verify(bitcoinAddress: Address | string, signatureString: string): boolean {
    Preconditions.checkArgument(!!bitcoinAddress, 'bitcoinAddress is required')
    Preconditions.checkArgument(
      !!(signatureString && typeof signatureString === 'string'),
      'signatureString is required',
    )

    const address =
      typeof bitcoinAddress === 'string'
        ? Address.fromString(bitcoinAddress)
        : bitcoinAddress

    const signature = Signature.fromCompact(
      BufferUtil.from(signatureString, 'base64'),
    )

    // Recover the public key
    const ecdsa = new ECDSA()
    ecdsa.hashbuf = this.magicHash()
    ecdsa.sig = signature
    const publicKey = ecdsa.toPublicKey()

    const signatureAddress = Address.fromPublicKey(publicKey, address.network)

    // Check that the recovered address and specified address match
    if (address.toString() !== signatureAddress.toString()) {
      this.error = 'The signature did not match the message digest'
      return false
    }

    return this._verify(publicKey, signature)
  }

  /**
   * Recover public key from signature
   */
  recoverPublicKey(
    bitcoinAddress: Address | string,
    signatureString: string,
  ): string {
    Preconditions.checkArgument(!!bitcoinAddress, 'bitcoinAddress is required')
    Preconditions.checkArgument(
      !!(signatureString && typeof signatureString === 'string'),
      'signatureString is required',
    )

    const address =
      typeof bitcoinAddress === 'string'
        ? Address.fromString(bitcoinAddress)
        : bitcoinAddress

    const signature = Signature.fromCompact(
      BufferUtil.from(signatureString, 'base64'),
    )

    // Recover the public key
    const ecdsa = new ECDSA()
    ecdsa.hashbuf = this.magicHash()
    ecdsa.sig = signature
    const publicKey = ecdsa.toPublicKey()

    const signatureAddress = Address.fromPublicKey(publicKey, address.network)

    // Check that the recovered address and specified address match
    if (address.toString() !== signatureAddress.toString()) {
      this.error = 'The signature did not match the message digest'
    }

    return publicKey.toString()
  }

  /**
   * Create Message from string
   */
  static fromString(str: string): Message {
    return new Message(str)
  }

  /**
   * Create Message from JSON
   */
  static fromJSON(json: string | object): Message {
    if (typeof json === 'string' && JSUtil.isValidJSON(json)) {
      json = JSON.parse(json)
    }
    return new Message((json as { message: string }).message)
  }

  /**
   * Convert to object
   */
  toObject(): { message: string } {
    return { message: this._message }
  }

  /**
   * Convert to JSON
   * @alias toObject API compatibility wrapper (may not be needed)
   */
  toJSON(): { message: string } {
    return this.toObject()
  }

  /**
   * Convert to string
   */
  toString(): string {
    return this._message
  }

  /**
   * Get string representation for console
   */
  inspect(): string {
    return '<Message: ' + this.toString() + '>'
  }
}

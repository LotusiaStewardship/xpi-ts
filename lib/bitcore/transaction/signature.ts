import { Preconditions } from '../util/preconditions.js'
import { JSUtil } from '../util/js.js'
import { PublicKey, PublicKeyInput } from '../publickey.js'
import { BitcoreError } from '../errors.js'
import { Signature } from '../crypto/signature.js'
import { BN } from '../crypto/bn.js'
import { isSchnorrSignature } from '../crypto/sigtype.js'

export interface TransactionSignatureData {
  publicKey: PublicKey | Buffer | string
  prevTxId: Buffer | string
  outputIndex: number
  inputIndex: number
  signature: Signature | Buffer | string
  sigtype: number
}

export interface TransactionSignatureObject {
  publicKey: string
  prevTxId: string
  outputIndex: number
  inputIndex: number
  signature: string
  sigtype: number
}

/**
 * Represents a digital signature within a transaction input, including identifying information and the signature itself.
 *
 * The `TransactionSignature` class extends the low-level cryptography `Signature` class and includes additional context,
 * such as which input/output the signature is for, the signer public key, and the sighash type.
 *
 * It automatically detects and parses ECDSA (DER format) and Schnorr signatures, supports serialization/deserialization,
 * and provides basic validation logic.
 *
 * @example
 * const tsig = new TransactionSignature({
 *   publicKey: pubkey,
 *   prevTxId: txid,
 *   outputIndex: 0,
 *   inputIndex: 0,
 *   signature: sigBuf, // Buffer, Signature, or hex
 *   sigtype: Signature.SIGHASH_ALL,
 * });
 */
export class TransactionSignature extends Signature {
  /** Public key of the signer */
  publicKey!: PublicKey
  /** Previous transaction id for the referenced UTXO (as Buffer) */
  prevTxId!: Buffer
  /** Index of the output in the previous transaction being spent */
  outputIndex!: number
  /** Index of this input in the current transaction */
  inputIndex!: number
  /** Signature hash type used for this signature (see Signature.SIGHASH_*) */
  sigtype!: number
  /** Signature value; can be Schnorr or ECDSA, as a Signature object */
  signature!: Signature

  /**
   * Creates a new TransactionSignature instance.
   *
   * @param arg - The signature data. Must be a TransactionSignatureData, another TransactionSignature, or (never used) string.
   * @throws {BitcoreError} If required arguments are missing or invalid.
   */
  constructor(arg?: TransactionSignatureData | TransactionSignature) {
    super(BN.fromNumber(0) as BN, BN.fromNumber(0) as BN)

    if (arg instanceof TransactionSignature) {
      return arg
    }

    if (typeof arg === 'object' && arg !== null) {
      return this._fromObject(arg)
    } else {
      throw new BitcoreError(
        'TransactionSignatures must be instantiated from an object',
      )
    }
  }

  /**
   * Initialize a TransactionSignature instance from an object.
   *
   * This method will set all required properties of the TransactionSignature, including
   * parsing and detecting whether the signature uses Schnorr or ECDSA encoding.
   *
   * @param arg - The object containing properties to initialize the TransactionSignature.
   * @returns The TransactionSignature instance with all fields set.
   * @throws {BitcoreError} If required or invalid arguments are supplied.
   *
   * Signature parsing process:
   *   - If the signature is already a Signature instance, it is directly assigned.
   *   - If the signature is a Buffer, it detects type (Schnorr/ECDSA) based on length and content,
   *     optionally stripping a possible sighash byte for type detection.
   *   - If the signature is a string, it is parsed from hex; type detection is performed similarly.
   */
  private _fromObject(arg: TransactionSignatureData): TransactionSignature {
    this._checkObjectArgs(arg)
    this.publicKey = new PublicKey(arg.publicKey as PublicKeyInput)
    this.prevTxId = Buffer.isBuffer(arg.prevTxId)
      ? arg.prevTxId
      : Buffer.from(arg.prevTxId, 'hex')
    this.outputIndex = arg.outputIndex
    this.inputIndex = arg.inputIndex

    // Parse signature with proper Schnorr/ECDSA detection
    if (arg.signature instanceof Signature) {
      this.signature = arg.signature
    } else if (Buffer.isBuffer(arg.signature)) {
      // Detect signature type by length (64 or 65 bytes = Schnorr, else ECDSA)
      // Remove sighash byte if present for detection
      const sigWithoutSighash =
        arg.signature.length > 64 &&
        arg.signature[arg.signature.length - 1] !== 0x30
          ? arg.signature.subarray(0, -1)
          : arg.signature

      if (isSchnorrSignature(sigWithoutSighash)) {
        // Parse as Schnorr signature (64 or 65 bytes)
        const parsed = Signature.parseSchnorrEncodedSig(arg.signature)
        const sig = new Signature(parsed.r, parsed.s)
        sig.isSchnorr = true
        if (parsed.nhashtype) {
          sig.nhashtype = parsed.nhashtype.readUInt8(0)
        }
        this.signature = sig
      } else {
        // Parse as DER-encoded ECDSA signature
        this.signature = Signature.fromDER(arg.signature)
      }
    } else {
      // Parse from hex string
      const buf = Buffer.from(arg.signature, 'hex')
      const sigWithoutSighash =
        buf.length > 64 && buf[buf.length - 1] !== 0x30
          ? buf.subarray(0, -1)
          : buf

      if (isSchnorrSignature(sigWithoutSighash)) {
        // Parse as Schnorr signature (64 or 65 bytes)
        const parsed = Signature.parseSchnorrEncodedSig(buf)
        const sig = new Signature(parsed.r, parsed.s)
        sig.isSchnorr = true
        if (parsed.nhashtype) {
          sig.nhashtype = parsed.nhashtype.readUInt8(0)
        }
        this.signature = sig
      } else {
        this.signature = Signature.fromString(arg.signature)
      }
    }

    this.sigtype = arg.sigtype
    return this
  }

  /**
   * Validates the input object for TransactionSignature construction.
   *
   * @param arg - The object to validate.
   * @throws {BitcoreError} If required fields are missing or invalid.
   * @private
   */
  private _checkObjectArgs(arg: TransactionSignatureData): void {
    Preconditions.checkArgument(
      arg.publicKey !== undefined,
      'publicKey is required',
    )
    Preconditions.checkArgument(
      arg.inputIndex !== undefined,
      'inputIndex is required',
    )
    Preconditions.checkArgument(
      arg.outputIndex !== undefined,
      'outputIndex is required',
    )
    Preconditions.checkState(
      typeof arg.inputIndex === 'number',
      'inputIndex must be a number',
    )
    Preconditions.checkState(
      typeof arg.outputIndex === 'number',
      'outputIndex must be a number',
    )
    Preconditions.checkArgument(
      arg.signature !== undefined,
      'signature is required',
    )
    Preconditions.checkArgument(
      arg.prevTxId !== undefined,
      'prevTxId is required',
    )
    Preconditions.checkState(
      arg.signature instanceof Signature ||
        Buffer.isBuffer(arg.signature) ||
        JSUtil.isHexa(arg.signature),
      'signature must be a buffer or hexa value',
    )
    Preconditions.checkState(
      Buffer.isBuffer(arg.prevTxId) || JSUtil.isHexa(arg.prevTxId),
      'prevTxId must be a buffer or hexa value',
    )
    Preconditions.checkArgument(
      arg.sigtype !== undefined,
      'sigtype is required',
    )
    Preconditions.checkState(
      typeof arg.sigtype === 'number',
      'sigtype must be a number',
    )
  }

  /**
   * Converts signature to plain JS object representation.
   * @returns The object with all signature fields as string/number types.
   */
  toObject(): TransactionSignatureObject {
    return {
      publicKey: this.publicKey.toString(),
      prevTxId: this.prevTxId.toString('hex'),
      outputIndex: this.outputIndex,
      inputIndex: this.inputIndex,
      signature: this.signature.toString(),
      sigtype: this.sigtype,
    }
  }

  /**
   * Converts signature to a plain object suitable for JSON serialization.
   */
  toJSON = this.toObject

  /**
   * Factory for constructing a TransactionSignature from an object.
   * @param obj - The signature data.
   * @returns New TransactionSignature instance.
   */
  static fromObject(obj: TransactionSignatureData): TransactionSignature {
    return new TransactionSignature(obj)
  }

  /**
   * Clone this transaction signature.
   * @returns Deep copy of this TransactionSignature.
   */
  clone(): TransactionSignature {
    return new TransactionSignature({
      publicKey: this.publicKey,
      prevTxId: Buffer.from(this.prevTxId),
      outputIndex: this.outputIndex,
      inputIndex: this.inputIndex,
      signature: this.signature,
      sigtype: this.sigtype,
    })
  }

  /**
   * Checks if this signature has all required fields and format.
   * @returns True if the signature is structurally valid.
   */
  isValid(): boolean {
    return (
      this.publicKey !== undefined &&
      this.prevTxId !== undefined &&
      this.outputIndex >= 0 &&
      this.inputIndex >= 0 &&
      this.signature !== undefined &&
      this.sigtype !== undefined &&
      PublicKey.isValid(this.publicKey) &&
      this.signature.r !== undefined &&
      this.signature.s !== undefined
    )
  }

  /**
   * Returns a human-readable string representation.
   * @returns Format like "TransactionSignature(0:0)".
   */
  toString(): string {
    return `TransactionSignature(${this.inputIndex}:${this.outputIndex})`
  }
}

/**
 * Transaction Input implementation for Lotus
 *
 * Signature Handling:
 * - All input types support both ECDSA and Schnorr signatures
 * - Signature type is specified via signingMethod parameter: 'ecdsa' or 'schnorr'
 * - Signatures are automatically detected by length when parsing (64 bytes = Schnorr)
 *
 * Input Types:
 * - Input (base class) - Generic input with P2PKH and P2PK support
 * - PublicKeyHashInput (P2PKH) - Standard pay-to-pubkey-hash
 * - PublicKeyInput (P2PK) - Pay-to-pubkey
 * - MultisigInput - Multi-signature output spending
 * - MultisigScriptHashInput (P2SH) - Pay-to-script-hash multisig
 *
 * Critical Notes:
 * - TransactionSignature.signature property holds the actual Signature object
 * - Must call methods on signature.signature, not directly on TransactionSignature
 * - Size estimation constants are conservative (assume larger ECDSA signatures)
 *
 * Reference: lotusd/src/script/interpreter.cpp
 */

import { Preconditions } from '../util/preconditions.js'
import { BitcoreError } from '../errors.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { BufferReader } from '../encoding/bufferreader.js'
import { BufferUtil } from '../util/buffer.js'
import { JSUtil } from '../util/js.js'
import { Script, empty } from '../script.js'
import { Opcode } from '../opcode.js'
import { BN } from '../crypto/bn.js'
import { Output } from './output.js'
import { PrivateKey } from '../privatekey.js'
import { PublicKey } from '../publickey.js'
import { Signature, SignatureSigningMethod } from '../crypto/signature.js'
import { TransactionSignature } from './signature.js'
import { Transaction } from './transaction.js'
import { sign, verify, TransactionLike } from './sighash.js'
import { Hash } from '../crypto/hash.js'
import {
  tweakPrivateKey,
  TAPROOT_SIGHASH_TYPE,
  extractTaprootCommitment,
} from '../taproot.js'
import type {
  MuSigKeyAggContext,
  MuSigAggregatedNonce,
} from '../crypto/musig2.js'
import { musigNonceAgg, musigSigAgg } from '../crypto/musig2.js'
import { Point } from '../crypto/point.js'

export interface InputData {
  prevTxId?: Buffer | string
  outputIndex?: number
  sequenceNumber?: number
  script?: Script | Buffer | string
  scriptBuffer?: Buffer
  output?: Output // Output type
}

export interface InputObject {
  prevTxId?: Buffer | string
  outputIndex?: number
  sequenceNumber?: number
  script?: Script | Buffer | string
  scriptBuffer?: Buffer
  scriptString?: string
  output?: Output
}

/**
 * Represents a transaction input
 */
export class Input {
  // Constants
  static readonly MAXINT = 0xffffffff // Math.pow(2, 32) - 1
  static readonly DEFAULT_SEQNUMBER = 0xffffffff
  static readonly DEFAULT_LOCKTIME_SEQNUMBER = 0xfffffffe
  static readonly DEFAULT_RBF_SEQNUMBER = 0xfffffffd
  static readonly SEQUENCE_LOCKTIME_TYPE_FLAG = 0x400000 // (1 << 22)
  static readonly SEQUENCE_LOCKTIME_DISABLE_FLAG = 0x80000000 // (1 << 31)
  static readonly SEQUENCE_LOCKTIME_MASK = 0xffff
  static readonly SEQUENCE_LOCKTIME_GRANULARITY = 512 // 512 seconds
  static readonly SEQUENCE_BLOCKDIFF_LIMIT = 0xffff // 16 bits

  // Subclasses
  static PublicKey: typeof PublicKeyInput
  static PublicKeyHash: typeof PublicKeyHashInput
  static Multisig: typeof MultisigInput
  static MultisigScriptHash: typeof MultisigScriptHashInput
  static Taproot: typeof TaprootInput
  static MuSigTaproot: typeof MuSigTaprootInput
  static P2PKH: typeof PublicKeyHashInput
  static P2SH: typeof MultisigScriptHashInput
  static P2TR: typeof TaprootInput

  // Instance properties
  /**
   * The transaction ID of the previous output being spent, as a Buffer.
   * This buffer is stored in internal (little-endian) order, as per Lotus transaction format,
   * but is typically displayed in RPCs or hex as big-endian (human-readable) order.
   */
  prevTxId!: Buffer
  outputIndex!: number
  sequenceNumber!: number
  private _scriptBuffer!: Buffer
  private _script?: Script
  output?: Output // Output type

  constructor(params?: InputData) {
    if (params) {
      this._fromObject(params)
    }
  }

  // Factory function to allow calling Input() without 'new'
  static create(params?: InputData): Input {
    return new Input(params)
  }

  static fromObject(obj: InputData): Input {
    Preconditions.checkArgument(
      typeof obj === 'object' && obj !== null,
      'Must provide an object',
    )
    const input = new Input()
    return input._fromObject(obj)
  }

  private _fromObject(params: InputData): Input {
    let prevTxId: Buffer
    if (typeof params.prevTxId === 'string' && JSUtil.isHexa(params.prevTxId)) {
      prevTxId = Buffer.from(params.prevTxId, 'hex')
    } else if (Buffer.isBuffer(params.prevTxId)) {
      prevTxId = params.prevTxId
    } else {
      prevTxId = Buffer.alloc(0) // Default empty buffer
    }

    this.output = params.output
    this.prevTxId = prevTxId
    this.outputIndex = params.outputIndex ?? 0
    this.sequenceNumber =
      params.sequenceNumber !== undefined
        ? params.sequenceNumber
        : Input.DEFAULT_SEQNUMBER

    if (params.scriptBuffer === undefined && params.script === undefined) {
      throw new BitcoreError.Transaction.Input.MissingScript()
    }

    this.setScript(params.scriptBuffer || params.script!)
    return this
  }

  /**
   * Get the script for this input
   */
  get script(): Script | null {
    if (this.isNull()) {
      return null
    }
    if (!this._script) {
      this._script = new Script(this._scriptBuffer)
      // Mark as input script
      ;(this._script as Script & { _isInput?: boolean })._isInput = true
    }
    return this._script
  }

  /**
   * Get the script buffer
   */
  get scriptBuffer(): Buffer {
    return this._scriptBuffer
  }

  /**
   * Set the script for this input
   */
  setScript(script: Script | Buffer | string | null): Input {
    this._script = undefined
    if (script instanceof Script) {
      this._script = script
      this._scriptBuffer = script.toBuffer()
    } else if (script === null) {
      this._script = empty()
      this._scriptBuffer = this._script.toBuffer()
    } else if (Buffer.isBuffer(script)) {
      this._scriptBuffer = script
      this._script = Script.fromBuffer(script)
    } else if (typeof script === 'string') {
      if (JSUtil.isHexa(script)) {
        this._scriptBuffer = Buffer.from(script, 'hex')
        this._script = Script.fromBuffer(this._scriptBuffer)
      } else {
        // Assume it's a script string
        this._scriptBuffer = Buffer.from(script, 'utf8')
        this._script = Script.fromBuffer(this._scriptBuffer)
      }
    } else {
      throw new TypeError('Invalid script type')
    }
    return this
  }

  /**
   * Check if this is a null input (coinbase)
   */
  isNull(): boolean {
    return (
      this.prevTxId.toString('hex') ===
        '0000000000000000000000000000000000000000000000000000000000000000' &&
      this.outputIndex === 0xffffffff
    )
  }

  /**
   * Check if this input is final
   */
  isFinal(): boolean {
    return this.sequenceNumber !== 4294967295
  }

  /**
   * Check if this input has a sequence number
   */
  hasSequence(): boolean {
    return this.sequenceNumber !== Input.DEFAULT_SEQNUMBER
  }

  /**
   * Check if this input has a relative lock time
   */
  hasRelativeLockTime(): boolean {
    return (
      (this.sequenceNumber & Input.SEQUENCE_LOCKTIME_DISABLE_FLAG) !==
        Input.SEQUENCE_LOCKTIME_DISABLE_FLAG &&
      this.sequenceNumber !== Input.DEFAULT_SEQNUMBER
    )
  }

  /**
   * Get the relative lock time value
   */
  getRelativeLockTime(): bigint {
    if (!this.hasRelativeLockTime()) {
      return BigInt(0)
    }
    return BigInt(this.sequenceNumber & Input.SEQUENCE_LOCKTIME_MASK)
  }

  /**
   * Check if the relative lock time is in blocks
   */
  isRelativeLockTimeInBlocks(): boolean {
    if (!this.hasRelativeLockTime()) {
      return false
    }
    return (this.sequenceNumber & Input.SEQUENCE_LOCKTIME_TYPE_FLAG) !== 0
  }

  /**
   * Get the relative lock time in blocks
   */
  getRelativeLockTimeInBlocks(): number {
    if (!this.isRelativeLockTimeInBlocks()) {
      return 0
    }
    return Number(this.getRelativeLockTime())
  }

  /**
   * Get the relative lock time in seconds
   */
  getRelativeLockTimeInSeconds(): number {
    if (this.isRelativeLockTimeInBlocks()) {
      return 0
    }
    return (
      Number(this.getRelativeLockTime()) *
      Number(Input.SEQUENCE_LOCKTIME_GRANULARITY)
    )
  }

  /**
   * Convert to object representation
   */
  toObject(): InputObject {
    const obj: InputObject = {
      prevTxId: Buffer.from(this.prevTxId).toString('hex'),
      outputIndex: this.outputIndex,
      sequenceNumber: this.sequenceNumber,
      script: this._scriptBuffer.toString('hex'),
    }

    // Add human readable form if input contains valid script
    if (this.script) {
      ;(obj as InputObject & { scriptString?: string }).scriptString =
        this.script.toASM()
    }

    if (this.output) {
      ;(obj as InputObject & { output?: Output }).output = this.output
    }

    return obj
  }

  /**
   * Convert to JSON
   */
  toJSON = this.toObject

  /**
   * Create from buffer reader
   */
  static fromBufferReader(br: BufferReader): Input {
    const input = new Input()
    input.prevTxId = br.readReverse(32)
    input.outputIndex = br.readUInt32LE()
    input._scriptBuffer = br.readVarLengthBuffer()
    input.sequenceNumber = br.readUInt32LE()
    return input
  }

  /**
   * Serialize to buffer
   */
  toBuffer(): Buffer {
    const bw = new BufferWriter()
    bw.writeReverse(this.prevTxId)
    bw.writeUInt32LE(this.outputIndex)
    bw.writeVarLengthBuffer(this._scriptBuffer)
    bw.writeUInt32LE(this.sequenceNumber)
    return bw.concat()
  }

  /**
   * Write to buffer writer
   */
  toBufferWriter(writer?: BufferWriter): BufferWriter {
    if (!writer) {
      writer = new BufferWriter()
    }
    writer.writeReverse(this.prevTxId)
    writer.writeUInt32LE(this.outputIndex)
    const script = this._scriptBuffer
    writer.writeVarintNum(script.length)
    writer.write(script)
    writer.writeUInt32LE(this.sequenceNumber)
    return writer
  }

  /**
   * Get the size of this input in bytes
   */
  getSize(): number {
    return (
      32 + // prevTxId
      4 + // outputIndex
      BufferWriter.varintBufNum(this._scriptBuffer.length).length +
      this._scriptBuffer.length + // script
      4 // sequenceNumber
    )
  }

  /**
   * Check if this input is valid
   */
  isValid(): boolean {
    if (this.isNull()) {
      return true
    }
    return (
      this.prevTxId.length === 32 &&
      this.outputIndex >= 0 &&
      this.outputIndex <= 0xffffffff &&
      this._scriptBuffer.length > 0
    )
  }

  /**
   * Clone this input
   */
  clone(): Input {
    return new Input({
      prevTxId: Buffer.from(this.prevTxId),
      outputIndex: this.outputIndex,
      sequenceNumber: this.sequenceNumber,
      scriptBuffer: Buffer.from(this._scriptBuffer),
      output: this.output,
    })
  }

  /**
   * Get signatures for the provided PrivateKey
   * @abstract
   */
  getSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype?: number,
    hashData?: unknown,
    signingMethod?: string,
  ): TransactionSignature[] {
    Preconditions.checkState(
      this.output instanceof Output,
      'Output is required',
    )

    sigtype = sigtype || Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
    const publicKey = privateKey.publicKey

    // Check if this is a P2PKH output
    if (this.output!.script.isPublicKeyHashOut()) {
      const addressHash = hashData || Hash.sha256ripemd160(publicKey.toBuffer())
      if (
        BufferUtil.equals(
          addressHash as Buffer,
          this.output!.script.getPublicKeyHash(),
        )
      ) {
        return [
          new TransactionSignature({
            publicKey: publicKey,
            prevTxId: this.prevTxId,
            outputIndex: this.outputIndex,
            inputIndex: index,
            signature: sign(
              transaction as unknown as TransactionLike,
              privateKey,
              sigtype,
              index,
              this.output!.script,
              new BN(this.output!.satoshis.toString()),
              undefined,
              signingMethod as 'ecdsa' | 'schnorr',
            ),
            sigtype: sigtype,
          }),
        ]
      }
    }
    // Check if this is a P2PK output
    else if (this.output!.script.isPublicKeyOut()) {
      if (
        publicKey.toString() ===
        this.output!.script.getPublicKey().toString('hex')
      ) {
        return [
          new TransactionSignature({
            publicKey: publicKey,
            prevTxId: this.prevTxId,
            outputIndex: this.outputIndex,
            inputIndex: index,
            signature: sign(
              transaction as unknown as TransactionLike,
              privateKey,
              sigtype,
              index,
              this.output!.script,
              new BN(this.output!.satoshis.toString()),
              undefined,
              signingMethod as 'ecdsa' | 'schnorr',
            ),
            sigtype: sigtype,
          }),
        ]
      }
    }

    return []
  }

  /**
   * Check if this input is fully signed
   * @abstract
   */
  isFullySigned(): boolean {
    throw new Error('Input#isFullySigned')
  }

  /**
   * Add signature to this input
   * @abstract
   */
  addSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: SignatureSigningMethod,
  ): this {
    Preconditions.checkState(
      this.isValidSignature(transaction, signature, signingMethod),
      'Signature is invalid',
    )

    // Determine input type based on output script and create appropriate input script
    if (this.output?.script.isPublicKeyHashOut()) {
      // P2PKH input: signature + public key
      const script = new Script()
      script.add(signature.signature.toTxFormat(signingMethod))
      script.add(signature.publicKey.toBuffer())
      this.setScript(script)
    } else if (this.output?.script.isPublicKeyOut()) {
      // P2PK input: signature only
      const script = new Script()
      script.add(signature.signature.toTxFormat(signingMethod))
      this.setScript(script)
    } else {
      // For other input types, create a basic script with signature
      // This is a fallback for unknown input types
      const script = new Script()
      script.add(signature.signature.toTxFormat(signingMethod))
      if (signature.publicKey) {
        script.add(signature.publicKey.toBuffer())
      }
      this.setScript(script)
    }

    return this
  }

  /**
   * Clear all signatures from this input
   * @abstract
   */
  clearSignatures(): this {
    throw new Error('Input#clearSignatures')
  }

  /**
   * Validate a signature for this input
   */
  isValidSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: string,
  ): boolean {
    // FIXME: Refactor signature so this is not necessary
    signature.signature.nhashtype = signature.sigtype
    return verify(
      transaction as unknown as TransactionLike,
      signature.signature,
      signature.publicKey,
      signature.inputIndex,
      this.output!.script,
      new BN(this.output!.satoshis.toString()),
      undefined,
      signingMethod as 'ecdsa' | 'schnorr',
    )
  }

  /**
   * Lock input for specified seconds
   */
  lockForSeconds(seconds: number): Input {
    Preconditions.checkArgument(
      typeof seconds === 'number',
      'seconds must be a number',
    )
    if (
      seconds < 0 ||
      seconds >=
        Input.SEQUENCE_LOCKTIME_GRANULARITY * Input.SEQUENCE_LOCKTIME_MASK
    ) {
      throw new Error('Lock time range error')
    }
    seconds = Math.floor(seconds / Input.SEQUENCE_LOCKTIME_GRANULARITY)
    this.sequenceNumber = seconds | Input.SEQUENCE_LOCKTIME_TYPE_FLAG
    return this
  }

  /**
   * Lock input until block height difference
   */
  lockUntilBlockHeight(heightDiff: number): Input {
    Preconditions.checkArgument(
      typeof heightDiff === 'number',
      'heightDiff must be a number',
    )
    if (heightDiff < 0 || heightDiff >= Input.SEQUENCE_BLOCKDIFF_LIMIT) {
      throw new Error('Block height out of range')
    }
    this.sequenceNumber = heightDiff
    return this
  }

  /**
   * Get lock time as Date or number
   */
  getLockTime(): Date | number | null {
    if (this.sequenceNumber & Input.SEQUENCE_LOCKTIME_DISABLE_FLAG) {
      return null
    }

    if (this.sequenceNumber & Input.SEQUENCE_LOCKTIME_TYPE_FLAG) {
      const seconds =
        Input.SEQUENCE_LOCKTIME_GRANULARITY *
        (this.sequenceNumber & Input.SEQUENCE_LOCKTIME_MASK)
      return seconds
    } else {
      const blockHeight = this.sequenceNumber & Input.SEQUENCE_LOCKTIME_MASK
      return blockHeight
    }
  }

  /**
   * Estimate the size of this input
   */
  _estimateSize(): number {
    return this.toBufferWriter().toBuffer().length
  }

  /**
   * String representation
   */
  toString(): string {
    if (this.isNull()) {
      return 'Input(coinbase)'
    }
    return `Input(${this.prevTxId.toString('hex')}:${this.outputIndex})`
  }
}

/**
 * Multisig input class
 *
 * Handles multi-signature inputs where multiple signatures are required.
 *
 * Size Estimation:
 * - SIGNATURE_SIZE = 73 bytes (conservative estimate for ECDSA)
 * - Schnorr signatures are smaller (65 bytes) but we use conservative estimate
 * - This ensures sufficient fees are calculated
 */
export class MultisigInput extends Input {
  static readonly OPCODES_SIZE = 1 // 0
  static readonly SIGNATURE_SIZE = 73 // size (1) + DER (<=72) - conservative for ECDSA

  publicKeys!: PublicKey[]
  threshold!: number
  signatures!: (TransactionSignature | undefined)[]
  publicKeyIndex!: { [key: string]: number }

  constructor(
    input: Input,
    pubkeys?: PublicKey[],
    threshold?: number,
    signatures?: TransactionSignature[],
    opts?: { noSorting?: boolean },
  ) {
    super({
      prevTxId: input.prevTxId,
      outputIndex: input.outputIndex,
      sequenceNumber: input.sequenceNumber,
      scriptBuffer: input.script?.toBuffer(),
      output: input.output,
    })

    opts = opts || {}
    pubkeys =
      pubkeys || (input as Input & { publicKeys?: PublicKey[] }).publicKeys
    threshold = threshold || (input as Input & { threshold?: number }).threshold
    signatures =
      signatures ||
      (input as Input & { signatures?: TransactionSignature[] }).signatures

    if (opts.noSorting) {
      this.publicKeys = pubkeys!
    } else {
      this.publicKeys = pubkeys!.sort((a, b) =>
        a.toString().localeCompare(b.toString()),
      )
    }

    Preconditions.checkState(
      Script.buildMultisigOut(this.publicKeys, threshold!).equals(
        this.output!.script,
      ),
      "Provided public keys don't match to the provided output script",
    )

    this.publicKeyIndex = {}
    this.publicKeys.forEach((publicKey, index) => {
      this.publicKeyIndex[publicKey.toString()] = index
    })

    this.threshold = threshold!
    this.signatures = signatures
      ? this._deserializeSignatures(signatures)
      : new Array(this.publicKeys.length)
  }

  toObject(): object {
    const obj = super.toObject()
    return {
      ...obj,
      threshold: this.threshold,
      publicKeys: this.publicKeys.map(pk => pk.toString()),
      signatures: this._serializeSignatures(),
    }
  }

  _deserializeSignatures(
    signatures: TransactionSignature[],
  ): (TransactionSignature | undefined)[] {
    return signatures.map(signature => {
      if (!signature) {
        return undefined
      }
      return new TransactionSignature(signature)
    })
  }

  _serializeSignatures(): (object | undefined)[] {
    return this.signatures.map(signature => {
      if (!signature) {
        return undefined
      }
      return signature.toObject()
    })
  }

  getSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype?: number,
    hashData?: unknown,
    signingMethod?: string,
  ): TransactionSignature[] {
    Preconditions.checkState(
      this.output instanceof Output,
      'Output is required',
    )
    sigtype = sigtype || Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    const results: TransactionSignature[] = []
    this.publicKeys.forEach(publicKey => {
      if (publicKey.toString() === privateKey.publicKey.toString()) {
        results.push(
          new TransactionSignature({
            publicKey: privateKey.publicKey,
            prevTxId: this.prevTxId,
            outputIndex: this.outputIndex,
            inputIndex: index,
            signature: sign(
              transaction as unknown as TransactionLike,
              privateKey,
              sigtype,
              index,
              this.output!.script,
              new BN(this.output!.satoshis.toString()),
              undefined,
              signingMethod as 'ecdsa' | 'schnorr',
            ),
            sigtype: sigtype,
          }),
        )
      }
    })
    return results
  }

  addSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: string,
  ): this {
    Preconditions.checkState(
      !this.isFullySigned(),
      'All needed signatures have already been added',
    )
    Preconditions.checkArgument(
      this.publicKeyIndex[signature.publicKey.toString()] !== undefined,
      'Signature has no matching public key',
    )
    Preconditions.checkState(
      this.isValidSignature(transaction, signature, signingMethod),
      'Invalid signature',
    )

    this.signatures[this.publicKeyIndex[signature.publicKey.toString()]] =
      signature
    this._updateScript(signingMethod)
    return this
  }

  _updateScript(signingMethod?: string): this {
    // Create multisig input script manually
    const script = new Script()
    script.add(Opcode.OP_0)

    // Add signatures
    const signatures = this._createSignatures(signingMethod)
    for (const sig of signatures) {
      script.add(sig)
    }

    this.setScript(script)
    return this
  }

  /**
   * Create signature buffers for multisig input
   *
   * Converts TransactionSignature objects to their serialized form:
   * [signature bytes (DER for ECDSA or 64-byte for Schnorr)] + [1-byte sighash type]
   *
   * CRITICAL: Must call toDER() on the signature.signature property, not the
   * TransactionSignature object itself.
   */
  _createSignatures(signingMethod?: string): Buffer[] {
    return this.signatures
      .filter(signature => signature !== undefined)
      .map(signature => {
        return Buffer.concat([
          signature!.signature.toDER(signingMethod), // FIXED: Call on signature.signature
          Buffer.from([signature!.sigtype]),
        ])
      })
  }

  clearSignatures(): this {
    this.signatures = new Array(this.publicKeys.length)
    this._updateScript()
    return this
  }

  isFullySigned(): boolean {
    return this.countSignatures() === this.threshold
  }

  countMissingSignatures(): number {
    return this.threshold - this.countSignatures()
  }

  countSignatures(): number {
    return this.signatures.reduce(
      (sum, signature) => sum + (signature ? 1 : 0),
      0,
    )
  }

  publicKeysWithoutSignature(): PublicKey[] {
    return this.publicKeys.filter(publicKey => {
      return !this.signatures[this.publicKeyIndex[publicKey.toString()]]
    })
  }

  isValidSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: string,
  ): boolean {
    signature.signature.nhashtype = signature.sigtype
    return verify(
      transaction as unknown as TransactionLike,
      signature.signature,
      signature.publicKey,
      signature.inputIndex,
      this.output!.script,
      new BN(this.output!.satoshis.toString()),
      undefined,
      signingMethod as 'ecdsa' | 'schnorr',
    )
  }

  normalizeSignatures(
    transaction: Transaction,
    input: Input,
    inputIndex: number,
    signatures: Buffer[],
    publicKeys: PublicKey[],
    signingMethod?: string,
  ): TransactionSignature[] {
    return publicKeys
      .map(pubKey => {
        let signatureMatch: TransactionSignature | null = null
        signatures = signatures.filter(signatureBuffer => {
          if (signatureMatch) {
            return true
          }

          const signature = new TransactionSignature({
            signature: Signature.fromTxFormat(signatureBuffer),
            publicKey: pubKey,
            prevTxId: input.prevTxId,
            outputIndex: input.outputIndex,
            inputIndex: inputIndex,
            sigtype: Signature.SIGHASH_ALL,
          })

          signature.signature.nhashtype = signature.sigtype
          const isMatch = verify(
            transaction as unknown as TransactionLike,
            signature.signature,
            signature.publicKey,
            signature.inputIndex,
            input.output!.script,
            new BN(input.output!.satoshis.toString()),
            undefined,
            signingMethod as 'ecdsa' | 'schnorr',
          )

          if (isMatch) {
            signatureMatch = signature
            return false
          }

          return true
        })

        return signatureMatch ? signatureMatch : null
      })
      .filter(sig => sig !== null) as TransactionSignature[]
  }

  _estimateSize(): number {
    return (
      MultisigInput.OPCODES_SIZE + this.threshold * MultisigInput.SIGNATURE_SIZE
    )
  }
}

/**
 * Multisig script hash input class (P2SH)
 *
 * Handles pay-to-script-hash inputs containing multisig redeem scripts.
 *
 * Size Estimation:
 * - SIGNATURE_SIZE = 74 bytes (conservative estimate for ECDSA)
 * - Schnorr signatures are smaller (66 bytes with sighash) but we use conservative estimate
 * - This ensures sufficient fees are calculated
 */
export class MultisigScriptHashInput extends Input {
  static readonly OPCODES_SIZE = 7 // serialized size (<=3) + 0 .. N .. M OP_CHECKMULTISIG
  static readonly SIGNATURE_SIZE = 74 // size (1) + DER (<=72) + sighash (1) - conservative for ECDSA
  static readonly PUBKEY_SIZE = 34 // size (1) + DER (<=33)

  publicKeys!: PublicKey[]
  threshold!: number
  signatures!: (TransactionSignature | undefined)[]
  redeemScript!: Script
  publicKeyIndex!: { [key: string]: number }
  checkBitsField!: Uint8Array

  constructor(
    input: Input,
    pubkeys?: PublicKey[],
    threshold?: number,
    signatures?: TransactionSignature[],
    opts?: { noSorting?: boolean },
  ) {
    super({
      prevTxId: input.prevTxId,
      outputIndex: input.outputIndex,
      sequenceNumber: input.sequenceNumber,
      scriptBuffer: input.script?.toBuffer(),
      output: input.output,
    })

    opts = opts || {}
    pubkeys =
      pubkeys || (input as Input & { publicKeys?: PublicKey[] }).publicKeys
    threshold = threshold || (input as Input & { threshold?: number }).threshold
    signatures =
      signatures ||
      (input as Input & { signatures?: TransactionSignature[] }).signatures

    if (opts.noSorting) {
      this.publicKeys = pubkeys!
    } else {
      this.publicKeys = pubkeys!.sort((a, b) =>
        a.toString().localeCompare(b.toString()),
      )
    }

    this.redeemScript = Script.buildMultisigOut(
      this.publicKeys,
      threshold!,
      opts,
    )
    Preconditions.checkState(
      Script.buildScriptHashOut(this.redeemScript).equals(this.output!.script),
      "Provided public keys don't hash to the provided output",
    )

    this.publicKeyIndex = {}
    this.publicKeys.forEach((publicKey, index) => {
      this.publicKeyIndex[publicKey.toString()] = index
    })

    this.threshold = threshold!
    this.signatures = signatures
      ? this._deserializeSignatures(signatures)
      : new Array(this.publicKeys.length)
    this.checkBitsField = new Uint8Array(this.publicKeys.length)
  }

  toObject(): object {
    const obj = super.toObject()
    return {
      ...obj,
      threshold: this.threshold,
      publicKeys: this.publicKeys.map(pk => pk.toString()),
      signatures: this._serializeSignatures(),
    }
  }

  _deserializeSignatures(
    signatures: TransactionSignature[],
  ): (TransactionSignature | undefined)[] {
    return signatures.map(signature => {
      if (!signature) {
        return undefined
      }
      return new TransactionSignature(signature)
    })
  }

  _serializeSignatures(): (object | undefined)[] {
    return this.signatures.map(signature => {
      if (!signature) {
        return undefined
      }
      return signature.toObject()
    })
  }

  getSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype?: number,
    hashData?: unknown,
    signingMethod?: string,
  ): TransactionSignature[] {
    Preconditions.checkState(
      this.output instanceof Output,
      'Output is required',
    )
    sigtype = sigtype || Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    const results: TransactionSignature[] = []
    this.publicKeys.forEach(publicKey => {
      if (publicKey.toString() === privateKey.publicKey.toString()) {
        results.push(
          new TransactionSignature({
            publicKey: privateKey.publicKey,
            prevTxId: this.prevTxId,
            outputIndex: this.outputIndex,
            inputIndex: index,
            signature: sign(
              transaction as unknown as TransactionLike,
              privateKey,
              sigtype,
              index,
              this.redeemScript,
              new BN(this.output!.satoshis.toString()),
              undefined,
              signingMethod as 'ecdsa' | 'schnorr' | undefined,
            ),
            sigtype: sigtype,
          }),
        )
      }
    })
    return results
  }

  addSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: string,
  ): this {
    Preconditions.checkState(
      !this.isFullySigned(),
      'All needed signatures have already been added',
    )
    Preconditions.checkArgument(
      this.publicKeyIndex[signature.publicKey.toString()] !== undefined,
      'Signature has no matching public key',
    )
    Preconditions.checkState(
      this.isValidSignature(transaction, signature, signingMethod),
      'Invalid signature',
    )

    this.signatures[this.publicKeyIndex[signature.publicKey.toString()]] =
      signature
    this.checkBitsField[this.publicKeyIndex[signature.publicKey.toString()]] =
      signature !== undefined ? 1 : 0
    this._updateScript(signingMethod, this.checkBitsField)
    return this
  }

  _updateScript(signingMethod?: string, checkBitsField?: Uint8Array): this {
    // Create P2SH multisig input script manually
    const script = new Script()
    script.add(Opcode.OP_0)

    // Add signatures
    const signatures = this._createSignatures(signingMethod)
    for (const sig of signatures) {
      script.add(sig)
    }

    // Add redeem script
    script.add(this.redeemScript.toBuffer())

    this.setScript(script)
    return this
  }

  /**
   * Create signature buffers for P2SH multisig input
   *
   * Converts TransactionSignature objects to their serialized form:
   * [signature bytes (DER for ECDSA or 64-byte for Schnorr)] + [1-byte sighash type]
   *
   * CRITICAL: Must call toDER() on the signature.signature property, not the
   * TransactionSignature object itself.
   */
  _createSignatures(signingMethod?: string): Buffer[] {
    return this.signatures
      .filter(signature => signature !== undefined)
      .map(signature => {
        return Buffer.concat([
          signature!.signature.toDER(signingMethod), // FIXED: Call on signature.signature
          Buffer.from([signature!.sigtype]),
        ])
      })
  }

  clearSignatures(): this {
    this.signatures = new Array(this.publicKeys.length)
    this._updateScript()
    return this
  }

  isFullySigned(): boolean {
    return this.countSignatures() === this.threshold
  }

  countMissingSignatures(): number {
    return this.threshold - this.countSignatures()
  }

  countSignatures(): number {
    return this.signatures.reduce(
      (sum, signature) => sum + (signature ? 1 : 0),
      0,
    )
  }

  publicKeysWithoutSignature(): PublicKey[] {
    return this.publicKeys.filter(publicKey => {
      return !this.signatures[this.publicKeyIndex[publicKey.toString()]]
    })
  }

  isValidSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: string,
  ): boolean {
    signingMethod = signingMethod || 'ecdsa'
    signature.signature.nhashtype = signature.sigtype
    return verify(
      transaction as unknown as TransactionLike,
      signature.signature,
      signature.publicKey,
      signature.inputIndex,
      this.redeemScript,
      new BN(this.output!.satoshis.toString()),
      undefined,
      signingMethod as 'ecdsa' | 'schnorr' | undefined,
    )
  }

  normalizeSignatures(
    transaction: Transaction,
    input: Input,
    inputIndex: number,
    signatures: Buffer[],
    publicKeys: PublicKey[],
    signingMethod?: string,
  ): TransactionSignature[] {
    // Implementation would go here
    return []
  }

  _estimateSize(): number {
    return (
      MultisigScriptHashInput.OPCODES_SIZE +
      this.threshold * MultisigScriptHashInput.SIGNATURE_SIZE +
      this.publicKeys.length * MultisigScriptHashInput.PUBKEY_SIZE
    )
  }
}

/**
 * Public key input class (P2PK)
 *
 * Handles pay-to-public-key inputs.
 *
 * Size Estimation:
 * - SCRIPT_MAX_SIZE = 73 bytes (conservative estimate for ECDSA)
 * - Schnorr signatures are smaller (65 bytes) but we use conservative estimate
 */
export class PublicKeyInput extends Input {
  static readonly SCRIPT_MAX_SIZE = 73 // sigsize (1 + 72) - conservative for ECDSA, Schnorr is 65

  getSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype?: number,
    hashData?: unknown,
    signingMethod?: string,
  ): TransactionSignature[] {
    Preconditions.checkState(
      this.output instanceof Output,
      'Output is required',
    )
    sigtype = sigtype || Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
    const publicKey = privateKey.publicKey

    if (
      publicKey.toString() ===
      this.output!.script.getPublicKey().toString('hex')
    ) {
      return [
        new TransactionSignature({
          publicKey: publicKey,
          prevTxId: this.prevTxId,
          outputIndex: this.outputIndex,
          inputIndex: index,
          signature: sign(
            transaction as unknown as TransactionLike,
            privateKey,
            sigtype,
            index,
            this.output!.script,
            new BN(this.output!.satoshis.toString()),
            undefined,
            signingMethod as 'ecdsa' | 'schnorr',
          ),
          sigtype: sigtype,
        }),
      ]
    }
    return []
  }

  addSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: SignatureSigningMethod,
  ): this {
    Preconditions.checkState(
      this.isValidSignature(transaction, signature, signingMethod),
      'Signature is invalid',
    )

    // Create P2PK input script manually
    const script = new Script()
    script.add(signature.signature.toTxFormat(signingMethod))

    this.setScript(script)
    return this
  }

  clearSignatures(): this {
    this.setScript(new Script())
    return this
  }

  isFullySigned(): boolean {
    return this.script!.isPublicKeyIn()
  }

  _estimateSize(): number {
    return PublicKeyInput.SCRIPT_MAX_SIZE
  }
}

/**
 * Public key hash input class (P2PKH)
 *
 * Handles pay-to-public-key-hash inputs (most common input type).
 *
 * Size Estimation:
 * - SCRIPT_MAX_SIZE = 107 bytes (73 for sig + 34 for pubkey)
 * - Conservative estimate assumes ECDSA; Schnorr would be 99 bytes (65 + 34)
 */
export class PublicKeyHashInput extends Input {
  static readonly SCRIPT_MAX_SIZE = 73 + 34 // sigsize (1 + 72) + pubkey (1 + 33) - conservative for ECDSA

  getSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype?: number,
    hashData?: unknown,
    signingMethod?: string,
  ): TransactionSignature[] {
    Preconditions.checkState(
      this.output instanceof Output,
      'Output is required',
    )
    hashData = hashData || Hash.sha256ripemd160(privateKey.publicKey.toBuffer())
    sigtype = sigtype || Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    if (
      BufferUtil.equals(
        hashData as Buffer,
        this.output!.script.getPublicKeyHash(),
      )
    ) {
      return [
        new TransactionSignature({
          publicKey: privateKey.publicKey,
          prevTxId: this.prevTxId,
          outputIndex: this.outputIndex,
          inputIndex: index,
          signature: sign(
            transaction as unknown as TransactionLike,
            privateKey,
            sigtype,
            index,
            this.output!.script,
            new BN(this.output!.satoshis.toString()),
            undefined,
            signingMethod as 'ecdsa' | 'schnorr' | undefined,
          ),
          sigtype: sigtype,
        }),
      ]
    }
    return []
  }

  addSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: SignatureSigningMethod,
  ): this {
    Preconditions.checkState(
      this.isValidSignature(transaction, signature, signingMethod),
      'Signature is invalid',
    )

    // Create P2PKH input script manually
    const script = new Script()
    script.add(signature.signature.toTxFormat(signingMethod))
    script.add(signature.publicKey.toBuffer())

    this.setScript(script)
    return this
  }

  clearSignatures(): this {
    this.setScript(new Script())
    return this
  }

  isFullySigned(): boolean {
    return this.script!.isPublicKeyHashIn()
  }

  _estimateSize(): number {
    return PublicKeyHashInput.SCRIPT_MAX_SIZE
  }
}

/**
 * Taproot Input Implementation
 *
 * Implements Pay-To-Taproot input handling for both:
 * - Key path spending (single Schnorr signature)
 * - Script path spending (script + control block + signatures)
 *
 * Reference: lotusd/src/script/interpreter.cpp VerifyTaprootSpend()
 */

/**
 * Taproot-specific input data
 */
export interface TaprootInputData extends InputData {
  /** Internal public key (before tweaking) */
  internalPubKey?: PublicKey
  /** Merkle root of script tree (for script path spending) */
  merkleRoot?: Buffer
  /** Control block (for script path spending) */
  controlBlock?: Buffer
  /** Script to execute (for script path spending) */
  tapScript?: Script
}

/**
 * TaprootInput - Handles Pay-To-Taproot inputs
 *
 * Supports two spending paths:
 *
 * 1. Key Path (default): Spend with single Schnorr signature
 *    - Requires SIGHASH_LOTUS
 *    - Requires Schnorr signature (not ECDSA)
 *    - Input script: <65-byte schnorr signature>
 *
 * 2. Script Path: Spend by revealing and executing a script
 *    - Requires control block proving script is in commitment
 *    - Input script: <...signatures/data> <script> <control_block>
 *
 * Reference: lotusd/src/script/interpreter.cpp lines 2074-2165
 */
export class TaprootInput extends Input {
  /** Internal public key (before Taproot tweaking) */
  internalPubKey?: PublicKey

  /** Merkle root of script tree */
  merkleRoot?: Buffer

  /** Control block for script path spending */
  controlBlock?: Buffer

  /** Script to execute for script path spending */
  tapScript?: Script

  constructor(params?: TaprootInputData) {
    super(params)

    if (params) {
      this.internalPubKey = params.internalPubKey
      this.merkleRoot = params.merkleRoot
      this.controlBlock = params.controlBlock
      this.tapScript = params.tapScript
    }
  }

  /**
   * Get signatures for key path spending
   *
   * Key path spending requirements:
   * - Must use SIGHASH_LOTUS (not SIGHASH_FORKID)
   * - Must use Schnorr signatures (not ECDSA)
   * - Signature hash is computed using SIGHASH_LOTUS algorithm
   *
   * Reference: lotusd/test/functional/logos_feature_taproot_key_spend.py
   */
  getSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype?: number,
    hashData?: unknown,
    signingMethod?: string,
  ): TransactionSignature[] {
    sigtype = sigtype || TAPROOT_SIGHASH_TYPE
    signingMethod = signingMethod || 'schnorr'

    Preconditions.checkState(
      this.output instanceof Output,
      'Output is required',
    )
    Preconditions.checkState(
      this.output!.script.isPayToTaproot(),
      'Output must be Pay-To-Taproot',
    )

    // Taproot key path MUST use SIGHASH_LOTUS
    sigtype ||= TAPROOT_SIGHASH_TYPE

    // Validate that SIGHASH_LOTUS is being used
    if ((sigtype & 0x60) !== Signature.SIGHASH_LOTUS) {
      throw new Error(
        'Taproot key spend signatures must use "SIGHASH_ALL | SIGHASH_LOTUS" (0x61)',
      )
    }

    // Taproot key path MUST use Schnorr
    signingMethod ||= 'schnorr'
    if (signingMethod !== 'schnorr') {
      throw new Error('Taproot key spend signature must be Schnorr')
    }

    // Taproot key path spending ALWAYS requires tweaking the private key
    // The signature must verify against the commitment (tweaked pubkey) in the scriptPubKey
    // Reference: lotusd/src/script/interpreter.cpp VerifyTaprootSpend()
    const merkleRoot = this.merkleRoot || Buffer.alloc(32)
    const tweakedPrivateKey = tweakPrivateKey(privateKey, merkleRoot)

    // Sign with tweaked key using SIGHASH_LOTUS
    const signature = sign(
      transaction as unknown as TransactionLike,
      tweakedPrivateKey,
      sigtype,
      index,
      this.output!.script,
      new BN(this.output!.satoshis.toString()),
      undefined,
      signingMethod,
    )

    return [
      new TransactionSignature({
        publicKey: tweakedPrivateKey.publicKey,
        prevTxId: this.prevTxId,
        outputIndex: this.outputIndex,
        inputIndex: index,
        signature: signature,
        sigtype: sigtype,
      }),
    ]
  }

  /**
   * Add signature to input (key path spending)
   */
  addSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: string,
  ): this {
    Preconditions.checkState(
      this.isValidSignature(transaction, signature, signingMethod),
      'Signature is invalid',
    )

    // For key path spending, input script is just the signature
    const script = new Script()

    // BUG FIX: Ensure inner signature has nhashtype set from TransactionSignature.sigtype
    // This is a defensive measure to prevent malformed signatures if the inner signature
    // doesn't have nhashtype set (e.g., from MuSig2 aggregation)
    if (!signature.signature.nhashtype && signature.sigtype) {
      signature.signature.nhashtype = signature.sigtype
    }

    script.add(signature.signature.toTxFormat('schnorr'))

    this.setScript(script)
    return this
  }

  /**
   * Check if signature is valid
   */
  isValidSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: string,
  ): boolean {
    Preconditions.checkState(
      this.output instanceof Output,
      'Output is required',
    )

    signingMethod = signingMethod || 'schnorr'

    if (signingMethod !== 'schnorr') {
      return false
    }

    return transaction.verifySignature(
      signature.signature,
      signature.publicKey,
      signature.inputIndex,
      this.output!.script,
      new BN(this.output!.satoshis),
      undefined,
      signingMethod,
    )
  }

  /**
   * Clear signatures
   */
  clearSignatures(): this {
    this.setScript(new Script())
    return this
  }

  /**
   * Check if input is fully signed
   */
  isFullySigned(): boolean {
    // For key path: should have 1 chunk (the signature)
    // For script path: should have script + control block
    return this.script !== null && this.script.chunks.length > 0
  }

  /**
   * Estimate size of input script
   */
  _estimateSize(): number {
    // Key path: 65 bytes (64-byte Schnorr + 1-byte sighash)
    // + varint for length (1 byte)
    return 66
  }
}

/**
 * MuSig2 Taproot Input
 *
 * Specialized input type for spending Taproot outputs using MuSig2 multi-signature.
 * Coordinates multi-party signing for Taproot key path spending.
 *
 * Multi-Party Signing Flow:
 * 1. All signers agree on message (transaction sighash)
 * 2. Round 1: Exchange public nonces
 * 3. Round 2: Exchange partial signatures
 * 4. Aggregate partial signatures into final Schnorr signature
 *
 * The final signature validates against the Taproot commitment (tweaked aggregated key).
 */
export class MuSigTaprootInput extends TaprootInput {
  /** Key aggregation context from MuSig2 */
  keyAggContext?: MuSigKeyAggContext

  /** Collected public nonces from all signers */
  publicNonces?: Map<number, [Point, Point]>

  /** Aggregated nonce */
  aggregatedNonce?: MuSigAggregatedNonce

  /** Collected partial signatures from all signers */
  partialSignatures?: Map<number, BN>

  /** My signer index in the key aggregation */
  mySignerIndex?: number

  constructor(
    params?: TaprootInputData & {
      keyAggContext?: MuSigKeyAggContext
      mySignerIndex?: number
    },
  ) {
    super(params)

    if (params) {
      this.keyAggContext = params.keyAggContext
      this.mySignerIndex = params.mySignerIndex
      this.publicNonces = new Map()
      this.partialSignatures = new Map()
    }
  }

  /**
   * Initialize MuSig2 signing session
   *
   * Sets up the key aggregation context for multi-party signing.
   *
   * @param keyAggContext - Key aggregation context from musigKeyAgg()
   * @param mySignerIndex - This signer's index in the aggregation
   */
  initMuSigSession(
    keyAggContext: MuSigKeyAggContext,
    mySignerIndex: number,
  ): this {
    this.keyAggContext = keyAggContext
    this.mySignerIndex = mySignerIndex
    this.publicNonces = new Map()
    this.partialSignatures = new Map()
    return this
  }

  /**
   * Add a public nonce from a signer
   *
   * @param signerIndex - Index of the signer
   * @param publicNonce - The signer's public nonce pair [R1, R2]
   */
  addPublicNonce(signerIndex: number, publicNonce: [Point, Point]): this {
    if (!this.publicNonces) {
      this.publicNonces = new Map()
    }
    this.publicNonces.set(signerIndex, publicNonce)
    return this
  }

  /**
   * Check if all public nonces have been received
   */
  hasAllNonces(): boolean {
    if (!this.keyAggContext || !this.publicNonces) {
      return false
    }
    const numSigners = this.keyAggContext.pubkeys.length
    return this.publicNonces.size === numSigners
  }

  /**
   * Aggregate all received public nonces
   *
   * Should be called after all signers have shared their public nonces.
   */
  aggregateNonces(): this {
    if (!this.hasAllNonces()) {
      throw new Error('Not all public nonces received')
    }

    // Convert map to array in order
    const noncesArray: [Point, Point][] = []
    for (let i = 0; i < this.keyAggContext!.pubkeys.length; i++) {
      const nonce = this.publicNonces!.get(i)
      if (!nonce) {
        throw new Error(`Missing nonce for signer ${i}`)
      }
      noncesArray.push(nonce)
    }

    this.aggregatedNonce = musigNonceAgg(noncesArray)
    return this
  }

  /**
   * Add a partial signature from a signer
   *
   * @param signerIndex - Index of the signer
   * @param partialSig - The signer's partial signature
   */
  addPartialSignature(signerIndex: number, partialSig: BN): this {
    if (!this.partialSignatures) {
      this.partialSignatures = new Map()
    }
    this.partialSignatures.set(signerIndex, partialSig)
    return this
  }

  /**
   * Check if all partial signatures have been received
   */
  hasAllPartialSignatures(): boolean {
    if (!this.keyAggContext || !this.partialSignatures) {
      return false
    }
    const numSigners = this.keyAggContext.pubkeys.length
    return this.partialSignatures.size === numSigners
  }

  /**
   * Finalize MuSig2 signature
   *
   * Aggregates all partial signatures into final Schnorr signature
   * and adds it to the input script.
   *
   * @param transaction - The transaction being signed
   * @param message - Message that was signed (sighash)
   */
  finalizeMuSigSignature(transaction: Transaction, message: Buffer): this {
    if (!this.hasAllPartialSignatures()) {
      throw new Error('Not all partial signatures received')
    }

    if (!this.aggregatedNonce) {
      throw new Error('Nonces must be aggregated first')
    }

    // Get the commitment (tweaked aggregated key) from the output script
    const commitment = extractTaprootCommitment(this.output!.script)

    // Convert partial signatures map to array
    const partialSigsArray: BN[] = []
    for (let i = 0; i < this.keyAggContext!.pubkeys.length; i++) {
      const partialSig = this.partialSignatures!.get(i)
      if (!partialSig) {
        throw new Error(`Missing partial signature for signer ${i}`)
      }
      partialSigsArray.push(partialSig)
    }

    // Aggregate partial signatures
    // Note: Use commitment (tweaked key) for aggregation
    const finalSignature = musigSigAgg(
      partialSigsArray,
      this.aggregatedNonce,
      message,
      commitment, // Use commitment, not untweaked aggregated key
    )

    // Add signature to input script
    const script = new Script()
    script.add(finalSignature.toTxFormat('schnorr'))

    this.setScript(script)
    return this
  }

  /**
   * Check if input is fully signed
   */
  isFullySigned(): boolean {
    // MuSig2 input is fully signed when all partial sigs are collected
    // and the final signature is in the script
    return (
      super.isFullySigned() ||
      (this.hasAllPartialSignatures() &&
        this.script !== null &&
        this.script.chunks.length > 0)
    )
  }
}

// Add subclass constructors as input types
Input.PublicKey = PublicKeyInput
Input.PublicKeyHash = PublicKeyHashInput
Input.Multisig = MultisigInput
Input.MultisigScriptHash = MultisigScriptHashInput
Input.Taproot = TaprootInput
Input.MuSigTaproot = MuSigTaprootInput
Input.P2PKH = PublicKeyHashInput
Input.P2SH = MultisigScriptHashInput
Input.P2TR = TaprootInput

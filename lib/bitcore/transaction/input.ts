/**
 * Transaction Input re-implementation for Lotus
 *
 * Re-implemented from lotusd source as the primary reference:
 * - COutPoint: lotusd/src/primitives/transaction.h lines 22-54
 * - CTxIn: lotusd/src/primitives/transaction.h lines 61-124
 * - Sequence locks: lotusd/src/consensus/tx_verify.cpp lines 67-134
 * - IsFinalTx: lotusd/src/consensus/tx_verify.cpp lines 19-38
 *
 * The TypeScript module in input.ts is used only as a reference for
 * API compatibility with the bitcore-style modules in lib/bitcore.
 *
 * Input Types:
 * - Input (base class) - Generic input with P2PKH and P2PK support
 * - PublicKeyHashInput (P2PKH) - Standard pay-to-pubkey-hash
 * - PublicKeyInput (P2PK) - Pay-to-pubkey
 * - MultisigInput - Multi-signature output spending
 * - MultisigScriptHashInput (P2SH) - Pay-to-script-hash multisig
 * - TaprootInput (P2TR) - Pay-to-taproot (key-path and script-path)
 * - MuSig2TaprootInput - MuSig2 multi-party taproot spending
 *
 * Signature Handling:
 * - All input types support both ECDSA and Schnorr signatures
 * - Signature type is specified via signingMethod parameter
 * - Signatures are automatically detected by length when parsing
 */
import { Preconditions } from '../util/preconditions'
import { BitcoreError } from '../errors'
import { BufferWriter } from '../encoding/bufferwriter'
import { BufferReader } from '../encoding/bufferreader'
import { BufferUtil } from '../util/buffer'
import { JSUtil } from '../util/js'
import { Script } from '../script'
import { Opcode } from '../opcode'
import { BN, Hash } from '../crypto'
import { Output } from './output'
import { PrivateKey } from '../privatekey'
import { PublicKey } from '../publickey'
import { muSig2NonceAgg, muSig2SigAgg } from '../crypto/musig2'
import { Point } from '../crypto/point'
import { Signature, SignatureSigningMethod } from '../crypto/signature'
import { TransactionSignature } from './signature'
import { Transaction } from './transaction'
import { sign, verify, TransactionLike } from './sighash'
import {
  tweakPrivateKey,
  TAPROOT_SIGHASH_TYPE,
  extractTaprootCommitment,
} from '../script/taproot'
import type {
  MuSig2KeyAggContext,
  MuSig2AggregatedNonce,
} from '../crypto/musig2'
import type { Buffer } from 'buffer/'

/**
 * Null outpoint index, matching COutPoint::NULL_INDEX in lotusd.
 *
 * Reference: lotusd/src/primitives/transaction.h line 28
 */
const NULL_INDEX = 0xffffffff

/**
 * 32-byte zero hash used for null outpoint detection.
 */
const NULL_HASH = BufferUtil.alloc(32)

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/**
 * Data shape accepted by the Input constructor and factory methods.
 *
 * Mirrors the fields serialised in CTxIn (prevout + scriptSig + nSequence)
 * plus the optional Output reference needed for signing.
 */
export interface InputData {
  prevTxId?: Buffer | string
  outputIndex?: number
  sequenceNumber?: number
  script?: Script | Buffer | string
  scriptBuffer?: Buffer
  output?: Output
}

/**
 * Plain-object representation returned by Input.toObject().
 */
export interface InputObject {
  prevTxId?: Buffer | string
  outputIndex?: number
  sequenceNumber?: number
  script?: Script | Buffer | string
  scriptBuffer?: Buffer
  scriptString?: string
  output?: Output
}

// ---------------------------------------------------------------------------
// Input (base class) — corresponds to CTxIn
// ---------------------------------------------------------------------------

/**
 * Represents a transaction input.
 *
 * Maps directly to lotusd's CTxIn which contains:
 * - COutPoint prevout  (txid + output index)
 * - CScript   scriptSig
 * - uint32_t  nSequence
 *
 * Reference: lotusd/src/primitives/transaction.h lines 61-124
 */
export class Input {
  // -----------------------------------------------------------------------
  // Static constants — sourced from CTxIn in lotusd/src/primitives/transaction.h
  // -----------------------------------------------------------------------

  /**
   * Maximum value for a uint32 field (2^32 - 1).
   */
  static readonly MAXINT = 0xffffffff

  /**
   * Default sequence number — disables nLockTime when set on every input.
   *
   * Reference: CTxIn::SEQUENCE_FINAL (transaction.h line 71)
   */
  static readonly DEFAULT_SEQNUMBER = 0xffffffff

  /**
   * Sequence number used when nLockTime is active.
   * One less than SEQUENCE_FINAL so the tx is not considered final.
   */
  static readonly DEFAULT_LOCKTIME_SEQNUMBER = 0xfffffffe

  /**
   * Sequence number signalling opt-in Replace-By-Fee (BIP 125).
   */
  static readonly DEFAULT_RBF_SEQNUMBER = 0xfffffffd

  /**
   * If this flag is set, CTxIn::nSequence is NOT interpreted as a
   * relative lock-time.
   *
   * Reference: CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG (transaction.h line 78)
   */
  static readonly SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31

  /**
   * If CTxIn::nSequence encodes a relative lock-time and this flag is
   * set, the relative lock-time has units of 512 seconds; otherwise it
   * specifies blocks with a granularity of 1.
   *
   * Reference: CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG (transaction.h line 85)
   */
  static readonly SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22

  /**
   * Mask applied to extract the lock-time value from the sequence field.
   *
   * Reference: CTxIn::SEQUENCE_LOCKTIME_MASK (transaction.h line 91)
   */
  static readonly SEQUENCE_LOCKTIME_MASK = 0x0000ffff

  /**
   * Granularity exponent for time-based relative lock-times.
   *
   * In lotusd this is stored as the shift amount (9), meaning the
   * multiplier is 2^9 = 512 seconds. We expose the multiplier directly
   * for convenience in the TypeScript API.
   *
   * Reference: CTxIn::SEQUENCE_LOCKTIME_GRANULARITY (transaction.h line 101)
   */
  static readonly SEQUENCE_LOCKTIME_GRANULARITY = 512

  /**
   * Maximum block-height difference encodable in the sequence field.
   */
  static readonly SEQUENCE_BLOCKDIFF_LIMIT = 0xffff

  // -----------------------------------------------------------------------
  // Instance properties — mirror CTxIn fields
  // -----------------------------------------------------------------------

  /**
   * Previous transaction ID as a 32-byte Buffer in internal
   * (little-endian) byte order, matching lotusd's COutPoint::txid.
   *
   * Reference: lotusd/src/primitives/transaction.h line 24
   */
  prevTxId!: Buffer

  /**
   * Index into the previous transaction's vout.
   *
   * Reference: lotusd/src/primitives/transaction.h line 25
   */
  outputIndex!: number

  /**
   * Sequence number.
   *
   * Reference: lotusd/src/primitives/transaction.h line 65
   */
  sequenceNumber!: number

  /**
   * The raw scriptSig bytes.
   */
  private _scriptBuffer!: Buffer

  /**
   * Lazily-parsed Script object.
   */
  private _script?: Script

  /**
   * The previous output being spent (optional; required for signing).
   */
  output?: Output

  // -----------------------------------------------------------------------
  // Construction
  // -----------------------------------------------------------------------

  constructor(params?: InputData) {
    if (params) {
      this._fromObject(params)
    }
  }

  /**
   * Factory — allows calling Input.create() instead of new Input().
   */
  static create(params?: InputData): Input {
    return new Input(params)
  }

  /**
   * Construct from a plain object.
   */
  static fromObject(obj: InputData): Input {
    Preconditions.checkArgument(
      typeof obj === 'object' && obj !== null,
      'Must provide an object',
    )
    const input = new Input()
    return input._fromObject(obj)
  }

  /**
   * Populate this instance from an InputData object.
   *
   * Validates prevTxId, sets defaults matching CTxIn's default
   * constructor (nSequence = SEQUENCE_FINAL).
   *
   * Reference: CTxIn default constructor (transaction.h line 103)
   */
  private _fromObject(params: InputData): Input {
    let prevTxId: Buffer
    if (typeof params.prevTxId === 'string' && JSUtil.isHexa(params.prevTxId)) {
      prevTxId = BufferUtil.from(params.prevTxId, 'hex')
    } else if (BufferUtil.isBuffer(params.prevTxId)) {
      prevTxId = params.prevTxId
    } else {
      prevTxId = BufferUtil.alloc(0)
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

  // -----------------------------------------------------------------------
  // Script accessors
  // -----------------------------------------------------------------------

  /**
   * Get the parsed Script for this input's scriptSig.
   * Returns null for coinbase (null) inputs.
   */
  get script(): Script | null {
    if (this.isNull()) {
      return null
    }
    if (!this._script) {
      this._script = new Script(this._scriptBuffer)
      ;(this._script as Script & { _isInput?: boolean })._isInput = true
    }
    return this._script
  }

  /**
   * Get the raw scriptSig bytes.
   */
  get scriptBuffer(): Buffer {
    return this._scriptBuffer
  }

  /**
   * Set the scriptSig from a Script, Buffer, or hex/utf8 string.
   */
  setScript(script: Script | Buffer | string | null): Input {
    this._script = undefined
    if (script instanceof Script) {
      this._script = script
      this._scriptBuffer = script.toBuffer()
    } else if (script === null) {
      this._script = Script.empty()
      this._scriptBuffer = this._script.toBuffer()
    } else if (BufferUtil.isBuffer(script)) {
      this._scriptBuffer = script
      this._script = Script.fromBuffer(script)
    } else if (typeof script === 'string') {
      if (JSUtil.isHexa(script)) {
        this._scriptBuffer = BufferUtil.from(script, 'hex')
        this._script = Script.fromBuffer(this._scriptBuffer)
      } else {
        this._scriptBuffer = BufferUtil.from(script, 'utf8')
        this._script = Script.fromBuffer(this._scriptBuffer)
      }
    } else {
      throw new TypeError('Invalid script type')
    }
    return this
  }

  // -----------------------------------------------------------------------
  // Outpoint helpers — correspond to COutPoint methods
  // -----------------------------------------------------------------------

  /**
   * Check if this input references a null outpoint.
   *
   * A null outpoint has an all-zero txid and index == NULL_INDEX.
   *
   * Reference: COutPoint::IsNull() (transaction.h line 35)
   */
  isNull(): boolean {
    return this.prevTxId === NULL_HASH && this.outputIndex === NULL_INDEX
  }

  // -----------------------------------------------------------------------
  // Sequence / finality helpers — derived from lotusd consensus logic
  // -----------------------------------------------------------------------

  /**
   * An input is considered "final" when its sequence number is not
   * SEQUENCE_FINAL (0xffffffff). This mirrors the per-input check in
   * IsFinalTx (tx_verify.cpp line 33).
   *
   * Note: the name `isFinal` is kept for bitcore API compatibility,
   * but the semantics match lotusd: returns true when the input
   * signals that nLockTime should be enforced (i.e. sequence != final).
   *
   * Reference: lotusd/src/consensus/tx_verify.cpp lines 32-34
   */
  isFinal(): boolean {
    return this.sequenceNumber !== Input.DEFAULT_SEQNUMBER
  }

  /**
   * Whether this input has a non-default sequence number.
   */
  hasSequence(): boolean {
    return this.sequenceNumber !== Input.DEFAULT_SEQNUMBER
  }

  /**
   * Whether this input encodes a BIP 68 relative lock-time.
   *
   * A relative lock-time is active when:
   * 1. The disable flag (bit 31) is NOT set, AND
   * 2. The sequence is not the default (SEQUENCE_FINAL)
   *
   * Reference: lotusd/src/consensus/tx_verify.cpp lines 98-102
   */
  hasRelativeLockTime(): boolean {
    return (
      (this.sequenceNumber & Input.SEQUENCE_LOCKTIME_DISABLE_FLAG) !==
        Input.SEQUENCE_LOCKTIME_DISABLE_FLAG &&
      this.sequenceNumber !== Input.DEFAULT_SEQNUMBER
    )
  }

  /**
   * Extract the raw relative lock-time value from the sequence field.
   *
   * Reference: lotusd/src/consensus/tx_verify.cpp lines 123-130
   */
  getRelativeLockTime(): bigint {
    if (!this.hasRelativeLockTime()) {
      return BigInt(0)
    }
    return BigInt(this.sequenceNumber & Input.SEQUENCE_LOCKTIME_MASK)
  }

  /**
   * Whether the relative lock-time is time-based (512-second units)
   * rather than block-based.
   *
   * Reference: lotusd/src/consensus/tx_verify.cpp line 106
   */
  isRelativeLockTimeInBlocks(): boolean {
    if (!this.hasRelativeLockTime()) {
      return false
    }
    return (this.sequenceNumber & Input.SEQUENCE_LOCKTIME_TYPE_FLAG) !== 0
  }

  /**
   * Get the relative lock-time in blocks (0 if time-based or disabled).
   */
  getRelativeLockTimeInBlocks(): number {
    if (!this.isRelativeLockTimeInBlocks()) {
      return 0
    }
    return Number(this.getRelativeLockTime())
  }

  /**
   * Get the relative lock-time in seconds (0 if block-based or disabled).
   *
   * The raw value is left-shifted by 9 (multiplied by 512) to convert
   * to seconds, matching lotusd's SEQUENCE_LOCKTIME_GRANULARITY.
   *
   * Reference: lotusd/src/consensus/tx_verify.cpp lines 120-125
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

  // -----------------------------------------------------------------------
  // Serialisation — matches CTxIn serialisation format
  // -----------------------------------------------------------------------

  /**
   * Convert to a plain-object representation.
   */
  toObject(): InputObject {
    const obj: InputObject = {
      prevTxId: BufferUtil.from(this.prevTxId).toString('hex'),
      outputIndex: this.outputIndex,
      sequenceNumber: this.sequenceNumber,
      script: this._scriptBuffer.toString('hex'),
    }

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
   * Convert to JSON (alias for toObject)
   */
  toJSON(): InputObject {
    return this.toObject()
  }

  /**
   * Deserialise from a BufferReader.
   *
   * Wire format (matching CTxIn SERIALIZE_METHODS):
   *   prevout.txid  (32 bytes, internal order)
   *   prevout.n     (uint32_t LE)
   *   scriptSig     (var-length)
   *   nSequence     (uint32_t LE)
   *
   * Reference: lotusd/src/primitives/transaction.h lines 112-114
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
   * Serialise to a Buffer.
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
   * Write to a BufferWriter.
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
   * Byte size of this input when serialised.
   */
  getSize(): number {
    return (
      32 +
      4 +
      BufferWriter.varintBufNum(this._scriptBuffer.length).length +
      this._scriptBuffer.length +
      4
    )
  }

  /**
   * Basic validity check.
   *
   * Coinbase inputs are always valid. Regular inputs must have a 32-byte
   * prevTxId, a valid outputIndex, and a non-empty scriptSig.
   */
  isValid(): boolean {
    if (this.isNull()) {
      return true
    }
    return (
      this.prevTxId.length === 32 &&
      this.outputIndex >= 0 &&
      this.outputIndex <= NULL_INDEX &&
      this._scriptBuffer.length > 0
    )
  }

  /**
   * Create a deep copy of this input.
   */
  clone(): Input {
    return new Input({
      prevTxId: BufferUtil.from(this.prevTxId),
      outputIndex: this.outputIndex,
      sequenceNumber: this.sequenceNumber,
      scriptBuffer: BufferUtil.from(this._scriptBuffer),
      output: this.output,
    })
  }

  /**
   * Get signatures for the provided PrivateKey.
   *
   * The base class handles P2PKH and P2PK outputs. Subclasses override
   * for their specific script types.
   *
   * @param transaction - The transaction being signed
   * @param privateKey - Key to sign with
   * @param index - Input index within the transaction
   * @param sigtype - Sighash type
   * @param hashData - Pre-computed pubkey hash (optimisation)
   * @param signingMethod - 'ecdsa' or 'schnorr'
   * @returns Array of TransactionSignature objects
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
    } else if (this.output!.script.isPublicKeyOut()) {
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
   * Check if this input is fully signed.
   * @abstract — subclasses must override.
   */
  isFullySigned(): boolean {
    throw new Error('Input#isFullySigned')
  }

  /**
   * Add a signature to this input.
   *
   * The base class handles P2PKH and P2PK script construction.
   * Subclasses override for their specific script types.
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

    if (this.output?.script.isPublicKeyHashOut()) {
      const script = new Script()
      script.add(signature.signature.toTxFormat(signingMethod))
      script.add(signature.publicKey.toBuffer())
      this.setScript(script)
    } else if (this.output?.script.isPublicKeyOut()) {
      const script = new Script()
      script.add(signature.signature.toTxFormat(signingMethod))
      this.setScript(script)
    } else {
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
   * Clear all signatures from this input.
   * @abstract — subclasses must override.
   */
  clearSignatures(): this {
    throw new Error('Input#clearSignatures')
  }

  /**
   * Validate a signature against this input.
   */
  isValidSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: string,
  ): boolean {
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

  // -----------------------------------------------------------------------
  // Relative lock-time setters
  // -----------------------------------------------------------------------

  /**
   * Lock this input for a specified number of seconds.
   *
   * Sets the sequence number to encode a time-based relative lock-time
   * per BIP 68. The value is divided by the granularity (512 seconds)
   * and the TYPE_FLAG is set.
   *
   * Reference: lotusd/src/consensus/tx_verify.cpp lines 106, 120-125
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
   * Lock this input until a specified block-height difference.
   *
   * Sets the sequence number to encode a block-based relative lock-time
   * per BIP 68.
   *
   * Reference: lotusd/src/consensus/tx_verify.cpp lines 126-131
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
   * Get the lock-time value encoded in the sequence number.
   *
   * Returns null if relative lock-time is disabled, otherwise returns
   * the value in seconds (time-based) or blocks (block-based).
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

  // -----------------------------------------------------------------------
  // Size estimation
  // -----------------------------------------------------------------------

  /**
   * Estimate the serialised size of this input's scriptSig.
   * Subclasses override with type-specific estimates.
   */
  _estimateSize(): number {
    return this.toBufferWriter().toBuffer().length
  }

  /**
   * Human-readable string, matching CTxIn::ToString() format.
   *
   * Reference: lotusd/src/primitives/transaction.cpp lines 19-33
   */
  toString(): string {
    if (this.isNull()) {
      return 'Input(coinbase)'
    }
    return `Input(${this.prevTxId.toString('hex')}:${this.outputIndex})`
  }
}

/**
 * Multi-signature input.
 *
 * Handles bare multisig outputs (OP_CHECKMULTISIG without P2SH wrapper).
 *
 * Size Estimation:
 * - SIGNATURE_SIZE = 73 bytes (conservative ECDSA estimate)
 * - Schnorr signatures are 65 bytes but we use the conservative value
 */
export class MultisigInput extends Input {
  static readonly OPCODES_SIZE = 1
  static readonly SIGNATURE_SIZE = 73

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
    const script = new Script()
    script.add(Opcode.OP_0)

    const signatures = this._createSignatures(signingMethod)
    for (const sig of signatures) {
      script.add(sig)
    }

    this.setScript(script)
    return this
  }

  /**
   * Create serialised signature buffers.
   *
   * Each signature is: [DER/Schnorr bytes] + [1-byte sighash type]
   */
  _createSignatures(signingMethod?: string): Buffer[] {
    return this.signatures
      .filter(signature => signature !== undefined)
      .map(signature => {
        return BufferUtil.concat([
          signature.signature.toDER(signingMethod),
          BufferUtil.from([signature.sigtype]),
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

// ---------------------------------------------------------------------------
// MultisigScriptHashInput (P2SH)
// ---------------------------------------------------------------------------

/**
 * Pay-to-script-hash multisig input.
 *
 * Size Estimation:
 * - SIGNATURE_SIZE = 74 bytes (conservative ECDSA estimate)
 * - PUBKEY_SIZE = 34 bytes
 */
export class MultisigScriptHashInput extends Input {
  static readonly OPCODES_SIZE = 7
  static readonly SIGNATURE_SIZE = 74
  static readonly PUBKEY_SIZE = 34

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
    const script = new Script()
    script.add(Opcode.OP_0)

    const signatures = this._createSignatures(signingMethod)
    for (const sig of signatures) {
      script.add(sig)
    }

    script.add(this.redeemScript.toBuffer())

    this.setScript(script)
    return this
  }

  /**
   * Create serialised signature buffers for P2SH multisig.
   */
  _createSignatures(signingMethod?: string): Buffer[] {
    return this.signatures
      .filter(signature => signature !== undefined)
      .map(signature => {
        return BufferUtil.concat([
          signature!.signature.toDER(signingMethod),
          BufferUtil.from([signature!.sigtype]),
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

// ---------------------------------------------------------------------------
// PublicKeyInput (P2PK)
// ---------------------------------------------------------------------------

/**
 * Pay-to-public-key input.
 *
 * Size Estimation:
 * - SCRIPT_MAX_SIZE = 73 bytes (conservative ECDSA; Schnorr is 65)
 */
export class PublicKeyInput extends Input {
  static readonly SCRIPT_MAX_SIZE = 73

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

// ---------------------------------------------------------------------------
// PublicKeyHashInput (P2PKH)
// ---------------------------------------------------------------------------

/**
 * Pay-to-public-key-hash input (most common input type).
 *
 * Size Estimation:
 * - SCRIPT_MAX_SIZE = 107 bytes (73 sig + 34 pubkey)
 * - Conservative; Schnorr would be 99 bytes (65 + 34)
 */
export class PublicKeyHashInput extends Input {
  static readonly SCRIPT_MAX_SIZE = 73 + 34

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

// ---------------------------------------------------------------------------
// TaprootInput (P2TR)
// ---------------------------------------------------------------------------

/**
 * Taproot-specific input data.
 */
export interface TaprootInputData extends InputData {
  /** Internal public key (before tweaking) */
  internalPubKey: PublicKey
  /** Merkle root of script tree (for script path spending) */
  merkleRoot: Buffer
  /** Control block (for script path spending) */
  controlBlock?: Buffer
  /** Script to execute (for script path spending) */
  tapScript?: Script
}

/**
 * Pay-To-Taproot input.
 *
 * Supports two spending paths:
 *
 * 1. Key Path (default): Spend with single Schnorr signature
 *    - Requires SIGHASH_LOTUS (0x60)
 *    - Input script: <65-byte schnorr signature>
 *
 * 2. Script Path: Spend by revealing and executing a script
 *    - Requires control block proving script is in commitment
 *    - Input script: <...signatures/data> <script> <control_block>
 *
 * Reference: lotusd/src/script/interpreter.cpp VerifyTaprootSpend()
 */
export class TaprootInput extends Input {
  /** Internal public key (before Taproot tweaking) */
  internalPubKey: PublicKey

  /** Merkle root of script tree */
  merkleRoot?: Buffer

  /** Control block for script path spending */
  controlBlock?: Buffer

  /** Script to execute for script path spending */
  tapScript?: Script

  constructor(params: TaprootInputData) {
    super(params)

    this.internalPubKey = params.internalPubKey
    this.merkleRoot = params.merkleRoot
    this.controlBlock = params.controlBlock
    this.tapScript = params.tapScript
  }

  /**
   * Check if this input has a script tree (script-path spending).
   *
   * A script tree exists if merkleRoot is defined, has length 32,
   * and is non-zero.
   */
  hasScriptTree(): boolean {
    if (!this.merkleRoot || this.merkleRoot.length !== 32) {
      return false
    }

    // 32-byte buffer of 0's is for key-path only
    return !this.merkleRoot.equals(BufferUtil.alloc(32))
  }

  /**
   * Check if this input is key-path only (no script tree).
   */
  isKeyPathOnly(): boolean {
    return !this.hasScriptTree()
  }

  /**
   * Get signatures for Taproot spending.
   *
   * Automatically detects spending path:
   * - Key-path: SIGHASH_LOTUS (0x60) REQUIRED, Schnorr only
   * - Script-path: Any valid sighash type
   *
   * Reference: lotusd/src/script/interpreter.cpp lines 2074-2165
   */
  getSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype?: number,
    hashData?: unknown,
    signingMethod?: 'ecdsa' | 'schnorr',
  ): TransactionSignature[] {
    Preconditions.checkState(
      this.output instanceof Output,
      'Output is required',
    )
    Preconditions.checkState(
      this.output!.script.isTaprootOut(),
      'Output must be Pay-To-Taproot',
    )

    const isKeyPath = this.isKeyPathOnly()

    if (isKeyPath) {
      sigtype = sigtype || TAPROOT_SIGHASH_TYPE
      if ((sigtype & 0x60) !== Signature.SIGHASH_LOTUS) {
        throw new Error(
          'Taproot key spend signatures must use "SIGHASH_ALL | SIGHASH_LOTUS" (0x61)',
        )
      }
      signingMethod = signingMethod || 'schnorr'
      if (signingMethod !== 'schnorr') {
        throw new Error('Taproot key spend signature must be Schnorr')
      }

      return this._getKeyPathSignatures(
        transaction,
        privateKey,
        index,
        sigtype,
        signingMethod,
      )
    } else {
      sigtype = sigtype || Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
      signingMethod = signingMethod || 'schnorr'

      return this._getScriptPathSignatures(
        transaction,
        privateKey,
        index,
        sigtype,
        signingMethod,
      )
    }
  }

  /**
   * Get signatures for key-path spending.
   *
   * The private key is tweaked with the merkle root before signing,
   * so the signature verifies against the commitment in scriptPubKey.
   *
   * Reference: lotusd/src/script/interpreter.cpp VerifyTaprootSpend()
   */
  private _getKeyPathSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype: number,
    signingMethod: 'ecdsa' | 'schnorr',
  ): TransactionSignature[] {
    const merkleRoot = this.merkleRoot || BufferUtil.alloc(32)
    const tweakedPrivateKey = tweakPrivateKey(privateKey, merkleRoot)

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
   * Get signatures for script-path spending.
   */
  private _getScriptPathSignatures(
    transaction: Transaction,
    privateKey: PrivateKey,
    index: number,
    sigtype: number,
    signingMethod: 'ecdsa' | 'schnorr',
  ): TransactionSignature[] {
    const signature = sign(
      transaction as unknown as TransactionLike,
      privateKey,
      sigtype,
      index,
      this.tapScript || this.output!.script,
      new BN(this.output!.satoshis.toString()),
      undefined,
      signingMethod,
    )

    return [
      new TransactionSignature({
        publicKey: privateKey.publicKey,
        prevTxId: this.prevTxId,
        outputIndex: this.outputIndex,
        inputIndex: index,
        signature: signature,
        sigtype: sigtype,
      }),
    ]
  }

  /**
   * Add signature to input (key-path or script-path).
   */
  addSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: 'ecdsa' | 'schnorr',
  ): this {
    Preconditions.checkState(
      this.isValidSignature(transaction, signature, signingMethod),
      'Signature is invalid',
    )

    const script = new Script()

    if (this.isKeyPathOnly()) {
      script.add(signature.signature.toTxFormat('schnorr'))
    } else {
      script.add(signature.signature.toTxFormat('schnorr'))

      if (this.tapScript) {
        script.add(this.tapScript.toBuffer())
      }

      if (this.controlBlock) {
        script.add(this.controlBlock)
      } else {
        throw new Error(
          'Script-path spending requires control block. ' +
            'Use buildScriptPathTaproot() to create output with script tree.',
        )
      }
    }

    this.setScript(script)
    return this
  }

  /**
   * Validate a signature for this Taproot input.
   */
  isValidSignature(
    transaction: Transaction,
    signature: TransactionSignature,
    signingMethod?: 'ecdsa' | 'schnorr',
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

  clearSignatures(): this {
    this.setScript(new Script())
    return this
  }

  isFullySigned(): boolean {
    return this.script !== null && this.script.chunks.length > 0
  }

  /**
   * Estimate size: key path = 65 bytes (64 Schnorr + 1 sighash) + 1 varint.
   */
  _estimateSize(): number {
    return 66
  }
}

// ---------------------------------------------------------------------------
// MuSig2TaprootInput
// ---------------------------------------------------------------------------

/**
 * MuSig2 Taproot Input.
 *
 * Specialised input type for spending Taproot outputs using MuSig2
 * multi-signature. Coordinates multi-party signing for Taproot key
 * path spending.
 *
 * Multi-Party Signing Flow:
 * 1. All signers agree on message (transaction sighash)
 * 2. Round 1: Exchange public nonces
 * 3. Round 2: Exchange partial signatures
 * 4. Aggregate partial signatures into final Schnorr signature
 */
export class MuSig2TaprootInput extends TaprootInput {
  /** Key aggregation context from MuSig2 */
  keyAggContext?: MuSig2KeyAggContext

  /** Collected public nonces from all signers */
  publicNonces?: Map<number, [Point, Point]>

  /** Aggregated nonce */
  aggregatedNonce?: MuSig2AggregatedNonce

  /** Collected partial signatures from all signers */
  partialSignatures?: Map<number, BN>

  /** This signer's index in the key aggregation */
  mySignerIndex?: number

  constructor(
    params: TaprootInputData & {
      keyAggContext?: MuSig2KeyAggContext
      mySignerIndex?: number
    },
  ) {
    super(params)

    this.keyAggContext = params.keyAggContext
    this.mySignerIndex = params.mySignerIndex
    this.publicNonces = new Map()
    this.partialSignatures = new Map()
  }

  /**
   * Initialise MuSig2 signing session.
   *
   * @param keyAggContext - Key aggregation context from musigKeyAgg()
   * @param mySignerIndex - This signer's index in the aggregation
   */
  initMuSig2Session(
    keyAggContext: MuSig2KeyAggContext,
    mySignerIndex: number,
  ): this {
    this.keyAggContext = keyAggContext
    this.mySignerIndex = mySignerIndex
    this.publicNonces = new Map()
    this.partialSignatures = new Map()
    return this
  }

  /**
   * Add a public nonce from a signer.
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
   * Check if all public nonces have been received.
   */
  hasAllNonces(): boolean {
    if (!this.keyAggContext || !this.publicNonces) {
      return false
    }
    const numSigners = this.keyAggContext.pubkeys.length
    return this.publicNonces.size === numSigners
  }

  /**
   * Aggregate all received public nonces.
   */
  aggregateNonces(): this {
    if (!this.hasAllNonces()) {
      throw new Error('Not all public nonces received')
    }

    const noncesArray: [Point, Point][] = []
    for (let i = 0; i < this.keyAggContext!.pubkeys.length; i++) {
      const nonce = this.publicNonces!.get(i)
      if (!nonce) {
        throw new Error(`Missing nonce for signer ${i}`)
      }
      noncesArray.push(nonce)
    }

    this.aggregatedNonce = muSig2NonceAgg(noncesArray)
    return this
  }

  /**
   * Add a partial signature from a signer.
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
   * Check if all partial signatures have been received.
   */
  hasAllPartialSignatures(): boolean {
    if (!this.keyAggContext || !this.partialSignatures) {
      return false
    }
    const numSigners = this.keyAggContext.pubkeys.length
    return this.partialSignatures.size === numSigners
  }

  /**
   * Finalise MuSig2 signature.
   *
   * Aggregates all partial signatures into a final Schnorr signature
   * and adds it to the input script.
   *
   * @param transaction - The transaction being signed
   * @param message - Message that was signed (sighash)
   */
  finalizeMuSig2Signature(transaction: Transaction, message: Buffer): this {
    if (!this.hasAllPartialSignatures()) {
      throw new Error('Not all partial signatures received')
    }

    if (!this.aggregatedNonce) {
      throw new Error('Nonces must be aggregated first')
    }

    const commitment = extractTaprootCommitment(this.output!.script)

    const partialSigsArray: BN[] = []
    for (let i = 0; i < this.keyAggContext!.pubkeys.length; i++) {
      const partialSig = this.partialSignatures!.get(i)
      if (!partialSig) {
        throw new Error(`Missing partial signature for signer ${i}`)
      }
      partialSigsArray.push(partialSig)
    }

    const finalSignature = muSig2SigAgg(
      partialSigsArray,
      this.aggregatedNonce,
      message,
      commitment,
    )

    const script = new Script()
    script.add(finalSignature.toTxFormat('schnorr'))

    this.setScript(script)
    return this
  }

  isFullySigned(): boolean {
    return (
      super.isFullySigned() ||
      (this.hasAllPartialSignatures() &&
        this.script !== null &&
        this.script.chunks.length > 0)
    )
  }
}

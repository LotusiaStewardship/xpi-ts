/**
 * Transaction implementation for Lotus
 *
 * Signature Handling:
 * Lotus supports both ECDSA and Schnorr signatures, automatically detected by length:
 * - 64 bytes = Schnorr signature
 * - Other lengths (typically 70-72 bytes) = ECDSA signature (DER-encoded)
 *
 * The signing method can be specified when calling transaction.sign():
 * - signingMethod: 'ecdsa' (default) or 'schnorr'
 *
 * Reference: lotusd/src/script/interpreter.cpp lines 1900-1908
 */

import { Preconditions } from '../util/preconditions.js'
import { JSUtil } from '../util/js.js'
import { BufferReader } from '../encoding/bufferreader.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { Hash } from '../crypto/hash.js'
import { Signature, SignatureSigningMethod } from '../crypto/signature.js'
import { verify, TransactionLike } from './sighash.js'
import { BitcoreError } from '../errors.js'
import { Address } from '../address.js'
import { UnspentOutput, UnspentOutputData } from './unspentoutput.js'
import {
  Input,
  InputObject,
  MultisigInput,
  MultisigScriptHashInput,
  PublicKeyInput,
  PublicKeyHashInput,
  TaprootInput,
  MuSigTaprootInput,
} from './input.js'
import { Output, OutputObject } from './output.js'
import { Script } from '../script.js'
import { PrivateKey } from '../privatekey.js'
import { PublicKey } from '../publickey.js'
import { BN } from '../crypto/bn.js'
import { TransactionSignature } from './signature.js'
import type { Point } from '../crypto/point.js'
import { sighash as computeSighash } from './sighash.js'
import { Interpreter } from '../script/interpreter.js'

export interface TransactionData {
  version?: number
  inputs?: InputObject[]
  outputs?: OutputObject[]
  nLockTime?: number
  changeScript?: Script | string
  changeAsm?: string
  changeIndex?: number
  fee?: number
}

export interface TransactionObject {
  txid: string
  hash: string
  version: number
  inputs: InputObject[]
  outputs: OutputObject[]
  nLockTime: number
  changeScript?: string
  changeAsm?: string
  changeIndex?: number
  fee?: number
}

// Constants
const CURRENT_VERSION = 2
const DEFAULT_NLOCKTIME = 0
const MAX_BLOCK_SIZE = 32_000_000

// Minimum amount for an output for it not to be considered a dust output
const DUST_AMOUNT = 546

// Margin of error to allow fees in the vecinity of the expected value but doesn't allow a big difference
const FEE_SECURITY_MARGIN = 150

// MAX_MONEY = 2,100,000,000,000,000 satoshis (2,100,000,000 XPI)
// see lotusd/src/amount.h
const MAX_MONEY = 2_100_000_000_000_000

// nlocktime limit to be considered block height rather than a timestamp
const NLOCKTIME_BLOCKHEIGHT_LIMIT = 5e8

// Max value for an unsigned 32 bit value
const NLOCKTIME_MAX_VALUE = 4294967295

// Value used for fee estimation (satoshis per kilobyte)
const FEE_PER_KB = 1_000

// Safe upper bound for change address script size in bytes
const CHANGE_OUTPUT_MAX_SIZE = 20 + 4 + 34 + 4
const MAXIMUM_EXTRA_SIZE = 4 + 9 + 9 + 4

const NULL_HASH = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
)

/**
 * Represents a transaction, a set of inputs and outputs to change ownership of tokens
 */
export class Transaction {
  // Static constants
  static readonly DUST_AMOUNT = DUST_AMOUNT
  static readonly FEE_SECURITY_MARGIN = FEE_SECURITY_MARGIN
  //static readonly MAX_MONEY = MAX_MONEY
  static readonly NLOCKTIME_BLOCKHEIGHT_LIMIT = NLOCKTIME_BLOCKHEIGHT_LIMIT
  static readonly NLOCKTIME_MAX_VALUE = NLOCKTIME_MAX_VALUE
  static readonly FEE_PER_KB = FEE_PER_KB
  static readonly CHANGE_OUTPUT_MAX_SIZE = CHANGE_OUTPUT_MAX_SIZE
  static readonly MAXIMUM_EXTRA_SIZE = MAXIMUM_EXTRA_SIZE
  static readonly NULL_HASH = NULL_HASH

  // Instance subclasses
  /* static Output: typeof Output
  static Input: typeof Input */

  // Instance properties
  inputs: Input[] = []
  outputs: Output[] = []
  _version: number = CURRENT_VERSION
  nLockTime: number = DEFAULT_NLOCKTIME
  private _inputAmount?: number
  private _outputAmount?: number
  private _changeScript?: Script
  private _changeIndex?: number
  private _fee?: number
  private _feePerKb?: number
  private _feePerByte?: number
  private _hash?: string
  private _txid?: string

  /**
   * Get spent outputs for all inputs (required for SIGHASH_LOTUS)
   *
   * Returns an array of Output objects being spent by each input.
   * This is required for SIGHASH_LOTUS signature algorithm.
   *
   * @returns Array of outputs, or undefined if any input is missing output info
   */
  get spentOutputs(): Output[] | undefined {
    // Check if all inputs have output information
    if (!this.inputs.every(input => input.output)) {
      return undefined
    }
    return this.inputs.map(input => input.output!)
  }

  constructor(serialized?: TransactionData | Transaction | Buffer | string) {
    if (serialized instanceof Transaction) {
      return Transaction.shallowCopy(serialized)
    } else if (typeof serialized === 'string' && JSUtil.isHexa(serialized)) {
      this.fromString(serialized)
    } else if (Buffer.isBuffer(serialized)) {
      this.fromBuffer(serialized)
    } else if (serialized && typeof serialized === 'object') {
      this.fromObject(serialized)
    } else {
      this._newTransaction()
    }
  }

  // Factory function to allow calling Transaction() without 'new'
  static create(
    serialized?: TransactionData | Transaction | Buffer | string,
  ): Transaction {
    return new Transaction(serialized)
  }

  /**
   * Create a 'shallow' copy of the transaction, by serializing and deserializing
   * it dropping any additional information that inputs and outputs may have hold
   */
  static shallowCopy(transaction: Transaction): Transaction {
    const copy = new Transaction(transaction.toBuffer())
    return copy
  }

  /**
   * Create from buffer
   */
  static fromBuffer(buffer: Buffer): Transaction {
    return new Transaction(buffer)
  }

  /**
   * Create from buffer reader
   */
  static fromBufferReader(reader: BufferReader): Transaction {
    return new Transaction().fromBufferReader(reader)
  }

  /**
   * Create from object
   */
  static fromObject(arg: TransactionData | Transaction): Transaction {
    return new Transaction(arg)
  }

  /**
   * Create from string
   */
  static fromString(str: string): Transaction {
    return new Transaction(str)
  }

  /**
   * Get the transaction hash (little endian)
   */
  get hash(): string {
    if (!this._hash) {
      const hashBuffer = this._getHash()
      const reader = new BufferReader(hashBuffer)
      this._hash = reader.readReverse(32).toString('hex')
    }
    return this._hash
  }

  /**
   * Get the transaction ID (little endian)
   */
  get id(): string {
    return this.txid
  }

  /**
   * Get the transaction ID (little endian)
   */
  get txid(): string {
    if (!this._txid) {
      const txidBuffer = this._getTxid()
      const reader = new BufferReader(txidBuffer)
      this._txid = reader.readReverse(32).toString('hex')
    }
    return this._txid
  }

  /**
   * Get the total input amount
   */
  get inputAmount(): number {
    return this._getInputAmount()
  }

  /**
   * Get the total output amount
   */
  get outputAmount(): number {
    return this._getOutputAmount()
  }

  get version(): number {
    return this._version
  }

  /** Satoshi-per-byte ratio for transaction fee calculation */
  feePerByte(feePerByte: number) {
    this._feePerByte = feePerByte
    this._updateChangeOutput()
  }

  /**
   * Set fee
   */
  fee(amount: number) {
    this._fee = amount
    this._updateChangeOutput()
  }

  /**
   * Set fee per KB
   */
  feePerKb(amount: number) {
    this._feePerKb = amount
    this._updateChangeOutput()
  }

  /**
   * Set version
   */
  set version(version: number) {
    this._version = version
  }

  /**
   * Retrieve the little endian hash of the transaction (used for serialization)
   */
  private _getHash(): Buffer {
    return Hash.sha256sha256(this.toBuffer())
  }

  /**
   * Get transaction ID hash
   */
  private _getTxid(): Buffer {
    const writer = new BufferWriter()
    writer.writeInt32LE(this.version)

    const inputHashes = this._getTxInputHashes()
    const outputHashes = this._getTxOutputHashes()
    const inputMerkleRootAndHeight = this._computeMerkleRoot(inputHashes)
    const outputMerkleRootAndHeight = this._computeMerkleRoot(outputHashes)

    writer.write(inputMerkleRootAndHeight.root)
    writer.writeUInt8(inputMerkleRootAndHeight.height)

    writer.write(outputMerkleRootAndHeight.root)
    writer.writeUInt8(outputMerkleRootAndHeight.height)

    writer.writeUInt32LE(this.nLockTime)

    return Hash.sha256sha256(writer.toBuffer())
  }

  /**
   * Iterate through each input in the transaction and return an array of hashes
   */
  private _getTxInputHashes(): Buffer[] {
    const hashes: Buffer[] = []

    if (this.inputs.length === 0) {
      return [Transaction.NULL_HASH]
    }

    for (let i = 0; i < this.inputs.length; i++) {
      const input = this.inputs[i]
      const writer = new BufferWriter()

      // The input hash is calculated by hashing together prevTxId buffer, outputIndex, and sequence number
      writer.writeReverse(input.prevTxId)
      writer.writeUInt32LE(input.outputIndex)
      writer.writeUInt32LE(Number(input.sequenceNumber))

      const hash = Hash.sha256sha256(writer.toBuffer())
      hashes.push(hash)
    }

    return hashes
  }

  /**
   * Iterate through each output in the transaction and return an array of hashes
   */
  private _getTxOutputHashes(): Buffer[] {
    const hashes: Buffer[] = []

    if (this.outputs.length === 0) {
      return [Transaction.NULL_HASH]
    }

    for (let i = 0; i < this.outputs.length; i++) {
      const output = this.outputs[i]
      // The output hash is calculated by hashing the output data
      const writer = new BufferWriter()
      writer.writeUInt64LEBN(new BN(output.satoshis))
      writer.writeVarLengthBuffer(output.scriptBuffer)
      const hash = Hash.sha256sha256(writer.toBuffer())
      hashes.push(hash)
    }

    return hashes
  }

  /**
   * Compute the merkle root and return the merkle root and the height of the merkle tree
   */
  private _computeMerkleRoot(hashes: Buffer[]): {
    root: Buffer
    height: number
  } {
    if (hashes.length === 0) {
      return {
        root: Transaction.NULL_HASH,
        height: 0,
      }
    }

    let j = 0
    let height = 1

    for (let size = hashes.length; size > 1; size = Math.floor(size / 2)) {
      height += 1
      if (size % 2 === 1) {
        hashes.push(Transaction.NULL_HASH)
        size += 1
      }
      for (let i = 0; i < size; i += 2) {
        const buf = Buffer.concat([hashes[j + i], hashes[j + i + 1]])
        hashes.push(Hash.sha256sha256(buf))
      }
      j += size
    }

    return {
      root: hashes[hashes.length - 1],
      height: height,
    }
  }

  /**
   * Get the total input amount
   */
  private _getInputAmount(): number {
    if (this._inputAmount !== undefined) {
      return this._inputAmount
    }

    let total = 0
    for (const input of this.inputs) {
      if (input.output && input.output.satoshis) {
        total += input.output.satoshis
      }
    }
    this._inputAmount = total
    return total
  }

  /**
   * Get the total output amount
   */
  private _getOutputAmount(): number {
    if (this._outputAmount !== undefined) {
      return this._outputAmount
    }

    let total = 0
    for (const output of this.outputs) {
      total += output.satoshis
    }
    this._outputAmount = total
    return total
  }

  /**
   * Initialize a new transaction
   */
  private _newTransaction(): void {
    this.version = CURRENT_VERSION
    this.nLockTime = DEFAULT_NLOCKTIME
  }

  /**
   * Serialize transaction to hex string
   */
  serialize(unsafe?: boolean | { disableAll?: boolean }): string {
    if (unsafe === true || (unsafe && unsafe.disableAll)) {
      return this.uncheckedSerialize()
    } else {
      return this.checkedSerialize(
        unsafe as {
          disableAll?: boolean
          disableDustOutputs?: boolean
          disableIsFullySigned?: boolean
        },
      )
    }
  }

  /**
   * Unchecked serialization (no validation)
   */
  uncheckedSerialize(): string {
    return this.toBuffer().toString('hex')
  }

  /**
   * Checked serialization (with validation)
   */
  checkedSerialize(opts?: {
    disableAll?: boolean
    disableDustOutputs?: boolean
    disableIsFullySigned?: boolean
  }): string {
    const serializationError = this.getSerializationError(opts)
    if (serializationError) {
      serializationError.message +=
        ' - For more information please see: ' +
        'https://bitcore.io/api/lib/transaction#serialization-checks'
      throw serializationError
    }
    return this.uncheckedSerialize()
  }

  /**
   * Get serialization error if any
   */
  getSerializationError(opts?: {
    disableAll?: boolean
    disableDustOutputs?: boolean
    disableIsFullySigned?: boolean
  }): Error | null {
    // Check for dust outputs
    const dustError = this._hasDustOutputs(opts)
    if (dustError) return dustError

    // Check for missing signatures
    const sigError = this._isMissingSignatures(opts)
    if (sigError) return sigError

    // Check for invalid satoshis
    if (this._hasInvalidSatoshis()) {
      return new BitcoreError('Invalid satoshis in outputs')
    }

    return null
  }

  /**
   * Check for dust outputs
   */
  private _hasDustOutputs(opts?: {
    disableDustOutputs?: boolean
  }): Error | null {
    if (opts && opts.disableDustOutputs) {
      return null
    }

    for (const output of this.outputs) {
      if (output.satoshis < Transaction.DUST_AMOUNT && !output.isOpReturn()) {
        return new BitcoreError('Dust outputs not allowed')
      }
    }

    return null
  }

  /**
   * Check for missing signatures
   */
  private _isMissingSignatures(opts?: {
    disableIsFullySigned?: boolean
  }): Error | null {
    if (opts && opts.disableIsFullySigned) {
      return null
    }

    if (!this.isFullySigned()) {
      return new BitcoreError('Transaction is not fully signed')
    }

    return null
  }

  /**
   * Check if transaction has invalid satoshis
   */
  private _hasInvalidSatoshis(): boolean {
    for (const output of this.outputs) {
      if (output.satoshis < 0) {
        return true
      }
    }
    return false
  }

  /**
   * Check if transaction is fully signed
   */
  isFullySigned(): boolean {
    for (const input of this.inputs) {
      // For now, assume inputs are fully signed if they have a script
      if (!input.script || input.script.chunks.length === 0) {
        return false
      }
    }
    return true
  }

  /**
   * Convert to Buffer
   */
  toBuffer(): Buffer {
    const writer = new BufferWriter()
    return this.toBufferWriter(writer).toBuffer()
  }

  /**
   * Write to BufferWriter
   */
  toBufferWriter(writer?: BufferWriter): BufferWriter {
    if (!writer) {
      writer = new BufferWriter()
    }
    writer.writeInt32LE(this.version)
    writer.writeVarintNum(this.inputs.length)
    for (const input of this.inputs) {
      input.toBufferWriter(writer)
    }
    writer.writeVarintNum(this.outputs.length)
    for (const output of this.outputs) {
      writer.writeUInt64LEBN(new BN(output.satoshis))
      writer.writeVarLengthBuffer(output.scriptBuffer)
    }
    writer.writeUInt32LE(this.nLockTime)
    return writer
  }

  /**
   * Deserialize from Buffer
   */
  fromBuffer(buffer: Buffer): Transaction {
    const reader = new BufferReader(buffer)
    return this.fromBufferReader(reader)
  }

  /**
   * Deserialize from BufferReader
   */
  fromBufferReader(reader: BufferReader): Transaction {
    Preconditions.checkArgument(
      !reader.finished(),
      'No transaction data received',
    )

    this.version = reader.readInt32LE()
    const sizeTxIns = reader.readVarintNum()

    for (let i = 0; i < sizeTxIns; i++) {
      const input = Input.fromBufferReader(reader)
      this.inputs.push(input)
    }

    const sizeTxOuts = reader.readVarintNum()
    for (let i = 0; i < sizeTxOuts; i++) {
      const output = Output.fromBufferReader(reader)
      this.outputs.push(output)
    }

    this.nLockTime = reader.readUInt32LE()
    return this
  }

  /**
   * Deserialize from hex string
   */
  fromString(str: string): Transaction {
    return this.fromBuffer(Buffer.from(str, 'hex'))
  }

  /**
   * Convert to object
   */
  toObject(): TransactionObject {
    const inputs = this.inputs.map(input => input.toObject())

    const outputs = this.outputs.map(output => output.toObject())

    const obj: TransactionObject = {
      txid: this.txid,
      hash: this.hash,
      version: this.version,
      inputs: inputs,
      outputs: outputs,
      nLockTime: this.nLockTime,
    }

    if (this._changeScript) {
      obj.changeScript = this._changeScript.toString()
      obj.changeAsm = this._changeScript.toASM()
    }
    if (this._changeIndex !== undefined) {
      obj.changeIndex = this._changeIndex
    }
    if (this._fee !== undefined) {
      obj.fee = this._fee
    }

    return obj
  }

  /**
   * Convert to JSON
   */
  toJSON = this.toObject

  /**
   * Deserialize from object
   */
  fromObject(arg: TransactionData | Transaction): Transaction {
    Preconditions.checkArgument(
      typeof arg === 'object' && arg !== null,
      'Must provide an object to deserialize a transaction',
    )

    let transaction: TransactionData
    if (arg instanceof Transaction) {
      const obj = arg.toObject()
      transaction = {
        version: obj.version,
        nLockTime: obj.nLockTime,
        inputs: obj.inputs,
        outputs: obj.outputs,
        changeScript: obj.changeScript,
        changeIndex: obj.changeIndex,
        fee: obj.fee,
      }
    } else {
      transaction = arg
    }

    // Clear existing data
    this.inputs = []
    this.outputs = []

    // Set version and locktime
    this.version = transaction.version || CURRENT_VERSION
    this.nLockTime = transaction.nLockTime || DEFAULT_NLOCKTIME

    // Add inputs
    if (transaction.inputs) {
      for (const inputData of transaction.inputs) {
        const input = new Input({
          prevTxId: inputData.prevTxId,
          outputIndex: inputData.outputIndex,
          sequenceNumber: inputData.sequenceNumber,
          script: inputData.script || undefined,
          scriptBuffer: inputData.scriptBuffer,
          output: inputData.output,
        })
        this.inputs.push(input)
      }
    }

    // Add outputs
    if (transaction.outputs) {
      for (const outputData of transaction.outputs) {
        const output = new Output({
          satoshis: outputData.satoshis,
          script: outputData.script,
        })
        this.outputs.push(output)
      }
    }

    // Set change script and index
    if (transaction.changeScript) {
      this._changeScript =
        typeof transaction.changeScript === 'string'
          ? Script.fromString(transaction.changeScript)
          : transaction.changeScript
    }
    if (transaction.changeIndex !== undefined) {
      this._changeIndex = transaction.changeIndex
    }
    if (transaction.fee !== undefined) {
      this._fee = transaction.fee
    }

    return this
  }

  /**
   * Add an input to the transaction
   */
  addInput(input: Input): Transaction {
    this.inputs.push(input)
    this._inputAmount = undefined // Reset cached amount
    return this
  }

  /**
   * Add an output to the transaction
   */
  addOutput(output: Output): Transaction {
    this._addOutput(output)
    this._updateChangeOutput()
    return this
  }

  /**
   * Clone this transaction
   */
  clone(): Transaction {
    return Transaction.shallowCopy(this)
  }

  /**
   * String representation
   */
  toString(): string {
    return this.uncheckedSerialize()
  }

  /**
   * Inspect representation
   */
  inspect(): string {
    return '<Transaction: ' + this.uncheckedSerialize() + '>'
  }

  /**
   * Add inputs from UTXOs
   */
  from(
    utxos:
      | UnspentOutput[]
      | UnspentOutputData[]
      | UnspentOutput
      | UnspentOutputData,
    pubkeys?: PublicKey[],
    threshold?: number,
    opts?: { noSorting?: boolean },
  ): Transaction {
    if (Array.isArray(utxos)) {
      for (const utxo of utxos) {
        this.from(utxo, pubkeys, threshold, opts)
      }
      return this
    }

    const exists = this.inputs.some(
      input =>
        input.prevTxId.toString('hex') === utxos.txId &&
        input.outputIndex === utxos.outputIndex,
    )
    if (exists) {
      return this
    }

    const utxo: UnspentOutput =
      utxos instanceof UnspentOutput ? utxos : new UnspentOutput(utxos)

    if (pubkeys && threshold) {
      this._fromMultisigUtxo(utxo, pubkeys, threshold, opts)
    } else {
      this._fromNonP2SH(utxo)
    }
    return this
  }

  /**
   * Set change address
   */
  change(address: Address | string): Transaction {
    this._changeScript = Script.fromAddress(address)
    this._updateChangeOutput()
    return this
  }

  /**
   * Add output to transaction
   */
  to(
    address:
      | Address
      | string
      | Array<{ address: Address | string; satoshis: number }>,
    amount: number | string | bigint,
  ): Transaction {
    if (Array.isArray(address)) {
      for (const to of address) {
        this.to(to.address, to.satoshis)
      }
      return this
    }

    Preconditions.checkArgument(
      JSUtil.isNaturalNumber(amount),
      'Amount is expected to be a positive integer',
    )
    this.addOutput(
      new Output({
        script: Script.fromAddress(new Address(address)),
        satoshis: amount,
      }),
    )
    return this
  }

  /**
   * Sign transaction
   *
   * Signs all inputs that can be signed with the provided private key(s).
   * Supports multiple signature hash types including SIGHASH_LOTUS.
   *
   * Sighash Types:
   * - SIGHASH_ALL | SIGHASH_FORKID (default): Signs all inputs and outputs
   * - SIGHASH_ALL | SIGHASH_LOTUS | SIGHASH_FORKID: Uses Lotus merkle tree algorithm
   * - Other combinations: SINGLE, ANYONECANPAY, etc.
   *
   * SIGHASH_LOTUS Requirements:
   * - All inputs must have output information attached
   * - Use transaction.from(utxo) to automatically attach output info
   * - SIGHASH_LOTUS provides better scaling and validation efficiency
   *
   * @param privateKey - Private key(s) to sign with
   * @param sigtype - Signature hash type (default: SIGHASH_ALL | SIGHASH_FORKID)
   * @param signingMethod - 'ecdsa' or 'schnorr' (default: 'ecdsa')
   * @returns this transaction (for chaining)
   * @throws Error if SIGHASH_LOTUS is used but inputs are missing output info
   *
   * @example
   * ```typescript
   * // Standard signing with SIGHASH_FORKID
   * tx.from(utxo).to(address, amount).sign(privateKey)
   *
   * // Sign with SIGHASH_LOTUS
   * tx.from(utxo)
   *   .to(address, amount)
   *   .sign(privateKey, Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS | Signature.SIGHASH_FORKID)
   *
   * // Sign with Schnorr signatures
   * tx.from(utxo).to(address, amount).sign(privateKey, null, 'schnorr')
   * ```
   */
  sign(
    privateKey: PrivateKey | string | Array<PrivateKey | string>,
    sigtype?: number | null,
    signingMethod?: SignatureSigningMethod,
  ): Transaction {
    const privKeys = Array.isArray(privateKey) ? privateKey : [privateKey]
    const sigtypeDefault =
      sigtype || Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    for (const privKey of privKeys) {
      const signatures = this.getSignatures(
        privKey,
        sigtypeDefault,
        signingMethod,
      )
      for (const signature of signatures) {
        this.applySignature(signature, signingMethod)
      }
    }
    return this
  }

  /**
   * Signs the transaction using the Schnorr signature algorithm with SIGHASH_LOTUS.
   *
   * This method is a convenience wrapper for signing Taproot and Lotus-native transactions,
   * as Taproot and SIGHASH_LOTUS require Schnorr signatures.
   *
   * - Uses SIGHASH_ALL | SIGHASH_LOTUS as the signature hash type.
   * - Applies to all inputs, signing each individually.
   * - Accepts a single private key, a WIF string, or an array of keys/WIFs.
   *
   * @param privateKey - Single private key, WIF string, or array of either.
   * @returns This Transaction instance (for chaining).
   *
   * @example
   * tx.signSchnorr(myTaprootKey)
   * tx.signSchnorr(['key1', 'key2'])
   */
  signSchnorr(
    privateKey: PrivateKey | string | Array<PrivateKey | string>,
  ): Transaction {
    return this.sign(
      privateKey,
      Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      'schnorr',
    )
  }

  /**
   * Get all MuSig2 Taproot inputs in this transaction
   *
   * Returns an array of MuSigTaprootInput instances that require
   * multi-party signing coordination.
   *
   * @returns Array of MuSig2 Taproot inputs
   *
   * @example
   * ```typescript
   * const musigInputs = tx.getMuSig2Inputs()
   * for (const input of musigInputs) {
   *   // Coordinate signing for each MuSig2 input
   * }
   * ```
   */
  getMuSig2Inputs(): MuSigTaprootInput[] {
    return this.inputs.filter(
      input => input instanceof MuSigTaprootInput,
    ) as MuSigTaprootInput[]
  }

  /**
   * Get sighash for a MuSig2 Taproot input
   *
   * Computes the transaction hash that needs to be signed for a specific
   * MuSig2 Taproot input using SIGHASH_ALL | SIGHASH_LOTUS.
   *
   * @param inputIndex - Index of the MuSig2 input
   * @returns 32-byte sighash buffer to be signed
   * @throws Error if input is not a MuSigTaprootInput
   *
   * @example
   * ```typescript
   * const sighash = tx.getMuSig2Sighash(0)
   * // Use this sighash to coordinate MuSig2 signing
   * ```
   */
  getMuSig2Sighash(inputIndex: number): Buffer {
    const input = this.inputs[inputIndex]
    if (!(input instanceof MuSigTaprootInput)) {
      throw new Error(`Input ${inputIndex} is not a MuSigTaprootInput`)
    }

    if (!input.output) {
      throw new Error(`Input ${inputIndex} is missing output information`)
    }

    const sigtype = Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS

    return computeSighash(
      this,
      sigtype,
      inputIndex,
      input.output.script,
      new BN(input.output.satoshis),
    )
  }

  /**
   * Add a public nonce for a MuSig2 input
   *
   * During Round 1 of MuSig2 signing, each signer generates and shares
   * their public nonces. Use this method to add received nonces to the input.
   *
   * @param inputIndex - Index of the MuSig2 input
   * @param signerIndex - Index of the signer (0-based)
   * @param nonce - Public nonce pair [R1, R2] from the signer
   * @returns this transaction (for chaining)
   * @throws Error if input is not a MuSigTaprootInput
   *
   * @example
   * ```typescript
   * // Alice adds Bob's nonce
   * tx.addMuSig2Nonce(0, 1, [bobR1, bobR2])
   * ```
   */
  addMuSig2Nonce(
    inputIndex: number,
    signerIndex: number,
    nonce: [Point, Point],
  ): Transaction {
    const input = this.inputs[inputIndex]
    if (!(input instanceof MuSigTaprootInput)) {
      throw new Error(`Input ${inputIndex} is not a MuSigTaprootInput`)
    }

    input.addPublicNonce(signerIndex, nonce)
    return this
  }

  /**
   * Add a partial signature for a MuSig2 input
   *
   * During Round 2 of MuSig2 signing, each signer generates and shares
   * their partial signatures. Use this method to add received partial
   * signatures to the input.
   *
   * @param inputIndex - Index of the MuSig2 input
   * @param signerIndex - Index of the signer (0-based)
   * @param partialSig - Partial signature from the signer
   * @returns this transaction (for chaining)
   * @throws Error if input is not a MuSigTaprootInput
   *
   * @example
   * ```typescript
   * // Alice adds Bob's partial signature
   * tx.addMuSig2PartialSignature(0, 1, bobPartialSig)
   * ```
   */
  addMuSig2PartialSignature(
    inputIndex: number,
    signerIndex: number,
    partialSig: BN,
  ): Transaction {
    const input = this.inputs[inputIndex]
    if (!(input instanceof MuSigTaprootInput)) {
      throw new Error(`Input ${inputIndex} is not a MuSigTaprootInput`)
    }

    input.addPartialSignature(signerIndex, partialSig)
    return this
  }

  /**
   * Finalize all MuSig2 inputs
   *
   * Aggregates partial signatures for all MuSig2 inputs that have received
   * all required partial signatures. This creates the final Schnorr signatures
   * and adds them to the input scripts.
   *
   * @returns this transaction (for chaining)
   * @throws Error if any MuSig2 input is missing partial signatures
   *
   * @example
   * ```typescript
   * // After all participants have shared partial signatures
   * tx.finalizeMuSig2Signatures()
   * console.log('Transaction ready to broadcast:', tx.serialize())
   * ```
   */
  finalizeMuSig2Signatures(): Transaction {
    const musigInputs = this.getMuSig2Inputs()

    for (let i = 0; i < this.inputs.length; i++) {
      const input = this.inputs[i]
      if (input instanceof MuSigTaprootInput) {
        if (!input.hasAllPartialSignatures()) {
          throw new Error(
            `MuSig2 input ${i} is missing partial signatures. ` +
              `Has ${input.partialSignatures?.size || 0} of ${input.keyAggContext?.pubkeys.length || 0}`,
          )
        }

        const sighash = this.getMuSig2Sighash(i)
        input.finalizeMuSigSignature(this, sighash)
      }
    }

    return this
  }

  /**
   * Get signatures for transaction
   */
  getSignatures(
    privKey: PrivateKey | string,
    sigtype?: number,
    signingMethod?: string,
  ): TransactionSignature[] {
    const privateKey = new PrivateKey(privKey)
    const sigtypeDefault =
      sigtype || Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
    const results: TransactionSignature[] = []

    const hashData = Hash.sha256ripemd160(privateKey.publicKey.toBuffer())
    for (let index = 0; index < this.inputs.length; index++) {
      const input = this.inputs[index]
      const signatures = input.getSignatures(
        this,
        privateKey,
        index,
        sigtypeDefault,
        hashData,
        signingMethod,
      )
      for (const signature of signatures) {
        results.push(signature)
      }
    }
    return results
  }

  /**
   * Apply signature to transaction
   */
  applySignature(
    signature: TransactionSignature,
    signingMethod?: SignatureSigningMethod,
  ): Transaction {
    this.inputs[signature.inputIndex].addSignature(
      this,
      signature,
      signingMethod,
    )
    return this
  }

  /**
   * Check if signature is valid
   */
  isValidSignature(sig: TransactionSignature): boolean {
    const input = this.inputs[sig.inputIndex]
    return input.isValidSignature(this, sig)
  }

  /**
   * Verify signature
   */
  verifySignature(
    sig: Signature,
    pubkey: PublicKey,
    nin: number,
    subscript: Script,
    satoshisBN: BN,
    flags?: number,
    signingMethod?: string,
  ): boolean {
    return verify(
      this as TransactionLike,
      sig,
      pubkey,
      nin,
      subscript,
      satoshisBN,
      flags,
      signingMethod as 'ecdsa' | 'schnorr' | undefined,
    )
  }

  /**
   * Lock until date
   */
  lockUntilDate(time: Date | number): Transaction {
    Preconditions.checkArgument(!!time, 'time is required')
    if (
      typeof time === 'number' &&
      time < Transaction.NLOCKTIME_BLOCKHEIGHT_LIMIT
    ) {
      throw new Error('Lock time too early')
    }
    if (time instanceof Date) {
      time = time.getTime() / 1000
    }

    for (let i = 0; i < this.inputs.length; i++) {
      if (this.inputs[i].sequenceNumber === Input.DEFAULT_SEQNUMBER) {
        this.inputs[i].sequenceNumber = Input.DEFAULT_LOCKTIME_SEQNUMBER
      }
    }

    this.nLockTime = time as number
    return this
  }

  /**
   * Lock until block height
   */
  lockUntilBlockHeight(height: number): Transaction {
    Preconditions.checkArgument(
      typeof height === 'number',
      'height must be a number',
    )
    if (height >= Transaction.NLOCKTIME_BLOCKHEIGHT_LIMIT) {
      throw new Error('Block height too high')
    }
    if (height < 0) {
      throw new Error('NLockTime out of range')
    }

    for (let i = 0; i < this.inputs.length; i++) {
      if (this.inputs[i].sequenceNumber === Input.DEFAULT_SEQNUMBER) {
        this.inputs[i].sequenceNumber = Input.DEFAULT_LOCKTIME_SEQNUMBER
      }
    }

    this.nLockTime = height
    return this
  }

  /**
   * Get lock time
   */
  getLockTime(): Date | number | null {
    if (!this.nLockTime) {
      return null
    }
    if (this.nLockTime < Transaction.NLOCKTIME_BLOCKHEIGHT_LIMIT) {
      return this.nLockTime
    }
    return new Date(1000 * this.nLockTime)
  }

  /**
   * Check if has all UTXO info
   */
  hasAllUtxoInfo(): boolean {
    return this.inputs.every(input => !!input.output)
  }

  /**
   * Add data output
   */
  addData(value: Buffer | string): Transaction {
    this.addOutput(
      new Output({
        script: Script.buildDataOut(value),
        satoshis: 0,
      }),
    )
    return this
  }

  /**
   * Clear outputs
   */
  clearOutputs(): Transaction {
    this.outputs = []
    this._clearSignatures()
    this._outputAmount = undefined
    this._changeIndex = undefined
    this._updateChangeOutput()
    return this
  }

  /**
   * Remove output
   */
  removeOutput(index: number): void {
    this._removeOutput(index)
    this._updateChangeOutput()
  }

  /**
   * Sort transaction
   */
  sort(): Transaction {
    this.sortInputs(inputs => {
      const copy = [...inputs]
      let i = 0
      copy.forEach(x => {
        ;(x as Input & { i?: number }).i = i++
      })
      copy.sort((first, second) => {
        const prevTxIdCompare = Buffer.compare(first.prevTxId, second.prevTxId)
        if (prevTxIdCompare !== 0) return prevTxIdCompare
        const outputIndexCompare = first.outputIndex - second.outputIndex
        if (outputIndexCompare !== 0) return outputIndexCompare
        return (
          (first as Input & { i?: number }).i! -
          (second as Input & { i?: number }).i!
        )
      })
      return copy
    })
    this.sortOutputs(outputs => {
      const copy = [...outputs]
      let i = 0
      copy.forEach(x => {
        ;(x as Output & { i?: number }).i = i++
      })
      copy.sort((first, second) => {
        const satoshisCompare = first.satoshis - second.satoshis
        if (satoshisCompare !== 0) return satoshisCompare
        const scriptCompare = Buffer.compare(
          first.scriptBuffer,
          second.scriptBuffer,
        )
        if (scriptCompare !== 0) return scriptCompare
        return (
          (first as Output & { i?: number }).i! -
          (second as Output & { i?: number }).i!
        )
      })
      return copy
    })
    return this
  }

  /**
   * Sort inputs
   */
  sortInputs(sortingFunction: (inputs: Input[]) => Input[]): Transaction {
    this.inputs = sortingFunction(this.inputs)
    return this
  }

  /**
   * Sort outputs
   */
  sortOutputs(sortingFunction: (outputs: Output[]) => Output[]): Transaction {
    const sortedOutputs = sortingFunction(this.outputs)
    return this._newOutputOrder(sortedOutputs)
  }

  /**
   * Shuffle outputs
   */
  shuffleOutputs(): Transaction {
    return this.sortOutputs(outputs => {
      const shuffled = [...outputs]
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1))
        ;[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]]
      }
      return shuffled
    })
  }

  /**
   * Remove input
   */
  removeInput(index: number): void {
    this.inputs.splice(index, 1)
    this._inputAmount = undefined
  }

  /**
   * Get fee
   */
  getFee(): number {
    if (this.isCoinbase()) {
      return 0
    }
    if (this._fee !== undefined) {
      return this._fee
    }
    if (!this._changeScript) {
      return this._getUnspentValue()
    }
    return this._estimateFee()
  }

  /**
   * Get change output
   */
  getChangeOutput(): Output | null {
    if (this._changeIndex !== undefined) {
      return this.outputs[this._changeIndex]
    }
    return null
  }

  /**
   * Verify transaction based on Lotus consensus rules
   * Based on tx_check.cpp in lotusd
   */
  verify(): string | boolean {
    // Basic checks that don't depend on any context

    // Check if inputs are empty
    if (this.inputs.length === 0) {
      return 'transaction inputs empty'
    }

    // Check if outputs are empty
    if (this.outputs.length === 0) {
      return 'transaction outputs empty'
    }

    // Size limits - Lotus uses 32MB max block size
    if (this.toBuffer().length > MAX_BLOCK_SIZE) {
      return 'transaction over the maximum block size'
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    let totalOutput = 0
    for (let i = 0; i < this.outputs.length; i++) {
      const output = this.outputs[i]

      // Check if satoshis is negative
      if (output.satoshis < 0) {
        return 'transaction output ' + i + ' satoshis is negative'
      }

      // Check if individual output exceeds MAX_MONEY
      if (output.satoshis > MAX_MONEY) {
        return 'transaction output ' + i + ' greater than MAX_MONEY'
      }

      // Check total output overflow
      totalOutput += output.satoshis
      if (totalOutput > MAX_MONEY) {
        return (
          'transaction output ' + i + ' total output greater than MAX_MONEY'
        )
      }
    }

    // Handle coinbase transactions separately
    if (this.isCoinbase()) {
      // Check coinbase script size (2-100 bytes)
      const coinbaseScript = this.inputs[0].scriptBuffer
      if (
        !coinbaseScript ||
        coinbaseScript.length < 2 ||
        coinbaseScript.length > 100
      ) {
        return 'coinbase transaction script size invalid'
      }
      return true
    }

    // For regular transactions:

    // Check for missing previous output information
    if (!this.hasAllUtxoInfo()) {
      return 'Missing previous output information'
    }

    // Input amount MUST NOT be less than output amount
    if (this.inputAmount < this.outputAmount) {
      return 'transaction input amount is less than output amount'
    }

    // Enforce minimum transaction fee based on FEE_PER_KB
    const actualFee = this.inputAmount - this.outputAmount
    const txSize = this.toBuffer().length
    // Calculate minimum fee: fee rate per KB / 1000 = per byte
    const feeRatePerByte = Transaction.FEE_PER_KB / 1000
    const minRequiredFee = Math.ceil(txSize * feeRatePerByte)

    if (actualFee < minRequiredFee) {
      return `transaction fee too low: ${actualFee} < ${minRequiredFee} (minimum ${feeRatePerByte} satoshi/byte)`
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    const inputSet = new Set<string>()
    for (let i = 0; i < this.inputs.length; i++) {
      const input = this.inputs[i]

      // Check for null inputs
      if (input.prevTxId.equals(Transaction.NULL_HASH)) {
        return 'transaction input ' + i + ' has null input'
      }

      // Check for duplicate inputs
      const inputId =
        input.prevTxId.toString('hex') + ':' + input.outputIndex.toString()
      if (inputSet.has(inputId)) {
        return 'transaction input ' + i + ' duplicate input'
      }
      inputSet.add(inputId)
    }

    // Verify input scripts using the Interpreter
    const scriptVerification = this._verifyScripts()
    if (!scriptVerification.success) {
      return scriptVerification.error || 'Script verification failed'
    }

    return true
  }

  /**
   * Verify all input scripts using the Interpreter
   * This validates that each scriptSig properly satisfies its corresponding scriptPubkey
   *
   * @param flags - Script verification flags (optional, defaults to standard Lotus flags)
   * @returns Object with success boolean and optional error message
   */
  private _verifyScripts(flags?: number): { success: boolean; error?: string } {
    // Skip script verification for coinbase transactions
    if (this.isCoinbase()) {
      return { success: true }
    }

    // Check that all inputs have output information
    if (!this.hasAllUtxoInfo()) {
      return {
        success: false,
        error: 'Missing UTXO (output) information for script verification',
      }
    }

    // Verify each input's script
    for (let i = 0; i < this.inputs.length; i++) {
      const input = this.inputs[i]

      // Ensure scripts are defined
      if (!input.script || !input.output?.script) {
        return {
          success: false,
          error: `Input ${i} script verification failed: missing script`,
        }
      }

      try {
        // Use standard Lotus verification flags if not provided
        const verifyFlags =
          flags !== undefined
            ? flags
            : Interpreter.SCRIPT_VERIFY_P2SH |
              Interpreter.SCRIPT_VERIFY_STRICTENC |
              Interpreter.SCRIPT_VERIFY_DERSIG |
              Interpreter.SCRIPT_VERIFY_LOW_S |
              Interpreter.SCRIPT_VERIFY_NULLFAIL |
              Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID |
              Interpreter.SCRIPT_ENABLE_SCHNORR_MULTISIG

        // Verify once and capture both result and error
        const interpreter = new Interpreter()
        const isValid = interpreter.verify(
          input.script,
          input.output.script,
          this,
          i,
          verifyFlags,
          BigInt(input.output.satoshis),
        )

        if (!isValid) {
          return {
            success: false,
            error: `Input ${i} script verification failed: ${interpreter.errstr}`,
          }
        }
      } catch (error: unknown) {
        return {
          success: false,
          error: `Input ${i} script verification error: ${error instanceof Error ? error.message : String(error)}`,
        }
      }
    }

    return { success: true }
  }

  /**
   * Check if coinbase
   */
  isCoinbase(): boolean {
    return (
      this.inputs.length === 1 &&
      this.inputs[0].prevTxId.equals(Transaction.NULL_HASH) &&
      this.inputs[0].outputIndex === 0xffffffff
    )
  }

  /**
   * Add input without checking
   */
  uncheckedAddInput(input: Input): Transaction {
    Preconditions.checkArgument(
      input instanceof Input,
      'input must be an Input',
    )
    this.inputs.push(input)
    this._inputAmount = undefined
    this._updateChangeOutput()
    return this
  }

  // Private helper methods
  private _newOutputOrder(newOutputs: Output[]): Transaction {
    const isInvalidSorting =
      this.outputs.length !== newOutputs.length ||
      this.outputs.some((output, index) => output !== newOutputs[index])

    if (isInvalidSorting) {
      throw new BitcoreError(
        'Invalid sorting: outputs must contain the same elements',
      )
    }

    if (this._changeIndex !== undefined) {
      const changeOutput = this.outputs[this._changeIndex]
      this._changeIndex = newOutputs.findIndex(
        output => output === changeOutput,
      )
    }

    this.outputs = newOutputs
    return this
  }

  private _fromNonP2SH(utxo: UnspentOutput): void {
    let clazz: typeof Input
    const unspentOutput = new UnspentOutput(utxo)

    if (unspentOutput.script.isPayToTaproot()) {
      // Check if this is a MuSig2 Taproot input
      if (
        unspentOutput.keyAggContext &&
        unspentOutput.mySignerIndex !== undefined
      ) {
        clazz = MuSigTaprootInput
        // Create MuSigTaprootInput with key aggregation context
        const input = new MuSigTaprootInput({
          output: new Output({
            script: unspentOutput.script,
            satoshis: unspentOutput.satoshis,
          }),
          prevTxId: unspentOutput.txId,
          outputIndex: unspentOutput.outputIndex,
          script: new Script(),
          keyAggContext: unspentOutput.keyAggContext,
          mySignerIndex: unspentOutput.mySignerIndex,
        })
        this.addInput(input)
        return
      }
      clazz = TaprootInput
      // Create TaprootInput with internal key and merkle root if provided
      const taprootInput = new TaprootInput({
        output: new Output({
          script: unspentOutput.script,
          satoshis: unspentOutput.satoshis,
        }),
        prevTxId: unspentOutput.txId,
        outputIndex: unspentOutput.outputIndex,
        script: new Script(),
        internalPubKey: unspentOutput.internalPubKey,
        merkleRoot: unspentOutput.merkleRoot,
      })
      this.addInput(taprootInput)
      return
    } else if (unspentOutput.script.isPayToPublicKeyHash()) {
      clazz = PublicKeyHashInput
    } else if (unspentOutput.script.isPublicKeyOut()) {
      clazz = PublicKeyInput
    } else {
      clazz = Input
    }

    this.addInput(
      new clazz({
        output: new Output({
          script: unspentOutput.script,
          satoshis: unspentOutput.satoshis,
        }),
        prevTxId: unspentOutput.txId,
        outputIndex: unspentOutput.outputIndex,
        script: new Script(),
      }),
    )
  }

  private _fromMultisigUtxo(
    utxo: UnspentOutput,
    pubkeys: PublicKey[],
    threshold: number,
    opts?: { noSorting?: boolean },
  ): void {
    Preconditions.checkArgument(
      threshold <= pubkeys.length,
      'Number of required signatures must be greater than the number of public keys',
    )
    const unspentOutput = new UnspentOutput(utxo)
    if (unspentOutput.script.isMultisigOut()) {
      this.addInput(
        new MultisigInput(
          new Input({
            output: new Output({
              script: unspentOutput.script,
              satoshis: unspentOutput.satoshis,
            }),
            prevTxId: unspentOutput.txId,
            outputIndex: unspentOutput.outputIndex,
            script: new Script(),
          }),
          pubkeys,
          threshold,
          undefined,
          opts,
        ),
      )
    } else if (unspentOutput.script.isPayToScriptHash()) {
      this.addInput(
        new MultisigScriptHashInput(
          new Input({
            output: new Output({
              script: unspentOutput.script,
              satoshis: unspentOutput.satoshis,
            }),
            prevTxId: unspentOutput.txId,
            outputIndex: unspentOutput.outputIndex,
            script: new Script(),
          }),
          pubkeys,
          threshold,
          undefined,
          opts,
        ),
      )
    } else {
      throw new Error('Unsupported script type')
    }
  }

  private _updateChangeOutput(): void {
    if (!this._changeScript) {
      return
    }
    this._clearSignatures()
    if (this._changeIndex !== undefined) {
      this._removeOutput(this._changeIndex)
    }
    const available = this._getUnspentValue()
    const fee = this.getFee()
    const changeAmount = available - fee
    if (changeAmount >= Transaction.DUST_AMOUNT) {
      this._changeIndex = this.outputs.length
      this._addOutput(
        new Output({
          script: this._changeScript,
          satoshis: changeAmount,
        }),
      )
    } else {
      this._changeIndex = undefined
    }
  }

  private _getUnspentValue(): number {
    return this._getInputAmount() - this._getOutputAmount()
  }

  private _clearSignatures(): void {
    for (const input of this.inputs) {
      input.clearSignatures()
    }
  }

  private _estimateFee(): number {
    const estimatedSize = this._estimateSize()
    const available = this._getUnspentValue()
    const feeRate =
      this._feePerByte || (this._feePerKb || Transaction.FEE_PER_KB) / 1000
    const getFee = (size: number) => size * feeRate
    const fee = Math.ceil(getFee(estimatedSize))
    const feeWithChange = Math.ceil(
      getFee(estimatedSize) + getFee(Transaction.CHANGE_OUTPUT_MAX_SIZE),
    )
    if (!this._changeScript || available <= feeWithChange) {
      return fee
    }
    return feeWithChange
  }

  /**
   * Calculate varint size for a number
   */
  private static _getVarintSize(n: number): number {
    if (n < 253) return 1
    if (n < 0x10000) return 3
    if (n < 0x100000000) return 5
    return 9
  }

  private _estimateSize(): number {
    // Version (4 bytes)
    let result = 4

    // Input count varint
    result += Transaction._getVarintSize(this.inputs.length)

    // For each input:
    for (const input of this.inputs) {
      // prevTxId: 32 bytes (already reversed)
      // outputIndex: 4 bytes
      // sequence: 4 bytes
      result += 40

      // Script length varint + script content
      const scriptSigLen = input._estimateSize()
      result += Transaction._getVarintSize(scriptSigLen)
      result += scriptSigLen
    }

    // Output count varint
    result += Transaction._getVarintSize(this.outputs.length)

    // For each output:
    for (const output of this.outputs) {
      // Use Output's getSize() method which includes:
      // - 8 bytes for value (UInt64LE)
      // - varint for script length
      // - script content
      result += output.getSize()
    }

    // LockTime: 4 bytes
    result += 4

    return result
  }

  private _removeOutput(index: number): void {
    this.outputs.splice(index, 1)
    this._outputAmount = undefined
  }

  private _addOutput(output: Output): void {
    this.outputs.push(output)
    this._outputAmount = undefined
  }
}

// Note: Transaction.Input and Transaction.Output static properties removed
// to avoid circular dependency issues. Import Input/Output directly instead.

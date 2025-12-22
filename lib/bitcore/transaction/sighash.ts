import { Signature } from '../crypto/signature.js'
import { Script, empty } from '../script.js'
import { Output } from './output.js'
import { UnspentOutput } from './unspentoutput.js'
import { BufferReader } from '../encoding/bufferreader.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { BN } from '../crypto/bn.js'
import { Hash } from '../crypto/hash.js'
import { ECDSA } from '../crypto/ecdsa.js'
import { Schnorr } from '../crypto/schnorr.js'
import { Preconditions } from '../util/preconditions.js'
import { BufferUtil } from '../util/buffer.js'
import { Interpreter } from '../script/interpreter.js'
import { PrivateKey } from '../privatekey.js'
import { PublicKey } from '../publickey.js'
import { Transaction } from './transaction.js'
import { Input } from './input.js'

export interface TransactionLike {
  /** This array is also used */
  inputs: Array<{
    prevTxId: Buffer
    outputIndex: number
    sequenceNumber: number
    script?: Script | null
  }>
  outputs: Array<{
    satoshis: number
    script?: Script
    toBufferWriter(writer: BufferWriter): void
  }>
  spentOutputs?: Output[]
  toBuffer(): Buffer
  version?: number
  nLockTime?: number
}

const SIGHASH_SINGLE_BUG_CONST =
  '0000000000000000000000000000000000000000000000000000000000000001'
const BITS_64_ON_CONST = 'ffffffffffffffff'
const NULL_HASH = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
)

// Sighash algorithm mask (bits 5-6 determine the algorithm)
// From lotusd/src/script/sighashtype.h
const SIGHASH_ALGORITHM_MASK = 0x60

// By default, we sign with sighash_forkid
const DEFAULT_SIGN_FLAGS_CONST = 1 << 16 // SCRIPT_ENABLE_SIGHASH_FORKID

/**
 * Get ForkId for UAHF
 */
function GetForkId(): number {
  return 0 // In the UAHF, a fork id of 0 is used (see [4] REQ-6-2 NOTE 4)
}

/**
 * Calculate merkle root and height from an array of hashes
 *
 * Implements the Lotus merkle tree algorithm used in SIGHASH_LOTUS.
 *
 * Algorithm:
 * 1. If array is empty, return null hash and height 0
 * 2. Start with height = 1
 * 3. While more than 1 hash remains:
 *    - Increment height
 *    - If odd number of hashes, append null hash (0x00...00)
 *    - Hash pairs: hash256(hash[i] + hash[i+1])
 *    - Continue with resulting hashes
 * 4. Return final hash and height
 *
 * Reference: lotusd/src/consensus/merkle.cpp ComputeMerkleRoot()
 * Python ref: lotusd/test/functional/test_framework/messages.py get_merkle_root()
 *
 * @param hashes - Array of 32-byte hash buffers
 * @returns Object with root (32-byte Buffer) and height (number)
 */
function getMerkleRoot(hashes: Buffer[]): { root: Buffer; height: number } {
  if (hashes.length === 0) {
    return { root: NULL_HASH, height: 0 }
  }

  let currentHashes = [...hashes]
  let height = 1

  while (currentHashes.length > 1) {
    height++
    const newHashes: Buffer[] = []

    for (let i = 0; i < currentHashes.length; i += 2) {
      const left = currentHashes[i]
      const right =
        i + 1 < currentHashes.length ? currentHashes[i + 1] : NULL_HASH

      // Hash the pair
      const combined = Buffer.concat([left, right])
      const pairHash = Hash.sha256sha256(combined)
      newHashes.push(pairHash)
    }

    currentHashes = newHashes
  }

  return { root: currentHashes[0], height }
}

/**
 * Calculate sighash for Lotus signatures (SIGHASH_LOTUS)
 *
 * This implements the Lotus-specific sighash algorithm which provides:
 * - Merkle tree commitments for inputs and outputs
 * - Support for taproot/tapscript execution data
 * - More efficient batch validation
 * - Better scaling properties
 *
 * The algorithm differs from BIP143 by using merkle roots instead of simple hashes,
 * which allows for more efficient validation and future optimizations.
 *
 * Requirements:
 * - Must have SIGHASH_LOTUS (0x60) flag set
 * - Must have SIGHASH_FORKID (0x40) flag set (LOTUS implies FORKID)
 * - Must provide spent outputs for all inputs
 *
 * Reference: lotusd/src/script/interpreter.cpp lines 1782-1846
 * Python ref: lotusd/test/functional/test_framework/script.py lines 765-813
 *
 * @param transaction - The transaction being signed
 * @param sighashType - Signature hash type (must include SIGHASH_LOTUS | SIGHASH_FORKID)
 * @param inputNumber - Index of the input being signed
 * @param spentOutputs - Array of outputs being spent (one for each input)
 * @param executedScriptHash - Optional: hash of the script being executed (for tapscript)
 * @param codeseparatorPos - Optional: position of last OP_CODESEPARATOR (default: 0xFFFFFFFF)
 * @returns 32-byte signature hash
 * @throws Error if validation fails or required data is missing
 */
function sighashForLotus(
  transaction: TransactionLike,
  sighashType: number,
  inputNumber: number,
  spentOutputs: Output[],
  executedScriptHash?: Buffer,
  codeseparatorPos: number = 0xffffffff,
): Buffer {
  Preconditions.checkArgument(
    spentOutputs.length === transaction.inputs.length,
    'Must provide spent output for each input',
  )
  Preconditions.checkArgument(
    inputNumber < transaction.inputs.length,
    'Input index out of range',
  )

  // Validate sighash type
  const baseType = sighashType & 0x03
  const unusedBits = sighashType & 0x1c

  if (baseType === 0 || unusedBits !== 0) {
    throw new Error('Invalid sighash type for SIGHASH_LOTUS')
  }

  const input = transaction.inputs[inputNumber]
  const writer = new BufferWriter()

  // 1. Hash type (4 bytes, little-endian)
  writer.writeUInt32LE(sighashType >>> 0)

  // 2. Hash of (spend_type, prevout, nSequence, spent_output)
  const spendType = executedScriptHash ? 2 : 0
  const inputHashWriter = new BufferWriter()

  inputHashWriter.writeUInt8(spendType)

  // Prevout (txid + output index)
  inputHashWriter.writeReverse(input.prevTxId)
  inputHashWriter.writeUInt32LE(input.outputIndex)

  // Sequence
  inputHashWriter.writeUInt32LE(input.sequenceNumber)

  // Spent output (value + script)
  const spentOutput = spentOutputs[inputNumber]
  inputHashWriter.writeUInt64LEBN(new BN(spentOutput.satoshis))
  inputHashWriter.writeVarLengthBuffer(spentOutput.scriptBuffer)

  const inputHash = Hash.sha256sha256(inputHashWriter.toBuffer())
  writer.write(inputHash)

  // 3. If execdata exists: codeseparator_pos and executed_script_hash
  if (executedScriptHash) {
    Preconditions.checkArgument(
      executedScriptHash.length === 32,
      'executed_script_hash must be 32 bytes',
    )
    writer.writeUInt32LE(codeseparatorPos)
    writer.write(executedScriptHash)
  }

  // 4. If not ANYONECANPAY: input_index, inputs_spent_outputs_merkle_root, total_input_amount
  if (!(sighashType & Signature.SIGHASH_ANYONECANPAY)) {
    writer.writeUInt32LE(inputNumber)

    // Calculate merkle root of all spent outputs
    const spentOutputHashes = spentOutputs.map(output => {
      const w = new BufferWriter()
      w.writeUInt64LEBN(new BN(output.satoshis))
      w.writeVarLengthBuffer(output.scriptBuffer)
      return Hash.sha256sha256(w.toBuffer())
    })
    const spentOutputsMerkle = getMerkleRoot(spentOutputHashes)
    writer.write(spentOutputsMerkle.root)

    // Total input amount (in satoshis, 8 bytes little-endian)
    const totalInputAmount = spentOutputs.reduce(
      (sum, output) => sum + output.satoshis,
      0,
    )
    writer.writeUInt64LEBN(new BN(totalInputAmount))
  }

  // 5. If ALL: total_output_amount (8 bytes little-endian)
  if (baseType === Signature.SIGHASH_ALL) {
    const totalOutputAmount = transaction.outputs.reduce(
      (sum, output) => sum + output.satoshis,
      0,
    )
    writer.writeUInt64LEBN(new BN(totalOutputAmount))
  }

  // 6. Version
  writer.writeUInt32LE(transaction.version || 2)

  // 7. If not ANYONECANPAY: inputs_merkle_root and inputs_merkle_height
  if (!(sighashType & Signature.SIGHASH_ANYONECANPAY)) {
    // Calculate merkle root of inputs (prevout + nSequence)
    const inputHashes = transaction.inputs.map(inp => {
      const w = new BufferWriter()
      w.writeReverse(inp.prevTxId)
      w.writeUInt32LE(inp.outputIndex)
      w.writeUInt32LE(inp.sequenceNumber)
      return Hash.sha256sha256(w.toBuffer())
    })
    const inputsMerkle = getMerkleRoot(inputHashes)
    writer.write(inputsMerkle.root)
    writer.writeUInt8(inputsMerkle.height)
  }

  // 8. If SINGLE: hash of output at input_index
  if (baseType === Signature.SIGHASH_SINGLE) {
    if (inputNumber >= transaction.outputs.length) {
      throw new Error('SIGHASH_SINGLE: no corresponding output for input')
    }
    const w = new BufferWriter()
    transaction.outputs[inputNumber].toBufferWriter(w)
    const outputHash = Hash.sha256sha256(w.toBuffer())
    writer.write(outputHash)
  }

  // 9. If ALL: outputs_merkle_root and outputs_merkle_height
  if (baseType === Signature.SIGHASH_ALL) {
    const outputHashes = transaction.outputs.map(output => {
      const w = new BufferWriter()
      output.toBufferWriter(w)
      return Hash.sha256sha256(w.toBuffer())
    })
    const outputsMerkle = getMerkleRoot(outputHashes)
    writer.write(outputsMerkle.root)
    writer.writeUInt8(outputsMerkle.height)
  }

  // 10. Locktime
  writer.writeUInt32LE(transaction.nLockTime || 0)

  // Final hash -- DO NOT REVERSE BYTES
  return Hash.sha256sha256(writer.toBuffer())
}

/**
 * Calculate sighash for ForkId signatures (BIP143)
 */
function sighashForForkId(
  transaction: TransactionLike,
  sighashType: number,
  inputNumber: number,
  subscript: Script,
  satoshisBN: BN,
): Buffer {
  const input = transaction.inputs[inputNumber]
  Preconditions.checkArgument(
    satoshisBN instanceof BN,
    'For ForkId=0 signatures, satoshis or complete input must be provided',
  )

  let hashPrevouts = BufferUtil.emptyBuffer(32)
  let hashSequence = BufferUtil.emptyBuffer(32)
  let hashOutputs = BufferUtil.emptyBuffer(32)

  if (!(sighashType & Signature.SIGHASH_ANYONECANPAY)) {
    hashPrevouts = GetPrevoutHash(transaction)
  }

  if (
    !(sighashType & Signature.SIGHASH_ANYONECANPAY) &&
    (sighashType & 31) !== Signature.SIGHASH_SINGLE &&
    (sighashType & 31) !== Signature.SIGHASH_NONE
  ) {
    hashSequence = GetSequenceHash(transaction)
  }

  if (
    (sighashType & 31) !== Signature.SIGHASH_SINGLE &&
    (sighashType & 31) !== Signature.SIGHASH_NONE
  ) {
    hashOutputs = GetOutputsHash(transaction)
  } else if (
    (sighashType & 31) === Signature.SIGHASH_SINGLE &&
    inputNumber < transaction.outputs.length
  ) {
    hashOutputs = GetOutputsHash(transaction, inputNumber)
  }

  const writer = new BufferWriter()

  // Version
  writer.writeUInt32LE(transaction.version || 2)

  // Input prevouts/nSequence (none/all, depending on flags)
  writer.write(hashPrevouts)
  writer.write(hashSequence)

  // The input being signed (replacing the scriptSig with scriptCode + amount)
  writer.writeReverse(input.prevTxId)
  writer.writeUInt32LE(input.outputIndex)
  writer.writeVarintNum(subscript.toBuffer().length)
  writer.write(subscript.toBuffer())
  writer.writeUInt64LEBN(satoshisBN)
  writer.writeUInt32LENumber(input.sequenceNumber)

  // Outputs (none/one/all, depending on flags)
  writer.write(hashOutputs)

  // Locktime
  writer.writeUInt32LE(transaction.nLockTime || 0)

  // Sighash type
  writer.writeUInt32LE(sighashType >>> 0)

  const buf = writer.toBuffer()
  const hash = Hash.sha256sha256(buf)
  // DO NOT read these bytes in reverse
  // This will order the bytes in little-endian, but this must be big-endian
  return new BufferReader(hash).read(32)
}

/**
 * Calculate sighash for legacy signatures
 */
function sighashLegacy(
  transaction: TransactionLike,
  sighashType: number,
  inputNumber: number,
  subscript: Script,
): Buffer {
  const input = transaction.inputs[inputNumber]

  function getHash(w: BufferWriter): Buffer {
    const buf = w.toBuffer()
    return Hash.sha256sha256(buf)
  }

  const writer = new BufferWriter()

  // Version
  writer.writeUInt32LE(2) // Assuming version 2

  // Input count
  writer.writeVarintNum(transaction.inputs.length)

  // Inputs
  for (let i = 0; i < transaction.inputs.length; i++) {
    const txInput = transaction.inputs[i]
    writer.writeReverse(txInput.prevTxId)
    writer.writeUInt32LE(txInput.outputIndex)

    if (i === inputNumber) {
      writer.writeVarLengthBuffer(subscript.toBuffer())
    } else {
      writer.writeVarintNum(0) // Empty script
    }

    writer.writeUInt32LENumber(txInput.sequenceNumber)
  }

  // Output count
  writer.writeVarintNum(transaction.outputs.length)

  // Outputs
  if (
    (sighashType & 31) !== Signature.SIGHASH_SINGLE &&
    (sighashType & 31) !== Signature.SIGHASH_NONE
  ) {
    for (const output of transaction.outputs) {
      output.toBufferWriter(writer)
    }
  } else if (
    (sighashType & 31) === Signature.SIGHASH_SINGLE &&
    inputNumber < transaction.outputs.length
  ) {
    transaction.outputs[inputNumber].toBufferWriter(writer)
  }

  // Locktime
  writer.writeUInt32LE(transaction.nLockTime || 0)

  // Sighash type
  writer.writeUInt32LE(sighashType)

  return getHash(writer)
}

/**
 * Calculate the sighash for a transaction
 *
 * This function routes to the appropriate sighash algorithm based on flags:
 * - SIGHASH_LOTUS (0x60): Lotus sighash with merkle trees
 * - SIGHASH_FORKID (0x40): BIP143 sighash
 * - Legacy (0x00): Original Bitcoin sighash
 *
 * Note: SIGHASH_LOTUS requires spent outputs for all inputs to be available
 * in the transaction.spentOutputs property.
 *
 * @param transaction - The transaction being signed (must have spentOutputs for LOTUS)
 * @param sighashType - Signature hash type flags
 * @param inputNumber - Index of input being signed
 * @param subscript - Script being executed/signed
 * @param satoshisBN - Value of output being spent (required for FORKID/LOTUS)
 * @param flags - Script validation flags
 * @returns 32-byte signature hash
 */
function sighash(
  transaction: TransactionLike,
  sighashType: number,
  inputNumber: number,
  subscript: Script,
  satoshisBN?: BN,
  flags?: number,
): Buffer {
  if (flags === undefined) {
    flags = DEFAULT_SIGN_FLAGS_CONST
  }

  // Copy transaction
  const txcopy = Transaction.shallowCopy(transaction as Transaction)

  // Copy script
  subscript = new Script(subscript)

  // Handle replay protection
  if (flags & Interpreter.SCRIPT_ENABLE_REPLAY_PROTECTION) {
    // Legacy chain's value for fork id must be of the form 0xffxxxx.
    // By xoring with 0xdead, we ensure that the value will be different
    // from the original one, even if it already starts with 0xff.
    const forkValue = sighashType >> 8
    const newForkValue = 0xff0000 | (forkValue ^ 0xdead)
    sighashType = (newForkValue << 8) | (sighashType & 0xff)
  }

  // Determine which sighash algorithm to use based on algorithm bits (bits 5-6)
  const algorithmBits = sighashType & SIGHASH_ALGORITHM_MASK

  // Check for SIGHASH_LOTUS (algorithm bits == 0x60)
  if (
    algorithmBits === Signature.SIGHASH_LOTUS &&
    flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID
  ) {
    // SIGHASH_LOTUS requires spent outputs from transaction
    const spentOutputs = transaction.spentOutputs
    if (!spentOutputs || spentOutputs.length !== transaction.inputs.length) {
      throw new Error(
        'SIGHASH_LOTUS requires spent outputs for all inputs (ensure all inputs have output information)',
      )
    }

    return sighashForLotus(txcopy, sighashType, inputNumber, spentOutputs)
  }

  // Check for SIGHASH_FORKID (algorithm bits == 0x40)
  if (
    algorithmBits === Signature.SIGHASH_FORKID &&
    flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID
  ) {
    return sighashForForkId(
      txcopy,
      sighashType,
      inputNumber,
      subscript,
      satoshisBN!,
    )
  }

  // For no ForkId sighash, separators need to be removed.
  subscript.removeCodeseparators()

  // Blank signatures for other inputs
  for (let i = 0; i < txcopy.inputs.length; i++) {
    txcopy.inputs[i] = new Input({
      prevTxId: txcopy.inputs[i].prevTxId,
      outputIndex: txcopy.inputs[i].outputIndex,
      sequenceNumber: txcopy.inputs[i].sequenceNumber,
      script: empty(),
    })
  }

  txcopy.inputs[inputNumber] = new Input({
    prevTxId: txcopy.inputs[inputNumber].prevTxId,
    outputIndex: txcopy.inputs[inputNumber].outputIndex,
    sequenceNumber: txcopy.inputs[inputNumber].sequenceNumber,
    script: subscript,
  })

  // Handle SIGHASH_NONE and SIGHASH_SINGLE
  if (
    (sighashType & 31) === Signature.SIGHASH_NONE ||
    (sighashType & 31) === Signature.SIGHASH_SINGLE
  ) {
    // Clear all sequence numbers except for the input being signed
    for (let i = 0; i < txcopy.inputs.length; i++) {
      if (i !== inputNumber) {
        txcopy.inputs[i].sequenceNumber = 0
      }
    }
  }

  // Handle SIGHASH_NONE
  if ((sighashType & 31) === Signature.SIGHASH_NONE) {
    txcopy.outputs = []
  } else if ((sighashType & 31) === Signature.SIGHASH_SINGLE) {
    // The SIGHASH_SINGLE bug.
    // https://bitcointalk.org/index.php?topic=260595.0
    if (inputNumber >= txcopy.outputs.length) {
      return Buffer.from(SIGHASH_SINGLE_BUG_CONST, 'hex')
    }

    // Truncate outputs to inputNumber + 1
    txcopy.outputs.length = inputNumber + 1

    // Set outputs before inputNumber to have max value and empty script
    for (let i = 0; i < inputNumber; i++) {
      txcopy.outputs[i] = new Output({
        satoshis: BN.fromBuffer(Buffer.from(BITS_64_ON_CONST, 'hex')),
        script: empty(),
      })
    }
  }

  // Handle SIGHASH_ANYONECANPAY
  if (sighashType & Signature.SIGHASH_ANYONECANPAY) {
    txcopy.inputs = [txcopy.inputs[inputNumber]]
  }

  // Serialize the transaction
  const buf = new BufferWriter()
    .write(txcopy.toBuffer())
    .writeInt32LE(sighashType >>> 0)
    .toBuffer()

  const hash = Hash.sha256sha256(buf)
  // Reverse the hash bytes here because Bitcoin sighash and signature logic expect little-endian order.
  // This is a legacy convention from Satoshi's original implementation, where hashes are often displayed
  // in big-endian for humans but processed in little-endian for signing and validation.
  return new BufferReader(hash).readReverse(32)
}

/**
 * Sign a transaction input
 *
 * Generates a cryptographic signature for a transaction input using the specified
 * signing method (ECDSA or Schnorr) and sighash algorithm.
 *
 * Sighash Algorithm Selection:
 * - If SIGHASH_LOTUS flag is set: Uses Lotus sighash (requires transaction.spentOutputs)
 * - If SIGHASH_FORKID flag is set: Uses BIP143 sighash
 * - Otherwise: Uses legacy Bitcoin sighash
 *
 * @param transaction - The transaction being signed (must have spentOutputs for LOTUS)
 * @param privateKey - Private key to sign with
 * @param sighashType - Signature hash type (e.g., SIGHASH_ALL | SIGHASH_FORKID)
 * @param inputIndex - Index of the input being signed
 * @param subscript - The script being executed/signed
 * @param satoshisBN - Value of the output being spent
 * @param flags - Script validation flags
 * @param signingMethod - 'ecdsa' (default) or 'schnorr'
 * @returns Signature object with nhashtype set
 * @throws Error if SIGHASH_LOTUS is used without transaction.spentOutputs
 */
function sign(
  transaction: TransactionLike,
  privateKey: PrivateKey,
  sighashType: number,
  inputIndex: number,
  subscript: Script,
  satoshisBN?: BN,
  flags?: number,
  signingMethod?: 'ecdsa' | 'schnorr',
): Signature {
  const hashbuf = sighash(
    transaction,
    sighashType,
    inputIndex,
    subscript,
    satoshisBN,
    flags,
  )

  signingMethod = signingMethod || 'ecdsa'
  let sig: Signature

  if (signingMethod === 'schnorr') {
    sig = Schnorr.sign(hashbuf, privateKey, 'big')
    sig.nhashtype = sighashType
    return sig
  } else if (signingMethod === 'ecdsa') {
    sig = ECDSA.sign(hashbuf, privateKey, 'big')
    sig.nhashtype = sighashType
    return sig
  } else {
    throw new Error('Invalid signing method. Must be "ecdsa" or "schnorr"')
  }
}

/**
 * Verify a transaction signature
 *
 * Verifies that a signature is valid for the specified transaction input.
 * Automatically uses the correct sighash algorithm based on the signature's
 * nhashtype field (LOTUS, FORKID, or legacy).
 *
 * @param transaction - The transaction being verified (must have spentOutputs for LOTUS)
 * @param signature - The signature to verify (must have nhashtype set)
 * @param publicKey - Public key to verify against
 * @param inputIndex - Index of the input being verified
 * @param subscript - The script being executed
 * @param satoshisBN - Value of the output being spent
 * @param flags - Script validation flags
 * @param signingMethod - 'ecdsa' (default) or 'schnorr'
 * @returns true if signature is valid, false otherwise
 * @throws Error if SIGHASH_LOTUS is used without transaction.spentOutputs
 */
function verify(
  transaction: TransactionLike,
  signature: Signature,
  publicKey: PublicKey,
  inputIndex: number,
  subscript: Script,
  satoshisBN?: BN,
  flags?: number,
  signingMethod?: 'ecdsa' | 'schnorr',
): boolean {
  Preconditions.checkArgument(
    transaction !== undefined,
    'Transaction is required',
  )
  Preconditions.checkArgument(
    signature !== undefined && signature.nhashtype !== undefined,
    'Signature with nhashtype is required',
  )

  const hashbuf = sighash(
    transaction,
    signature.nhashtype!,
    inputIndex,
    subscript,
    satoshisBN,
    flags,
  )

  signingMethod = signingMethod || 'ecdsa'

  // NOTE: Using 'little' endian matches bitcore-lib-xpi behavior
  // Combined with BIP143 hash reversal, this produces correct signatures
  if (signingMethod === 'schnorr') {
    return Schnorr.verify(hashbuf, signature, publicKey, 'big')
  } else if (signingMethod === 'ecdsa') {
    return ECDSA.verify(hashbuf, signature, publicKey, 'big')
  } else {
    throw new Error('Invalid signing method. Must be "ecdsa" or "schnorr"')
  }
}

/**
 * Computes the double SHA256 hash of the prevouts (txid + index) of all inputs in the transaction.
 * @param tx - The transaction-like object.
 * @returns Buffer - The double SHA256 hash of all input prevouts.
 */
function GetPrevoutHash(tx: TransactionLike): Buffer {
  const writer = new BufferWriter()

  for (const input of tx.inputs) {
    writer.writeReverse(input.prevTxId)
    writer.writeUInt32LE(input.outputIndex)
  }

  const buf = writer.toBuffer()
  return Hash.sha256sha256(buf)
}

/**
 * Computes the double SHA256 hash of the sequence numbers of all inputs in the transaction.
 * @param tx - The transaction-like object.
 * @returns Buffer - The double SHA256 hash of all input sequence numbers.
 */
function GetSequenceHash(tx: TransactionLike): Buffer {
  const writer = new BufferWriter()

  for (const input of tx.inputs) {
    writer.writeUInt32LENumber(input.sequenceNumber)
  }

  const buf = writer.toBuffer()
  return Hash.sha256sha256(buf)
}

/**
 * Computes the double SHA256 hash of the serialized outputs in the transaction.
 * If n is provided, only that output is hashed.
 * @param tx - The transaction-like object.
 * @param n - Optional output index to hash a single output.
 * @returns Buffer - The double SHA256 hash of outputs.
 */
function GetOutputsHash(tx: TransactionLike, n?: number): Buffer {
  const writer = new BufferWriter()

  if (n === undefined) {
    for (const output of tx.outputs) {
      output.toBufferWriter(writer)
    }
  } else {
    tx.outputs[n].toBufferWriter(writer)
  }

  const buf = writer.toBuffer()
  return Hash.sha256sha256(buf)
}

/**
 * Default sign flags
 */
export const DEFAULT_SIGN_FLAGS = DEFAULT_SIGN_FLAGS_CONST

/**
 * Constants
 */
export const SIGHASH_SINGLE_BUG = SIGHASH_SINGLE_BUG_CONST
export const BITS_64_ON = BITS_64_ON_CONST

/**
 * @namespace Signing
 */
export { sighash, sign, verify }

import { Script } from '../script.js'
import { Opcode } from '../opcode.js'
import { BN } from '../crypto/bn.js'
import { Hash } from '../crypto/hash.js'
import { Signature } from '../crypto/signature.js'
import { PublicKey } from '../publickey.js'
import { ECDSA } from '../crypto/ecdsa.js'
import { Schnorr } from '../crypto/schnorr.js'
import { Preconditions } from '../util/preconditions.js'
import type { Transaction } from '../transaction/transaction.js'
import {
  TAPROOT_INTRO_SIZE,
  TAPROOT_SIZE_WITHOUT_STATE,
  TAPROOT_SCRIPTTYPE,
  verifyTaprootSpend,
} from '../taproot.js'

export interface InterpreterData {
  script?: Script
  tx?: Transaction
  nin?: number
  flags?: number
  satoshisBN?: bigint
  outputScript?: Script // Output script (scriptPubKey) for sighash calculation
}

export interface InterpreterObject {
  script?: Script
  tx?: Transaction
  nin?: number
  flags?: number
  satoshisBN?: bigint
  outputScript?: Script // Output script (scriptPubKey) for sighash calculation
  stack?: Buffer[] // Stack for script execution
}

/**
 * Lotus transactions contain scripts. Each input has a script called the
 * scriptSig, and each output has a script called the scriptPubkey. To validate
 * an input, the input's script is concatenated with the referenced output script,
 * and the result is executed. If at the end of execution the stack contains a
 * "true" value, then the transaction is valid.
 *
 * The primary way to use this class is via the verify function.
 * e.g., Interpreter().verify( ... );
 */
export class Interpreter {
  // Script verification flags
  // Note: Lotus enforces many Bitcoin rules (P2SH, STRICTENC, etc.) as mandatory consensus rules
  // These flags are kept for compatibility, but many are always enforced in Lotus
  // Reference: lotusd/src/script/script_flags.h and lotusd/src/policy/policy.h
  static SCRIPT_VERIFY_NONE = 0

  // Bitcoin compatibility flags (bits 0-15)
  // Note: In Lotus, most of these are always enforced, not optional
  static SCRIPT_VERIFY_P2SH = 1 << 0
  static SCRIPT_VERIFY_STRICTENC = 1 << 1
  static SCRIPT_VERIFY_DERSIG = 1 << 2
  static SCRIPT_VERIFY_LOW_S = 1 << 3
  static SCRIPT_VERIFY_NULLDUMMY = 1 << 4
  static SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5
  static SCRIPT_VERIFY_MINIMALDATA = 1 << 6
  static SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7 // lotusd: same
  static SCRIPT_VERIFY_CLEANSTACK = 1 << 8 // lotusd: same (MANDATORY)
  static SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = 1 << 9
  static SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = 1 << 10
  static SCRIPT_VERIFY_MINIMALIF = 1 << 13 // lotusd: same
  static SCRIPT_VERIFY_NULLFAIL = 1 << 14
  static SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE = 1 << 15

  // Lotus-specific flags (bits 16+)
  // Enables both SIGHASH_FORKID (0x40) and SIGHASH_LOTUS (0x60) signatures
  // Reference: lotusd/src/script/script_flags.h line 47-49
  static SCRIPT_ENABLE_SIGHASH_FORKID = 1 << 16 // lotusd: same (MANDATORY)
  static SCRIPT_ENABLE_REPLAY_PROTECTION = 1 << 17 // lotusd: same
  static SCRIPT_ENABLE_CHECKDATASIG = 1 << 18
  static SCRIPT_DISALLOW_SEGWIT_RECOVERY = 1 << 20
  static SCRIPT_ENABLE_SCHNORR_MULTISIG = 1 << 21
  static SCRIPT_VERIFY_INPUT_SIGCHECKS = 1 << 22 // lotusd: same (STANDARD)

  // Taproot-specific flags
  // Note: lotusd uses bits 0-1 for these, but we use higher bits to avoid conflicts
  static SCRIPT_TAPROOT_KEY_SPEND_PATH = 1 << 23 // lotusd uses 1<<0
  /**
   * @deprecated No longer active as of Winter Solstice 2025 (Second Samuel)
   */
  static SCRIPT_DISABLE_TAPROOT_SIGHASH_LOTUS = 1 << 24 // lotusd uses 1<<1 (STANDARD)

  // Constants
  static MAX_SCRIPT_ELEMENT_SIZE = 520
  static MAX_SCRIPT_SIZE = 10000
  static MAX_STACK_SIZE = 1000
  static MAX_OPCODE_COUNT = 201

  // Stack constants
  static false = Buffer.from([0])
  static true = Buffer.from([1])

  // Additional constants from reference
  static MAXIMUM_ELEMENT_SIZE = 4
  static LOCKTIME_THRESHOLD = 500000000
  static LOCKTIME_THRESHOLD_BN = new BN(500000000)

  // Sequence locktime flags
  static SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
  static SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
  static SEQUENCE_LOCKTIME_MASK = 0x0000ffff

  // Instance properties
  script!: Script
  tx?: Transaction
  nin?: number
  flags!: number
  satoshisBN?: bigint
  outputScript?: Script // Output script (scriptPubKey) for sighash calculation
  stack: Buffer[] = []
  altstack: Buffer[] = []
  pc: number = 0
  pbegincodehash: number = 0
  nOpCount: number = 0
  vfExec: boolean[] = []
  errstr: string = ''

  constructor(obj?: InterpreterObject) {
    this.initialize()
    if (obj) {
      this.set(obj)
    }
  }

  // Factory function to allow calling Interpreter() without 'new'
  static create(obj?: InterpreterObject): Interpreter {
    return new Interpreter(obj)
  }

  /**
   * Initialize the interpreter state
   */
  initialize(): void {
    this.stack = []
    this.altstack = []
    this.pc = 0
    this.pbegincodehash = 0
    this.nOpCount = 0
    this.vfExec = []
    this.errstr = ''
    this.flags = Interpreter.SCRIPT_VERIFY_NONE
  }

  /**
   * Set interpreter properties
   */
  set(obj: InterpreterObject): Interpreter {
    this.script = obj.script || this.script
    this.tx = obj.tx || this.tx
    this.nin = obj.nin !== undefined ? obj.nin : this.nin
    this.flags = obj.flags !== undefined ? obj.flags : this.flags
    this.satoshisBN = obj.satoshisBN || this.satoshisBN
    this.outputScript = obj.outputScript || this.outputScript
    this.stack = obj.stack || this.stack
    return this
  }

  /**
   * Verifies a Script by executing it and returns true if it is valid.
   * This function needs to be provided with the scriptSig and the scriptPubkey
   * separately.
   * @param {Script} scriptSig - the script's first part (corresponding to the tx input)
   * @param {Script} scriptPubkey - the script's last part (corresponding to the tx output)
   * @param {Transaction=} tx - the Transaction containing the scriptSig in one input
   * @param {number} nin - index of the transaction input containing the scriptSig verified.
   * @param {number} flags - evaluation flags. See Interpreter.SCRIPT_* constants
   * @param {bigint} satoshisBN - amount in satoshis of the input to be verified
   */
  verify(
    scriptSig: Script,
    scriptPubkey: Script,
    tx: Transaction,
    nin: number,
    flags: number,
    satoshisBN: bigint,
  ): boolean {
    Preconditions.checkArgument(
      scriptSig instanceof Script,
      'scriptSig',
      'Must be a Script',
    )
    Preconditions.checkArgument(
      scriptPubkey instanceof Script,
      'scriptPubkey',
      'Must be a Script',
    )

    // If FORKID is enabled, we also ensure strict encoding
    if (flags && (flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID) !== 0) {
      flags |= Interpreter.SCRIPT_VERIFY_STRICTENC

      // If FORKID is enabled, we need the input amount
      if (!satoshisBN) {
        throw new Error(
          'internal error - need satoshisBN to verify FORKID transactions',
        )
      }
    }

    this.set({
      script: scriptSig,
      tx: tx,
      nin: nin,
      flags: flags,
      satoshisBN: satoshisBN,
    })

    let stackCopy: Buffer[] = []

    // Check for sig push only
    if ((this.flags & Interpreter.SCRIPT_VERIFY_SIGPUSHONLY) !== 0) {
      if (!scriptSig.isPushOnly()) {
        this.errstr = 'SCRIPT_ERR_SIG_PUSHONLY'
        return false
      }
    }

    // Evaluate scriptSig first
    if (!this.evaluate()) {
      return false
    }

    // Store stack for P2SH if needed
    if (this.flags & Interpreter.SCRIPT_VERIFY_P2SH) {
      stackCopy = this.stack.slice()
    }

    // Store the stack from scriptSig execution
    const stack = this.stack

    // Initialize for scriptPubkey evaluation
    this.initialize()
    this.script = scriptPubkey
    this.stack = stack
    this.tx = tx
    this.nin = nin
    this.flags = flags || Interpreter.SCRIPT_VERIFY_NONE
    this.satoshisBN = satoshisBN

    // Check if scriptPubkey starts with OP_SCRIPTTYPE (e.g., Taproot)
    // Reference: lotusd/src/script/interpreter.cpp lines 2198-2206
    const scriptPubkeyBuf = scriptPubkey.toBuffer()
    if (
      scriptPubkeyBuf.length > 0 &&
      scriptPubkeyBuf[0] === Opcode.OP_SCRIPTTYPE
    ) {
      // Verify script type (Taproot, etc.)
      // validates against the values initialized above
      if (!this._verifyScriptType(scriptPubkey)) {
        return false
      }

      return true
    }

    // Evaluate scriptPubkey with the stack from scriptSig
    if (!this.evaluate()) {
      return false
    }

    // Check final stack
    if (this.stack.length === 0) {
      this.errstr = 'SCRIPT_ERR_EVAL_FALSE_NO_RESULT'
      return false
    }

    const buf = this.stack[this.stack.length - 1]
    if (!Interpreter.castToBool(buf)) {
      this.errstr = 'SCRIPT_ERR_EVAL_FALSE_IN_STACK'
      return false
    }

    // Additional validation for spend-to-script-hash transactions:
    if (
      this.flags & Interpreter.SCRIPT_VERIFY_P2SH &&
      scriptPubkey.isScriptHashOut()
    ) {
      // scriptSig must be literals-only or validation fails
      if (!scriptSig.isPushOnly()) {
        this.errstr = 'SCRIPT_ERR_SIG_PUSHONLY'
        return false
      }

      // stackCopy cannot be empty here, because if it was the
      // P2SH HASH <> EQUAL scriptPubKey would be evaluated with
      // an empty stack and the EvalScript above would return false.
      if (stackCopy.length === 0) {
        throw new Error('internal error - stack copy empty')
      }

      const redeemScriptSerialized = stackCopy[stackCopy.length - 1]
      const redeemScript = Script.fromBuffer(redeemScriptSerialized)
      stackCopy.pop()

      this.initialize()
      this.script = redeemScript
      this.stack = stackCopy
      this.tx = tx
      this.nin = nin
      this.flags = flags || Interpreter.SCRIPT_VERIFY_NONE
      this.satoshisBN = satoshisBN

      // evaluate redeemScript
      if (!this.evaluate()) {
        return false
      }

      if (stackCopy.length === 0) {
        this.errstr = 'SCRIPT_ERR_EVAL_FALSE_NO_P2SH_STACK'
        return false
      }

      if (!Interpreter.castToBool(stackCopy[stackCopy.length - 1])) {
        this.errstr = 'SCRIPT_ERR_EVAL_FALSE_IN_P2SH_STACK'
        return false
      }
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain). The same holds for witness
    // evaluation.
    if ((this.flags & Interpreter.SCRIPT_VERIFY_CLEANSTACK) != 0) {
      // Disallow CLEANSTACK without P2SH, as otherwise a switch
      // CLEANSTACK->P2SH+CLEANSTACK would be possible, which is not a
      // softfork (and P2SH should be one).
      if ((this.flags & Interpreter.SCRIPT_VERIFY_P2SH) == 0) {
        throw new Error('internal error - CLEANSTACK without P2SH')
      }

      if (stackCopy.length != 1) {
        this.errstr = 'SCRIPT_ERR_CLEANSTACK'
        return false
      }
    }

    return true
  }

  /**
   * Check raw signature encoding
   */
  checkRawSignatureEncoding(buf: Buffer): boolean {
    if (buf.length === 0) {
      return true
    }

    // TODO update interpreter.js and necessary functions to match bitcoin-abc interpreter.cpp
    if (Interpreter.isSchnorrSig(buf)) {
      return true
    }

    if (
      (this.flags &
        (Interpreter.SCRIPT_VERIFY_DERSIG |
          Interpreter.SCRIPT_VERIFY_LOW_S |
          Interpreter.SCRIPT_VERIFY_STRICTENC)) !==
        0 &&
      !Signature.isDER(buf)
    ) {
      this.errstr = 'SCRIPT_ERR_SIG_DER_INVALID_FORMAT'
      return false
    } else if ((this.flags & Interpreter.SCRIPT_VERIFY_LOW_S) !== 0) {
      // Note: buf here is DER only (without hashtype byte)
      const sig = Signature.fromDER(buf, false)
      if (!sig.hasLowS()) {
        this.errstr = 'SCRIPT_ERR_SIG_DER_HIGH_S'
        return false
      }
    }

    return true
  }

  /**
   * Check signature encoding
   */
  checkSignatureEncoding(buf: Buffer): boolean {
    if (buf.length === 0) {
      return true
    }

    try {
      const sig = Signature.fromDER(buf)

      // Check for high S values
      if ((this.flags & Interpreter.SCRIPT_VERIFY_LOW_S) !== 0) {
        if (
          sig.s >
          new BN(
            '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0',
            16,
          )
        ) {
          this.errstr = 'SCRIPT_ERR_SIG_DER_HIGH_S'
          return false
        }
      }

      // Check hash type
      const hashType = buf[buf.length - 1]
      if (hashType < 0x80 || hashType > 0x84) {
        this.errstr = 'SCRIPT_ERR_SIG_HASHTYPE'
        return false
      }

      // Check fork ID
      if ((this.flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID) !== 0) {
        if ((hashType & 0x40) === 0) {
          this.errstr = 'SCRIPT_ERR_ILLEGAL_FORKID'
          return false
        }
      } else {
        if ((hashType & 0x40) !== 0) {
          this.errstr = 'SCRIPT_ERR_MUST_USE_FORKID'
          return false
        }
      }

      return true
    } catch (e) {
      this.errstr = 'SCRIPT_ERR_SIG_DER_INVALID_FORMAT'
      return false
    }
  }

  /**
   * Check transaction signature encoding
   */
  checkTxSignatureEncoding(buf: Buffer): boolean {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (buf.length === 0) {
      return true
    }

    if (!this.checkRawSignatureEncoding(buf.subarray(0, buf.length - 1))) {
      return false
    }

    if ((this.flags & Interpreter.SCRIPT_VERIFY_STRICTENC) !== 0) {
      const sig = Signature.fromTxFormat(buf)

      if (!sig.hasDefinedHashtype()) {
        this.errstr = 'SCRIPT_ERR_SIG_HASHTYPE'
        return false
      }

      // Skip FORKID checks for Taproot key path spending
      const isTaprootKeyPath =
        (this.flags & Interpreter.SCRIPT_TAPROOT_KEY_SPEND_PATH) !== 0

      if (!isTaprootKeyPath) {
        if (
          !(this.flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID) &&
          sig.nhashtype! & Signature.SIGHASH_FORKID
        ) {
          this.errstr = 'SCRIPT_ERR_ILLEGAL_FORKID'
          return false
        }

        if (
          this.flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID &&
          !(sig.nhashtype! & Signature.SIGHASH_FORKID)
        ) {
          this.errstr = 'SCRIPT_ERR_MUST_USE_FORKID'
          return false
        }
      }
    }

    return true
  }

  /**
   * Check data signature encoding
   */
  checkDataSignatureEncoding(buf: Buffer): boolean {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (buf.length === 0) {
      return true
    }

    return this.checkRawSignatureEncoding(buf)
  }

  /**
   * Check public key encoding
   */
  checkPubkeyEncoding(buf: Buffer): boolean {
    if ((this.flags & Interpreter.SCRIPT_VERIFY_STRICTENC) !== 0) {
      if (
        !PublicKey.isValid(buf) &&
        !this.isCompressedOrUncompressedPubkey(buf)
      ) {
        this.errstr = 'SCRIPT_ERR_PUBKEYTYPE'
        return false
      }
    }
    return true
  }

  /**
   * Check if buffer is compressed or uncompressed public key
   */
  private isCompressedOrUncompressedPubkey(buf: Buffer): boolean {
    if (buf.length === 33) {
      return buf[0] === 0x02 || buf[0] === 0x03
    }
    if (buf.length === 65) {
      return buf[0] === 0x04
    }
    return false
  }

  /**
   * Evaluate the script
   */
  evaluate(): boolean {
    if (this.script.toBuffer().length > Interpreter.MAX_SCRIPT_SIZE) {
      this.errstr = 'SCRIPT_ERR_SCRIPT_SIZE'
      return false
    }

    try {
      while (this.pc < this.script.chunks.length) {
        if (this.stack.length > Interpreter.MAX_STACK_SIZE) {
          this.errstr = 'SCRIPT_ERR_STACK_SIZE'
          return false
        }

        if (!this.step()) {
          return false
        }
      }

      // Size limits
      if (
        this.stack.length + this.altstack.length >
        Interpreter.MAX_STACK_SIZE
      ) {
        this.errstr = 'SCRIPT_ERR_STACK_SIZE'
        return false
      }

      // Check for unbalanced conditionals
      if (this.vfExec.length > 0) {
        this.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
        return false
      }

      return true
    } catch (e) {
      this.errstr = 'SCRIPT_ERR_UNKNOWN_ERROR: ' + (e as Error).message
      return false
    }
  }

  /**
   * Convert a number to script number buffer
   */
  private toScriptNumBuffer(value: number | bigint): Buffer {
    const num = typeof value === 'bigint' ? value : BigInt(value)
    if (num === 0n) {
      return Buffer.alloc(0)
    }

    const isNegative = num < 0n
    const absNum = isNegative ? -num : num

    // Convert to little-endian bytes
    const bytes: number[] = []
    let temp = absNum
    while (temp > 0n) {
      bytes.push(Number(temp & 0xffn))
      temp >>= 8n
    }

    // Add sign bit if negative
    if (isNegative) {
      if (bytes.length > 0 && (bytes[bytes.length - 1] & 0x80) !== 0) {
        bytes.push(0x80)
      } else if (bytes.length > 0) {
        bytes[bytes.length - 1] |= 0x80
      } else {
        bytes.push(0x80)
      }
    }

    return Buffer.from(bytes)
  }

  /**
   * Convert script number buffer to bigint
   */
  private fromScriptNumBuffer(buf: Buffer): bigint {
    if (buf.length === 0) {
      return 0n
    }

    let result = 0n
    for (let i = 0; i < buf.length; i++) {
      result |= BigInt(buf[i]) << BigInt(i * 8)
    }

    // Check for negative
    if (buf.length > 0 && (buf[buf.length - 1] & 0x80) !== 0) {
      // Clear the sign bit
      const lastByte = buf[buf.length - 1] & 0x7f
      result =
        (result & ~(0xffn << BigInt((buf.length - 1) * 8))) |
        (BigInt(lastByte) << BigInt((buf.length - 1) * 8))
      result = -result
    }

    return result
  }

  /**
   * Cast buffer to boolean
   */
  private castToBool(buf: Buffer): boolean {
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] !== 0) {
        // Check for negative zero
        if (i === buf.length - 1 && buf[i] === 0x80) {
          return false
        }
        return true
      }
    }
    return false
  }

  /**
   * Execute one step of the script
   */
  step(): boolean {
    // This is a simplified version - the full implementation would be very long
    // For now, we'll implement basic opcode handling

    if (this.pc >= this.script.chunks.length) {
      return true
    }

    const chunk = this.script.chunks[this.pc]
    this.pc++
    const opcodenum = chunk.opcodenum

    if (opcodenum === undefined) {
      this.errstr = 'SCRIPT_ERR_UNDEFINED_OPCODE'
      return false
    }

    if (chunk.buf && chunk.buf.length > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
      this.errstr = 'SCRIPT_ERR_PUSH_SIZE'
      return false
    }

    // Count opcodes
    if (
      opcodenum > Opcode.OP_16 &&
      ++this.nOpCount > Interpreter.MAX_OPCODE_COUNT
    ) {
      this.errstr = 'SCRIPT_ERR_OP_COUNT'
      return false
    }

    // Check if opcode is disabled
    if (this.isOpcodeDisabled(opcodenum)) {
      this.errstr = 'SCRIPT_ERR_DISABLED_OPCODE'
      return false
    }

    const fRequireMinimal =
      (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA) !== 0
    const fExec = this.vfExec.indexOf(false) === -1

    // Handle push data
    if (fExec && opcodenum >= 0 && opcodenum <= Opcode.OP_PUSHDATA4) {
      if (fRequireMinimal && !this.script.checkMinimalPush(this.pc - 1)) {
        this.errstr = 'SCRIPT_ERR_MINIMALDATA'
        return false
      }
      if (!chunk.buf) {
        this.stack.push(Interpreter.false)
      } else if (chunk.len !== chunk.buf.length) {
        throw new Error('Length of push value not equal to length of data')
      } else {
        this.stack.push(chunk.buf)
      }
    } else if (
      fExec ||
      (Opcode.OP_IF <= opcodenum && opcodenum <= Opcode.OP_ENDIF)
    ) {
      // Handle opcodes
      switch (opcodenum) {
        // Push values
        case Opcode.OP_1NEGATE: {
          this.stack.push(this.toScriptNumBuffer(-1))
          break
        }

        case Opcode.OP_1:
        case Opcode.OP_2:
        case Opcode.OP_3:
        case Opcode.OP_4:
        case Opcode.OP_5:
        case Opcode.OP_6:
        case Opcode.OP_7:
        case Opcode.OP_8:
        case Opcode.OP_9:
        case Opcode.OP_10:
        case Opcode.OP_11:
        case Opcode.OP_12:
        case Opcode.OP_13:
        case Opcode.OP_14:
        case Opcode.OP_15:
        case Opcode.OP_16: {
          const value = opcodenum - Opcode.OP_1 + 1
          this.stack.push(this.toScriptNumBuffer(value))
          break
        }

        // Control flow
        case Opcode.OP_NOP:
        case Opcode.OP_NOP1:
        case Opcode.OP_NOP4:
        case Opcode.OP_NOP5:
        case Opcode.OP_NOP6:
        case Opcode.OP_NOP7:
        case Opcode.OP_NOP8:
        case Opcode.OP_NOP9:
        case Opcode.OP_NOP10: {
          if (
            this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
          ) {
            this.errstr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS'
            return false
          }
          break
        }

        case Opcode.OP_NOP2:
        case Opcode.OP_CHECKLOCKTIMEVERIFY: {
          if (!(this.flags & Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
            // not enabled; treat as a NOP2
            if (
              this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
            ) {
              this.errstr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS'
              return false
            }
            break
          }

          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          // Note that elsewhere numeric opcodes are limited to
          // operands in the range -2**31+1 to 2**31-1, however it is
          // legal for opcodes to produce results exceeding that
          // range. This limitation is implemented by CScriptNum's
          // default 4-byte limit.
          //
          // If we kept to that limit we'd have a year 2038 problem,
          // even though the nLockTime field in transactions
          // themselves is uint32 which only becomes meaningless
          // after the year 2106.
          //
          // Thus as a special case we tell CScriptNum to accept up
          // to 5-byte bignums, which are good until 2**39-1, well
          // beyond the 2**32-1 limit of the nLockTime field itself.
          const fRequireMinimal =
            (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA) !== 0
          const nLockTime = BN.fromScriptNumBuffer(
            this.stack[this.stack.length - 1],
            fRequireMinimal,
            5,
          )

          // In the rare event that the argument may be < 0 due to
          // some arithmetic being done first, you can always use
          // 0 MAX CHECKLOCKTIMEVERIFY.
          if (nLockTime.lt(new BN(0))) {
            this.errstr = 'SCRIPT_ERR_NEGATIVE_LOCKTIME'
            return false
          }

          // Actually compare the specified lock time with the transaction.
          if (!this.checkLockTime(nLockTime)) {
            this.errstr = 'SCRIPT_ERR_UNSATISFIED_LOCKTIME'
            return false
          }
          break
        }

        case Opcode.OP_NOP3:
        case Opcode.OP_CHECKSEQUENCEVERIFY: {
          if (!(this.flags & Interpreter.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
            // not enabled; treat as a NOP3
            if (
              this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
            ) {
              this.errstr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS'
              return false
            }
            break
          }

          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          // nSequence, like nLockTime, is a 32-bit unsigned
          // integer field. See the comment in CHECKLOCKTIMEVERIFY
          // regarding 5-byte numeric operands.
          const fRequireMinimal =
            (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA) !== 0
          const nSequence = BN.fromScriptNumBuffer(
            this.stacktop(-1),
            fRequireMinimal,
            5,
          )

          // In the rare event that the argument may be < 0 due to
          // some arithmetic being done first, you can always use
          // 0 MAX CHECKSEQUENCEVERIFY.
          if (nSequence.lt(new BN(0))) {
            this.errstr = 'SCRIPT_ERR_NEGATIVE_LOCKTIME'
            return false
          }

          // To provide for future soft-fork extensibility, if the
          // operand has the disabled lock-time flag set,
          // CHECKSEQUENCEVERIFY behaves as a NOP.
          if (
            !nSequence.and(Interpreter.SEQUENCE_LOCKTIME_DISABLE_FLAG).isZero()
          ) {
            break
          }

          // Actually compare the specified lock time with the transaction.
          if (!this.checkSequence(nSequence)) {
            this.errstr = 'SCRIPT_ERR_UNSATISFIED_LOCKTIME'
            return false
          }
          break
        }

        case Opcode.OP_IF:
        case Opcode.OP_NOTIF: {
          let fValue = false
          if (fExec) {
            if (this.stack.length < 1) {
              this.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
              return false
            }
            const buf = this.stacktop(-1)

            if (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALIF) {
              if (buf.length > 1) {
                this.errstr = 'SCRIPT_ERR_MINIMALIF'
                return false
              }
              if (buf.length == 1 && buf[0] != 1) {
                this.errstr = 'SCRIPT_ERR_MINIMALIF'
                return false
              }
            }
            fValue = Interpreter.castToBool(buf)
            if (opcodenum === Opcode.OP_NOTIF) {
              fValue = !fValue
            }
            this.stack.pop()
          }
          this.vfExec.push(fValue)
          break
        }

        case Opcode.OP_ELSE: {
          if (this.vfExec.length === 0) {
            this.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
            return false
          }
          this.vfExec[this.vfExec.length - 1] =
            !this.vfExec[this.vfExec.length - 1]
          break
        }

        case Opcode.OP_ENDIF: {
          if (this.vfExec.length === 0) {
            this.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
            return false
          }
          this.vfExec.pop()
          break
        }

        case Opcode.OP_VERIFY: {
          // (true -- ) or
          // (false -- false) and return
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const buf = this.stacktop(-1)
          const fValue = Interpreter.castToBool(buf)
          if (fValue) {
            this.stack.pop()
          } else {
            this.errstr = 'SCRIPT_ERR_VERIFY'
            return false
          }
          break
        }

        case Opcode.OP_RETURN:
          this.errstr = 'SCRIPT_ERR_OP_RETURN'
          return false

        // Stack manipulation
        case Opcode.OP_TOALTSTACK: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          this.altstack.push(this.stack.pop()!)
          break
        }

        case Opcode.OP_FROMALTSTACK: {
          if (this.altstack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_ALTSTACK_OPERATION'
            return false
          }
          this.stack.push(this.altstack.pop()!)
          break
        }

        case Opcode.OP_2DROP: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          this.stack.pop()
          this.stack.pop()
          break
        }

        case Opcode.OP_2DUP: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const x1 = this.stack[this.stack.length - 2]
          const x2 = this.stack[this.stack.length - 1]
          this.stack.push(x1)
          this.stack.push(x2)
          break
        }

        case Opcode.OP_3DUP: {
          if (this.stack.length < 3) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const x1 = this.stack[this.stack.length - 3]
          const x2 = this.stack[this.stack.length - 2]
          const x3 = this.stack[this.stack.length - 1]
          this.stack.push(x1)
          this.stack.push(x2)
          this.stack.push(x3)
          break
        }

        case Opcode.OP_2OVER: {
          if (this.stack.length < 4) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const x1 = this.stack[this.stack.length - 4]
          const x2 = this.stack[this.stack.length - 3]
          this.stack.push(x1)
          this.stack.push(x2)
          break
        }

        case Opcode.OP_2ROT: {
          if (this.stack.length < 6) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const x1 = this.stack.splice(this.stack.length - 6, 1)[0]
          const x2 = this.stack.splice(this.stack.length - 5, 1)[0]
          this.stack.push(x1)
          this.stack.push(x2)
          break
        }

        case Opcode.OP_2SWAP: {
          if (this.stack.length < 4) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const x1 = this.stack[this.stack.length - 4]
          const x2 = this.stack[this.stack.length - 3]
          const x3 = this.stack[this.stack.length - 2]
          const x4 = this.stack[this.stack.length - 1]
          this.stack[this.stack.length - 4] = x3
          this.stack[this.stack.length - 3] = x4
          this.stack[this.stack.length - 2] = x1
          this.stack[this.stack.length - 1] = x2
          break
        }

        // OP_IFDUP is disabled in Lotus (lotusd/src/script/interpreter.cpp line 90)
        // case Opcode.OP_IFDUP removed

        case Opcode.OP_DEPTH: {
          this.stack.push(this.toScriptNumBuffer(this.stack.length))
          break
        }

        case Opcode.OP_DROP: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          this.stack.pop()
          break
        }

        case Opcode.OP_DUP: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          this.stack.push(this.stack[this.stack.length - 1])
          break
        }

        case Opcode.OP_NIP: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          this.stack.splice(this.stack.length - 2, 1)
          break
        }

        case Opcode.OP_OVER: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          this.stack.push(this.stack[this.stack.length - 2])
          break
        }

        case Opcode.OP_PICK:
        case Opcode.OP_ROLL: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const n = this.fromScriptNumBuffer(this.stack[this.stack.length - 1])
          this.stack.pop()
          if (n < 0n || n >= BigInt(this.stack.length)) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const val = this.stack[this.stack.length - 1 - Number(n)]
          if (opcodenum === Opcode.OP_ROLL) {
            this.stack.splice(this.stack.length - 1 - Number(n), 1)
          }
          this.stack.push(val)
          break
        }

        case Opcode.OP_ROT: {
          if (this.stack.length < 3) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const x1 = this.stack[this.stack.length - 3]
          const x2 = this.stack[this.stack.length - 2]
          const x3 = this.stack[this.stack.length - 1]
          this.stack[this.stack.length - 3] = x2
          this.stack[this.stack.length - 2] = x3
          this.stack[this.stack.length - 1] = x1
          break
        }

        case Opcode.OP_SWAP: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const x1 = this.stack[this.stack.length - 2]
          const x2 = this.stack[this.stack.length - 1]
          this.stack[this.stack.length - 2] = x2
          this.stack[this.stack.length - 1] = x1
          break
        }

        case Opcode.OP_TUCK: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const x1 = this.stack[this.stack.length - 2]
          const x2 = this.stack[this.stack.length - 1]
          this.stack.splice(this.stack.length - 2, 0, x2)
          break
        }

        case Opcode.OP_SIZE: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const size = this.stack[this.stack.length - 1].length
          this.stack.push(this.toScriptNumBuffer(size))
          break
        }

        // Bitwise operations
        case Opcode.OP_AND:
        case Opcode.OP_OR:
        case Opcode.OP_XOR: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const buf1 = this.stack.pop()!
          const buf2 = this.stack.pop()!

          if (buf1.length !== buf2.length) {
            this.errstr = 'SCRIPT_ERR_INVALID_OPERAND_SIZE'
            return false
          }

          const result = Buffer.alloc(buf1.length)
          for (let i = 0; i < buf1.length; i++) {
            switch (opcodenum) {
              case Opcode.OP_AND:
                result[i] = buf1[i] & buf2[i]
                break
              case Opcode.OP_OR:
                result[i] = buf1[i] | buf2[i]
                break
              case Opcode.OP_XOR:
                result[i] = buf1[i] ^ buf2[i]
                break
            }
          }
          this.stack.push(result)
          break
        }

        // Comparison operations
        case Opcode.OP_EQUAL:
        case Opcode.OP_EQUALVERIFY: {
          // (x1 x2 - bool)
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const buf1 = this.stacktop(-2)
          const buf2 = this.stacktop(-1)
          const fEqual = buf1.toString('hex') === buf2.toString('hex')
          this.stack.pop()
          this.stack.pop()
          this.stack.push(fEqual ? Interpreter.true : Interpreter.false)
          if (opcodenum === Opcode.OP_EQUALVERIFY) {
            if (fEqual) {
              this.stack.pop()
            } else {
              this.errstr = 'SCRIPT_ERR_EQUALVERIFY'
              return false
            }
          }
          break
        }

        // Arithmetic operations
        case Opcode.OP_1ADD: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn = this.fromScriptNumBuffer(this.stack[this.stack.length - 1])
          this.stack[this.stack.length - 1] = this.toScriptNumBuffer(bn + 1n)
          break
        }

        case Opcode.OP_1SUB: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn = this.fromScriptNumBuffer(this.stack[this.stack.length - 1])
          this.stack[this.stack.length - 1] = this.toScriptNumBuffer(bn - 1n)
          break
        }

        case Opcode.OP_NEGATE: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn = this.fromScriptNumBuffer(this.stack[this.stack.length - 1])
          this.stack[this.stack.length - 1] = this.toScriptNumBuffer(-bn)
          break
        }

        case Opcode.OP_ABS: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn = this.fromScriptNumBuffer(this.stack[this.stack.length - 1])
          this.stack[this.stack.length - 1] = this.toScriptNumBuffer(
            bn < 0n ? -bn : bn,
          )
          break
        }

        case Opcode.OP_NOT: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn = this.fromScriptNumBuffer(this.stack[this.stack.length - 1])
          this.stack[this.stack.length - 1] = this.toScriptNumBuffer(
            bn === 0n ? 1n : 0n,
          )
          break
        }

        case Opcode.OP_0NOTEQUAL: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn = this.fromScriptNumBuffer(this.stack[this.stack.length - 1])
          this.stack[this.stack.length - 1] = this.toScriptNumBuffer(
            bn !== 0n ? 1n : 0n,
          )
          break
        }

        case Opcode.OP_ADD: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          this.stack.push(this.toScriptNumBuffer(bn1 + bn2))
          break
        }

        case Opcode.OP_SUB: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          this.stack.push(this.toScriptNumBuffer(bn2 - bn1))
          break
        }

        case Opcode.OP_BOOLAND: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          const result = bn1 !== 0n && bn2 !== 0n ? 1n : 0n
          this.stack.push(this.toScriptNumBuffer(result))
          break
        }

        case Opcode.OP_BOOLOR: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          const result = bn1 !== 0n || bn2 !== 0n ? 1n : 0n
          this.stack.push(this.toScriptNumBuffer(result))
          break
        }

        // OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL are disabled in Lotus
        // (lotusd/src/script/interpreter.cpp lines 97-99)

        case Opcode.OP_LESSTHAN: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          const result = bn2 < bn1 ? 1n : 0n
          this.stack.push(this.toScriptNumBuffer(result))
          break
        }

        case Opcode.OP_GREATERTHAN: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          const result = bn2 > bn1 ? 1n : 0n
          this.stack.push(this.toScriptNumBuffer(result))
          break
        }

        case Opcode.OP_LESSTHANOREQUAL: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          const result = bn2 <= bn1 ? 1n : 0n
          this.stack.push(this.toScriptNumBuffer(result))
          break
        }

        case Opcode.OP_GREATERTHANOREQUAL: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          const result = bn2 >= bn1 ? 1n : 0n
          this.stack.push(this.toScriptNumBuffer(result))
          break
        }

        case Opcode.OP_MIN: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          const result = bn1 < bn2 ? bn1 : bn2
          this.stack.push(this.toScriptNumBuffer(result))
          break
        }

        case Opcode.OP_MAX: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!)
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!)
          const result = bn1 > bn2 ? bn1 : bn2
          this.stack.push(this.toScriptNumBuffer(result))
          break
        }

        case Opcode.OP_WITHIN: {
          if (this.stack.length < 3) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const bn1 = this.fromScriptNumBuffer(this.stack.pop()!) // upper bound
          const bn2 = this.fromScriptNumBuffer(this.stack.pop()!) // lower bound
          const bn3 = this.fromScriptNumBuffer(this.stack.pop()!) // value
          const result = bn3 >= bn2 && bn3 < bn1 ? 1n : 0n
          this.stack.push(this.toScriptNumBuffer(result))
          break
        }

        // Hash operations
        case Opcode.OP_RIPEMD160: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const buf = this.stack.pop()!
          this.stack.push(Hash.ripemd160(buf))
          break
        }

        // OP_SHA1 is disabled in Lotus (lotusd/src/script/interpreter.cpp line 100)

        case Opcode.OP_SHA256: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const buf = this.stack.pop()!
          this.stack.push(Hash.sha256(buf))
          break
        }

        case Opcode.OP_HASH160: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const buf = this.stack.pop()!
          this.stack.push(Hash.sha256ripemd160(buf))
          break
        }

        case Opcode.OP_HASH256: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const buf = this.stack.pop()!
          this.stack.push(Hash.sha256sha256(buf))
          break
        }

        case Opcode.OP_CODESEPARATOR: {
          // Hash starts after the code separator
          this.pbegincodehash = this.pc
          break
        }

        case Opcode.OP_CHECKDATASIG:
        case Opcode.OP_CHECKDATASIGVERIFY: {
          // (sig message pubkey -- bool)
          if (this.stack.length < 3) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          const bufSig = this.stacktop(-3)
          const bufMessage = this.stacktop(-2)
          const bufPubkey = this.stacktop(-1)

          if (
            !this.checkDataSignatureEncoding(bufSig) ||
            !this.checkPubkeyEncoding(bufPubkey)
          ) {
            return false
          }

          let fSuccess = false

          try {
            const sig = Signature.fromDataFormat(bufSig)
            const pubkey = new PublicKey(bufPubkey)
            const bufHash = Hash.sha256(bufMessage)
            if (!sig.isSchnorr) {
              fSuccess = ECDSA.verify(bufHash, sig, pubkey, 'big')
            } else {
              fSuccess = Schnorr.verify(bufHash, sig, pubkey, 'big')
            }
          } catch (e) {
            // invalid sig or pubkey
            fSuccess = false
          }

          if (
            !fSuccess &&
            this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL &&
            bufSig.length
          ) {
            this.errstr = 'SCRIPT_ERR_NULLFAIL'
            return false
          }

          this.stack.pop()
          this.stack.pop()
          this.stack.pop()

          this.stack.push(fSuccess ? Interpreter.true : Interpreter.false)
          if (opcodenum === Opcode.OP_CHECKDATASIGVERIFY) {
            if (fSuccess) {
              this.stack.pop()
            } else {
              this.errstr = 'SCRIPT_ERR_CHECKDATASIGVERIFY'
              return false
            }
          }
          break
        }

        case Opcode.OP_REVERSEBYTES: {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          const buf = this.stacktop(-1)
          const reversedBuf = Buffer.from(buf).reverse()
          this.stack.pop()
          this.stack.push(reversedBuf)
          break
        }

        case Opcode.OP_CHECKSIG: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          const sigBuf = this.stack[this.stack.length - 2]
          const pubkeyBuf = this.stack[this.stack.length - 1]

          if (
            !this.checkTxSignatureEncoding(sigBuf) ||
            !this.checkPubkeyEncoding(pubkeyBuf)
          ) {
            return false
          }

          // Subset of script starting at the most recent codeseparator
          const subscript = new Script()
          subscript.chunks = this.script.chunks.slice(this.pbegincodehash)

          // Drop the signature, since there's no way for a signature to sign itself
          const tmpScript = new Script().add(sigBuf)
          subscript.findAndDelete(tmpScript)

          let fSuccess = false

          try {
            const signature = Signature.fromTxFormat(sigBuf)
            const pubkey = new PublicKey(pubkeyBuf)

            if (
              this.tx &&
              this.nin !== undefined &&
              this.satoshisBN !== undefined
            ) {
              if (!signature.isSchnorr) {
                fSuccess = this.tx.verifySignature(
                  signature,
                  pubkey,
                  this.nin,
                  subscript,
                  new BN(this.satoshisBN.toString()),
                  this.flags,
                )
              } else {
                fSuccess = this.tx.verifySignature(
                  signature,
                  pubkey,
                  this.nin,
                  subscript,
                  new BN(this.satoshisBN.toString()),
                  this.flags,
                  'schnorr',
                )
              }
            }
          } catch (e) {
            // Invalid sig or pubkey
            fSuccess = false
          }

          if (
            !fSuccess &&
            this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL &&
            sigBuf.length
          ) {
            this.errstr = 'SCRIPT_ERR_NULLFAIL'
            return false
          }

          this.stack.pop()
          this.stack.pop()
          this.stack.push(fSuccess ? Interpreter.true : Interpreter.false)
          break
        }

        case Opcode.OP_CHECKSIGVERIFY: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          const sigBuf2 = this.stack[this.stack.length - 2]
          const pubkeyBuf2 = this.stack[this.stack.length - 1]

          if (
            !this.checkTxSignatureEncoding(sigBuf2) ||
            !this.checkPubkeyEncoding(pubkeyBuf2)
          ) {
            return false
          }

          // Subset of script starting at the most recent codeseparator
          const subscript2 = new Script()
          subscript2.chunks = this.script.chunks.slice(this.pbegincodehash)

          // Drop the signature, since there's no way for a signature to sign itself
          const tmpScript2 = new Script().add(sigBuf2)
          subscript2.findAndDelete(tmpScript2)

          let fSuccess2 = false

          try {
            const signature = Signature.fromTxFormat(sigBuf2)
            const pubkey = new PublicKey(pubkeyBuf2)

            if (
              this.tx &&
              this.nin !== undefined &&
              this.satoshisBN !== undefined
            ) {
              if (!signature.isSchnorr) {
                fSuccess2 = this.tx.verifySignature(
                  signature,
                  pubkey,
                  this.nin,
                  subscript2,
                  new BN(this.satoshisBN.toString()),
                  this.flags,
                )
              } else {
                fSuccess2 = this.tx.verifySignature(
                  signature,
                  pubkey,
                  this.nin,
                  subscript2,
                  new BN(this.satoshisBN.toString()),
                  this.flags,
                  'schnorr',
                )
              }
            }
          } catch (e) {
            // Invalid sig or pubkey
            fSuccess2 = false
          }

          if (
            !fSuccess2 &&
            this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL &&
            sigBuf2.length
          ) {
            this.errstr = 'SCRIPT_ERR_NULLFAIL'
            return false
          }

          this.stack.pop()
          this.stack.pop()

          if (fSuccess2) {
            // Drop the result (true)
            // Nothing to do
          } else {
            this.errstr = 'SCRIPT_ERR_CHECKSIGVERIFY'
            return false
          }
          break
        }

        case Opcode.OP_CHECKMULTISIG:
        case Opcode.OP_CHECKMULTISIGVERIFY: {
          // ([dummy] [sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

          const fRequireMinimal =
            (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA) !== 0
          let i = 1
          const idxTopKey = i + 1
          if (this.stack.length < i) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          const nKeysCountBN = BN.fromScriptNumBuffer(
            this.stacktop(-i),
            fRequireMinimal,
          )
          let nKeysCount = nKeysCountBN.toNumber()
          const idxSigCount = idxTopKey + nKeysCount
          if (nKeysCount < 0 || nKeysCount > 20) {
            this.errstr = 'SCRIPT_ERR_PUBKEY_COUNT'
            return false
          }
          this.nOpCount += nKeysCount
          if (this.nOpCount > 201) {
            this.errstr = 'SCRIPT_ERR_OP_COUNT'
            return false
          }

          let ikey = ++i // top pubkey
          const idxTopSig = idxSigCount + 1

          i += nKeysCount

          // ikey2 is the position of last non-signature item in
          // the stack. Top stack item = 1. With
          // SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if
          // operation fails.
          let ikey2 = nKeysCount + 2

          if (this.stack.length < i) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          const nSigsCountBN = BN.fromScriptNumBuffer(
            this.stacktop(-idxSigCount),
            fRequireMinimal,
          )
          let nSigsCount = nSigsCountBN.toNumber()
          const idxDummy = idxTopSig + nSigsCount

          if (nSigsCount < 0 || nSigsCount > nKeysCount) {
            this.errstr = 'SCRIPT_ERR_SIG_COUNT'
            return false
          }
          let isig = ++i
          i += nSigsCount
          if (this.stack.length < idxDummy) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          // Subset of script starting at the most recent codeseparator
          const subscript = new Script()
          subscript.chunks = this.script.chunks.slice(this.pbegincodehash)

          let fSuccess = true

          if (
            this.flags & Interpreter.SCRIPT_ENABLE_SCHNORR_MULTISIG &&
            this.stacktop(-idxDummy).length !== 0
          ) {
            // SCHNORR MULTISIG

            const dummy = this.stacktop(-idxDummy)

            const bitfieldObj = this.decodeBitfield(dummy, nKeysCount)

            if (!bitfieldObj.result) {
              fSuccess = false
            }

            const nSigs8bit = new Uint8Array([nSigsCount])
            const nSigs32 = Uint32Array.from(nSigs8bit)

            if (this.countBits(bitfieldObj.bitfield!) !== nSigs32[0]) {
              this.errstr = 'INVALID_BIT_COUNT'
              fSuccess = false
            }

            const bottomKey = idxTopKey + nKeysCount - 1
            const bottomSig = idxTopSig + nSigsCount - 1

            let iKey = 0
            for (let iSig = 0; iSig < nSigsCount; iSig++, iKey++) {
              if (bitfieldObj.bitfield! >> iKey === 0) {
                this.errstr = 'INVALID_BIT_RANGE'
                fSuccess = false
              }

              while (((bitfieldObj.bitfield! >> iKey) & 0x01) == 0) {
                if (iKey >= nKeysCount) {
                  this.errstr = 'wrong'
                  fSuccess = false
                  break
                }
                iKey++
              }

              // this is a sanity check and should be
              // unreachable
              if (iKey >= nKeysCount) {
                this.errstr = 'PUBKEY_COUNT'
                fSuccess = false
              }

              // Check the signature
              const bufsig = this.stacktop(-bottomSig + iSig)
              const bufPubkey = this.stacktop(-bottomKey + iKey)

              // Note that only pubkeys associated with a
              // signature are check for validity

              if (
                !this.checkRawSignatureEncoding(bufsig) ||
                !this.checkPubkeyEncoding(bufPubkey)
              ) {
                fSuccess = false
              }

              try {
                const sig = Signature.fromTxFormat(bufsig)
                const pubkey = new PublicKey(bufPubkey)
                const fOk =
                  this.tx?.verifySignature(
                    sig,
                    pubkey,
                    this.nin!,
                    subscript,
                    new BN(this.satoshisBN!.toString()),
                    this.flags,
                    'schnorr',
                  ) || false

                if (!fOk) {
                  this.errstr = 'SIG_NULLFAIL'
                  fSuccess = false
                }
              } catch (e) {
                fSuccess = false
              }
            }

            if (bitfieldObj.bitfield! >> iKey != 0) {
              // This is a sanity check and should be
              // unreachable.
              this.errstr = 'INVALID_BIT_COUNT'
              fSuccess = false
            }
          } else {
            // LEGACY MULTISIG (ECDSA / NULL)

            // Drop the signatures, since there's no way for a signature to sign itself
            for (let k = 0; k < nSigsCount; k++) {
              const bufSig = this.stacktop(-isig - k)
              subscript.findAndDelete(new Script().add(bufSig))
            }

            while (fSuccess && nSigsCount > 0) {
              const bufSig = this.stacktop(-isig)
              const bufPubkey = this.stacktop(-ikey)

              if (
                !this.checkTxSignatureEncoding(bufSig) ||
                !this.checkPubkeyEncoding(bufPubkey)
              ) {
                return false
              }

              let fOk = false
              try {
                const sig = Signature.fromTxFormat(bufSig)
                const pubkey = new PublicKey(bufPubkey)
                fOk =
                  this.tx?.verifySignature(
                    sig,
                    pubkey,
                    this.nin!,
                    subscript,
                    new BN(this.satoshisBN!.toString()),
                    this.flags,
                  ) || false
              } catch (e) {
                // invalid sig or pubkey
                fOk = false
              }

              if (fOk) {
                isig++
                nSigsCount--
              }
              ikey++
              nKeysCount--

              // If there are more signatures left than keys left,
              // then too many signatures have failed
              if (nSigsCount > nKeysCount) {
                fSuccess = false
              }
            }
          }

          // Clean up stack of actual arguments
          while (i-- > 1) {
            if (
              !fSuccess &&
              this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL &&
              !ikey2 &&
              this.stacktop(-1).length
            ) {
              this.errstr = 'SCRIPT_ERR_NULLFAIL'
              return false
            }

            if (ikey2 > 0) {
              ikey2--
            }

            this.stack.pop()
          }

          // A bug causes CHECKMULTISIG to consume one extra argument
          // whose contents were not checked in any way.
          //
          // Unfortunately this is a potential source of mutability,
          // so optionally verify it is exactly equal to zero prior
          // to removing it from the stack.
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          if (
            this.flags & Interpreter.SCRIPT_VERIFY_NULLDUMMY &&
            this.stacktop(-1).length
          ) {
            this.errstr = 'SCRIPT_ERR_SIG_NULLDUMMY'
            return false
          }
          this.stack.pop()

          this.stack.push(fSuccess ? Interpreter.true : Interpreter.false)

          if (opcodenum === Opcode.OP_CHECKMULTISIGVERIFY) {
            if (fSuccess) {
              this.stack.pop()
            } else {
              this.errstr = 'SCRIPT_ERR_CHECKMULTISIGVERIFY'
              return false
            }
          }
          break
        }

        // Byte string operations
        case Opcode.OP_CAT: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          const buf1 = this.stacktop(-2)
          const buf2 = this.stacktop(-1)
          if (buf1.length + buf2.length > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
            this.errstr = 'SCRIPT_ERR_PUSH_SIZE'
            return false
          }
          this.stack[this.stack.length - 2] = Buffer.concat([buf1, buf2])
          this.stack.pop()
          break
        }

        case Opcode.OP_SPLIT: {
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }
          const fRequireMinimal =
            (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA) !== 0
          const buf1 = this.stacktop(-2)

          // Make sure the split point is appropriate
          const position = BN.fromScriptNumBuffer(
            this.stacktop(-1),
            fRequireMinimal,
          ).toNumber()
          if (position < 0 || position > buf1.length) {
            this.errstr = 'SCRIPT_ERR_INVALID_SPLIT_RANGE'
            return false
          }

          // Prepare the results in their own buffer as `data`
          // will be invalidated.
          // Copy buffer data, to slice it before
          const n1 = Buffer.from(buf1)

          // Replace existing stack values by the new values.
          this.stack[this.stack.length - 2] = n1.subarray(0, position)
          this.stack[this.stack.length - 1] = n1.subarray(position)
          break
        }

        // Conversion operations
        case Opcode.OP_NUM2BIN: {
          // (in size -- out)
          if (this.stack.length < 2) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          const fRequireMinimal =
            (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA) !== 0
          const size = BN.fromScriptNumBuffer(
            this.stacktop(-1),
            fRequireMinimal,
          ).toNumber()
          if (size > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
            this.errstr = 'SCRIPT_ERR_PUSH_SIZE'
            return false
          }

          this.stack.pop()
          let rawnum = this.stacktop(-1)

          // Try to see if we can fit that number in the number of
          // byte requested.
          rawnum = Interpreter._minimallyEncode(rawnum)

          if (rawnum.length > size) {
            // We definitively cannot.
            this.errstr = 'SCRIPT_ERR_IMPOSSIBLE_ENCODING'
            return false
          }

          // We already have an element of the right size, we
          // don't need to do anything.
          if (rawnum.length == size) {
            this.stack[this.stack.length - 1] = rawnum
            break
          }

          let signbit = 0x00
          if (rawnum.length > 0) {
            signbit = rawnum[rawnum.length - 1] & 0x80
            rawnum[rawnum.length - 1] &= 0x7f
          }

          const num = Buffer.alloc(size)
          rawnum.copy(num, 0)

          let l = rawnum.length - 1
          while (l++ < size - 2) {
            num[l] = 0x00
          }

          num[l] = signbit

          this.stack[this.stack.length - 1] = num
          break
        }

        case Opcode.OP_BIN2NUM: {
          // (in -- out)
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
            return false
          }

          const buf1 = this.stacktop(-1)
          const buf2 = Interpreter._minimallyEncode(buf1)

          this.stack[this.stack.length - 1] = buf2

          // The resulting number must be a valid number.
          if (!Interpreter._isMinimallyEncoded(buf2)) {
            this.errstr = 'SCRIPT_ERR_INVALID_NUMBER_RANGE'
            return false
          }
          break
        }

        default:
          this.errstr = 'SCRIPT_ERR_BAD_OPCODE'
          return false
      }
    }

    return true
  }

  /**
   * Helper function for Schnorr multisig - decode bitfield
   */
  private decodeBitfield(
    dummy: Buffer,
    size: number,
  ): { result: boolean; bitfield?: number } {
    if (size > 32) {
      this.errstr = 'INVALID_BITFIELD_SIZE'
      return { result: false }
    }

    const bitfieldSize = Math.floor((size + 7) / 8)
    const dummyBitlength = dummy.length
    if (dummyBitlength !== bitfieldSize) {
      this.errstr = 'INVALID_BITFIELD_SIZE'
      return { result: false }
    }

    let bitfield = 0
    const dummyAs32Bit = Uint32Array.from(dummy)

    for (let i = 0; i < bitfieldSize; i++) {
      bitfield = bitfield | (dummyAs32Bit[i] << (8 * i))
    }

    const mask = (0x01 << size) - 1
    if ((bitfield & mask) != bitfield) {
      this.errstr = 'INVALID_BIT_RANGE'
      return { result: false }
    }

    return { result: true, bitfield: bitfield }
  }

  /**
   * Helper function for Schnorr multisig - count bits
   */
  private countBits(v: number): number {
    /**
     * Computes the number of bits set in each group of 8bits then uses a
     * multiplication to sum all of them in the 8 most significant bits and
     * return these.
     * More detailed explanation can be found at
     * https://www.playingwithpointers.com/blog/swar.html
     */
    v = v - ((v >> 1) & 0x55555555)
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333)
    return (((v + (v >> 4)) & 0xf0f0f0f) * 0x1010101) >> 24
  }

  /**
   * Stack helper - get element from top of stack
   */
  private stacktop(i: number): Buffer {
    return this.stack[this.stack.length + i]
  }

  /**
   * Check if opcode is disabled (matches lotusd/src/script/interpreter.cpp IsOpcodeDisabled)
   */
  private isOpcodeDisabled(opcode: number): boolean {
    switch (opcode) {
      // Disabled opcodes in Lotus
      case 80: // OP_RESERVED
      case 101: // OP_VERIF
      case 102: // OP_VERNOTIF
      case 115: // OP_IFDUP - Disabled in Lotus!
      case Opcode.OP_INVERT:
      case 137: // OP_RESERVED1
      case 138: // OP_RESERVED2
      case Opcode.OP_2MUL:
      case Opcode.OP_2DIV:
      case Opcode.OP_MUL:
      case 156: // OP_NUMEQUAL - Disabled in Lotus!
      case 157: // OP_NUMEQUALVERIFY - Disabled in Lotus!
      case 158: // OP_NUMNOTEQUAL - Disabled in Lotus!
      case 167: // OP_SHA1 - Disabled in Lotus!
      case Opcode.OP_LSHIFT:
      case Opcode.OP_RSHIFT:
        return true

      // Enabled opcodes (re-enabled in BCH Nov 2018, kept in Lotus)
      case Opcode.OP_DIV:
      case Opcode.OP_MOD:
      case Opcode.OP_SPLIT:
      case Opcode.OP_CAT:
      case Opcode.OP_AND:
      case Opcode.OP_OR:
      case Opcode.OP_XOR:
      case Opcode.OP_BIN2NUM:
      case Opcode.OP_NUM2BIN:
        return false

      default:
        // All undefined opcodes (>= 0xbd = 189) are also disabled
        // OP_REVERSEBYTES is 0xbc (188), so first undefined is 0xbd (189)
        if (opcode >= 189) {
          return true
        }
        return false
    }
  }

  /**
   * Check lock time
   */
  checkLockTime(nLockTime: BN): boolean {
    if (!this.tx || this.nin === undefined) {
      return false
    }

    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (
      !(
        (this.tx.nLockTime < Interpreter.LOCKTIME_THRESHOLD &&
          nLockTime.lt(Interpreter.LOCKTIME_THRESHOLD_BN)) ||
        (this.tx.nLockTime >= Interpreter.LOCKTIME_THRESHOLD &&
          nLockTime.gte(Interpreter.LOCKTIME_THRESHOLD_BN))
      )
    ) {
      return false
    }

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime.gt(new BN(this.tx.nLockTime))) {
      return false
    }

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (!this.tx.inputs[this.nin].isFinal()) {
      return false
    }

    return true
  }

  /**
   * Check sequence
   */
  checkSequence(nSequence: BN): boolean {
    if (!this.tx || this.nin === undefined) {
      return false
    }

    // Relative lock times are supported by comparing the passed in operand to
    // the sequence number of the input.
    const txToSequence = this.tx.inputs[this.nin].sequenceNumber

    // Fail if the transaction's version number is not set high enough to
    // trigger BIP 68 rules.
    if (this.tx.version < 2) {
      return false
    }

    // Sequence numbers with their most significant bit set are not consensus
    // constrained. Testing that the transaction's sequence number do not have
    // this bit set prevents using this property to get around a
    // CHECKSEQUENCEVERIFY check.
    if (txToSequence & Interpreter.SEQUENCE_LOCKTIME_DISABLE_FLAG) {
      return false
    }

    // Mask off any bits that do not have consensus-enforced meaning before
    // doing the integer comparisons
    const nLockTimeMask =
      Interpreter.SEQUENCE_LOCKTIME_TYPE_FLAG |
      Interpreter.SEQUENCE_LOCKTIME_MASK
    const txToSequenceMasked = new BN(txToSequence & nLockTimeMask)
    const nSequenceMasked = nSequence.and(nLockTimeMask)

    // There are two kinds of nSequence: lock-by-blockheight and
    // lock-by-blocktime, distinguished by whether nSequenceMasked <
    // CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script unless the type
    // of nSequenceMasked being tested is the same as the nSequenceMasked in the
    // transaction.
    const SEQUENCE_LOCKTIME_TYPE_FLAG_BN = new BN(
      Interpreter.SEQUENCE_LOCKTIME_TYPE_FLAG,
    )

    if (
      !(
        (txToSequenceMasked.lt(SEQUENCE_LOCKTIME_TYPE_FLAG_BN) &&
          nSequenceMasked.lt(SEQUENCE_LOCKTIME_TYPE_FLAG_BN)) ||
        (txToSequenceMasked.gte(SEQUENCE_LOCKTIME_TYPE_FLAG_BN) &&
          nSequenceMasked.gte(SEQUENCE_LOCKTIME_TYPE_FLAG_BN))
      )
    ) {
      return false
    }

    // Now that we know we're comparing apples-to-apples, the comparison is a
    // simple numeric one.
    if (nSequenceMasked.gt(txToSequenceMasked)) {
      return false
    }
    return true
  }

  /**
   * Static method to cast buffer to boolean
   */
  static castToBool(buf: Buffer): boolean {
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] !== 0) {
        // Check for negative zero
        if (i === buf.length - 1 && buf[i] === 0x80) {
          return false
        }
        return true
      }
    }
    return false
  }

  /**
   * Check if buffer is Schnorr signature
   */
  static isSchnorrSig(buf: Buffer): boolean {
    return (buf.length === 64 || buf.length === 65) && buf[0] !== 0x30
  }

  /**
   * Verify script type (dispatches to appropriate handler)
   * Reference: lotusd/src/script/interpreter.cpp lines 2158-2174
   *
   * Note: scriptSig has already been executed and its results are on this.stack
   */
  private _verifyScriptType(scriptPubkey: Script): boolean {
    const buf = scriptPubkey.toBuffer()

    // Must have at least 2 bytes: OP_SCRIPTTYPE + type byte
    if (buf.length < 2) {
      this.errstr = 'SCRIPT_ERR_SCRIPTTYPE_MALFORMED_SCRIPT'
      return false
    }

    // Check script type (second byte)
    const scriptType = buf[1]

    switch (scriptType) {
      case TAPROOT_SCRIPTTYPE: {
        // Taproot script - delegate to taproot module
        const result = verifyTaprootSpend(scriptPubkey, this.stack, this.flags)

        if (!result.success) {
          this.errstr = result.error || 'SCRIPT_ERR_UNKNOWN'
          return false
        }

        // Update stack from verification
        if (result.stack) {
          this.stack = result.stack
        }

        // If there is a script to execute, evaluate it
        if (result.scriptToExecute) {
          const prevScript = this.script
          const prevPc = this.pc
          const prevPbegincodehash = this.pbegincodehash

          this.script = result.scriptToExecute
          this.pc = 0
          this.pbegincodehash = 0

          const evalResult = this.evaluate()

          // Restore state
          this.script = prevScript
          this.pc = prevPc
          this.pbegincodehash = prevPbegincodehash

          if (!evalResult) {
            return false
          }

          // Check final stack
          if (this.stack.length === 0) {
            this.errstr = 'SCRIPT_ERR_EVAL_FALSE_NO_RESULT'
            return false
          }

          const finalBuf = this.stack[this.stack.length - 1]
          if (!Interpreter.castToBool(finalBuf)) {
            this.errstr = 'SCRIPT_ERR_EVAL_FALSE_IN_STACK'
            return false
          }
        } else {
          // Key path spending - verify signature
          const scriptBuf = scriptPubkey.toBuffer()
          const vchPubkey = scriptBuf.subarray(
            TAPROOT_INTRO_SIZE,
            TAPROOT_SIZE_WITHOUT_STATE,
          )
          const vchSig = this.stack[this.stack.length - 1]
          const sigFlags =
            this.flags | Interpreter.SCRIPT_TAPROOT_KEY_SPEND_PATH

          // Check signature and pubkey encoding
          if (
            !this.checkTxSignatureEncoding(vchSig) ||
            !this.checkPubkeyEncoding(vchPubkey)
          ) {
            return false
          }

          // Empty signature fails
          if (vchSig.length === 0) {
            this.errstr = 'SCRIPT_ERR_TAPROOT_VERIFY_SIGNATURE_FAILED'
            return false
          }

          // Verify Schnorr signature with SIGHASH_LOTUS
          const sig = Signature.fromTxFormat(vchSig)
          const pubkey = new PublicKey(vchPubkey)

          if (!sig.isSchnorr) {
            this.errstr = 'SCRIPT_ERR_TAPROOT_KEY_SPEND_SIGNATURE_NOT_SCHNORR'
            return false
          }

          try {
            const isValid = this.tx?.verifySignature(
              sig,
              pubkey,
              this.nin!,
              scriptPubkey, // Use scriptPubkey as subscript for Taproot
              new BN(this.satoshisBN!.toString()),
              sigFlags,
              'schnorr',
            )

            if (!isValid) {
              this.errstr = 'SCRIPT_ERR_TAPROOT_VERIFY_SIGNATURE_FAILED'
              return false
            }
          } catch (e) {
            this.errstr = 'SCRIPT_ERR_TAPROOT_VERIFY_SIGNATURE_FAILED'
            return false
          }
        }

        return true
      }
      // Unknown script type
      default:
        this.errstr = 'SCRIPT_ERR_SCRIPTTYPE_INVALID_TYPE'
        return false
    }
  }

  /**
   * Check if buffer is minimally encoded
   */
  static _isMinimallyEncoded(buf: Buffer, nMaxNumSize?: number): boolean {
    nMaxNumSize = nMaxNumSize || Interpreter.MAXIMUM_ELEMENT_SIZE
    if (buf.length > nMaxNumSize) {
      return false
    }

    if (buf.length > 0) {
      // Check that the number is encoded with the minimum possible number
      // of bytes.
      //
      // If the most-significant-byte - excluding the sign bit - is zero
      // then we're not minimal. Note how this test also rejects the
      // negative-zero encoding, 0x80.
      if ((buf[buf.length - 1] & 0x7f) === 0) {
        // One exception: if there's more than one byte and the most
        // significant bit of the second-most-significant-byte is set it
        // would conflict with the sign bit. An example of this case is
        // +-255, which encode to 0xff00 and 0xff80 respectively.
        // (big-endian).
        if (buf.length <= 1 || (buf[buf.length - 2] & 0x80) === 0) {
          return false
        }
      }
    }
    return true
  }

  /**
   * Minimally encode the buffer content
   */
  static _minimallyEncode(buf: Buffer): Buffer {
    if (buf.length === 0) {
      return buf
    }

    // If the last byte is not 0x00 or 0x80, we are minimally encoded.
    const last = buf[buf.length - 1]
    if (last & 0x7f) {
      return buf
    }

    // If the script is one byte long, then we have a zero, which encodes as an
    // empty array.
    if (buf.length === 1) {
      return Buffer.from('')
    }

    // If the next byte has it sign bit set, then we are minimaly encoded.
    if (buf[buf.length - 2] & 0x80) {
      return buf
    }

    // We are not minimally encoded, we need to figure out how much to trim.
    for (let i = buf.length - 1; i > 0; i--) {
      // We found a non zero byte, time to encode.
      if (buf[i - 1] !== 0) {
        if (buf[i - 1] & 0x80) {
          // We found a byte with it sign bit set so we need one more
          // byte.
          const result = Buffer.alloc(i + 1)
          buf.copy(result, 0, 0, i)
          result[i] = last
          return result
        } else {
          // the sign bit is clear, we can use it.
          const result = Buffer.alloc(i)
          buf.copy(result, 0, 0, i)
          result[i - 1] |= last
          return result
        }
      }
    }

    // If we the whole thing is zeros, then we have a zero.
    return Buffer.from('')
  }
}

/**
 * Copyright 2025-2026 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * Lotus Script Interpreter
 *
 * Client-side script evaluation engine for validating that crafted
 * transactions will pass lotusd consensus checks before broadcasting.
 *
 * This is NOT a consensus implementation. It mirrors lotusd behavior
 * to give wallets confidence that their transactions are well-formed.
 * The authoritative interpreter is always lotusd itself.
 *
 * Architecture:
 * - evalScript(): Executes a single script on a stack
 * - verifyScript(): Orchestrates scriptSig + scriptPubKey evaluation
 * - SignatureChecker interface: Pluggable signature verification
 *
 * Reference: lotusd/src/script/interpreter.cpp
 *
 * @module Interpreter
 */

import { BN, Schnorr, ECDSA, Signature, isSchnorrSignature } from '../../crypto'
import { PublicKey } from '../../publickey'
import { sighash as computeSighash } from '../../transaction/sighash'
import { BufferUtil } from '../../util/buffer'
import { Opcode } from '../../opcode'
import { Hash } from '../../crypto/hash'
import { Script } from '../../script'
import { ConditionStack } from './condition-stack'
import { ScriptNum, ScriptNumError } from './script-num'
import {
  MAX_SCRIPT_ELEMENT_SIZE,
  MAX_OPS_PER_SCRIPT,
  MAX_PUBKEYS_PER_MULTISIG,
  MAX_SCRIPT_SIZE,
  MAX_STACK_SIZE,
  MAX_NUM2BIN_SIZE,
  ScriptError,
  ScriptFlags,
  type ScriptResult,
  type ScriptExecutionMetrics,
  type ScriptExecutionData,
  type SignatureChecker,
} from './types'
import {
  TAPROOT_SCRIPTTYPE,
  TAPROOT_INTRO_SIZE,
  TAPROOT_SIZE_WITHOUT_STATE,
  TAPROOT_SIZE_WITH_STATE,
  TAPROOT_ANNEX_TAG,
  TAPROOT_LEAF_MASK,
  TAPROOT_LEAF_TAPSCRIPT,
  TAPROOT_CONTROL_BASE_SIZE,
  TAPROOT_CONTROL_NODE_SIZE,
  TAPROOT_CONTROL_MAX_SIZE,
  verifyTaprootCommitment,
} from '../taproot'
import type { Buffer } from 'buffer/'

// ─── Stack Helpers ────────────────────────────────────────────────

/** Type alias for stack elements (byte arrays) */
type StackElement = Buffer

/** Access stack element relative to top: stacktop(-1) = top */
function stacktop(stack: StackElement[], offset: number): StackElement {
  return stack[stack.length + offset]
}

/** Set a stack element relative to top */
function stackset(
  stack: StackElement[],
  offset: number,
  value: StackElement,
): void {
  stack[stack.length + offset] = value
}

/** Pop and discard the top stack element */
function popstack(stack: StackElement[]): void {
  if (stack.length === 0) {
    throw new Error('popstack: stack empty')
  }
  stack.pop()
}

/** Swap two stack elements by their offsets from top */
function stackswap(
  stack: StackElement[],
  offsetA: number,
  offsetB: number,
): void {
  const idxA = stack.length + offsetA
  const idxB = stack.length + offsetB
  const tmp = stack[idxA]
  stack[idxA] = stack[idxB]
  stack[idxB] = tmp
}

// ─── Boolean Casting ──────────────────────────────────────────────

const EMPTY_BUFFER = BufferUtil.alloc(0)
const FALSE_BUFFER = BufferUtil.alloc(0)
const TRUE_BUFFER = BufferUtil.from([0x01])

/**
 * Cast a stack element to a boolean per Bitcoin script rules.
 *
 * Any byte array is false if it is empty or consists entirely of
 * zero bytes. Negative zero (0x80 as the last byte with all others
 * zero) is also false.
 *
 * Reference: lotusd CastToBool()
 */
function castToBool(buf: Buffer): boolean {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) {
      // Negative zero check: 0x80 in the last byte only
      if (i === buf.length - 1 && buf[i] === 0x80) {
        return false
      }
      return true
    }
  }
  return false
}

// ─── Opcode Classification ───────────────────────────────────────

/**
 * First undefined opcode value in Lotus.
 *
 * OP_RAWLEFTBITSHIFT (0xbe = 190) is the last defined opcode
 * before the prefix range. Anything at or above this value
 * (excluding the prefix range) is undefined and disabled.
 *
 * Reference: lotusd FIRST_UNDEFINED_OP_VALUE
 */
const FIRST_UNDEFINED_OP_VALUE = Opcode.OP_RAWLEFTBITSHIFT + 1

/**
 * Check if an opcode is disabled in Lotus consensus.
 *
 * Lotus disables several opcodes that were part of the original
 * Bitcoin script language but were removed for security or
 * design reasons.
 *
 * Reference: lotusd IsOpcodeDisabled()
 */
function isOpcodeDisabled(opcode: number): boolean {
  switch (opcode) {
    case Opcode.OP_RESERVED:
    case Opcode.OP_VERIF:
    case Opcode.OP_VERNOTIF:
    case Opcode.OP_IFDUP:
    case Opcode.OP_INVERT:
    case Opcode.OP_RESERVED1:
    case Opcode.OP_RESERVED2:
    case Opcode.OP_2MUL:
    case Opcode.OP_2DIV:
    case Opcode.OP_MUL:
    case Opcode.OP_NUMEQUAL:
    case Opcode.OP_NUMEQUALVERIFY:
    case Opcode.OP_NUMNOTEQUAL:
    case Opcode.OP_SHA1:
      return true
    default:
      if (opcode >= FIRST_UNDEFINED_OP_VALUE) {
        return true
      }
      return false
  }
}

/**
 * Check whether a data push uses the minimal encoding.
 *
 * Lotus requires that data pushes use the smallest possible opcode.
 * For example, pushing a single byte 0x01 must use OP_1, not a
 * 1-byte push opcode.
 *
 * Reference: lotusd CheckMinimalPush()
 */
function checkMinimalPush(data: Buffer, opcode: number): boolean {
  if (data.length === 0) {
    return opcode === Opcode.OP_0
  }
  if (data.length === 1) {
    if (data[0] >= 1 && data[0] <= 16) {
      return opcode === Opcode.OP_1 + (data[0] - 1)
    }
    if (data[0] === 0x81) {
      return opcode === Opcode.OP_1NEGATE
    }
  }
  if (data.length <= 75) {
    return opcode === data.length
  }
  if (data.length <= 255) {
    return opcode === Opcode.OP_PUSHDATA1
  }
  if (data.length <= 65535) {
    return opcode === Opcode.OP_PUSHDATA2
  }
  return true
}

// ─── Script Parsing ──────────────────────────────────────────────

/**
 * A parsed instruction from the script byte stream.
 */
interface ScriptInstruction {
  /** The opcode byte */
  opcode: number
  /** Data bytes for push operations (empty buffer for non-push) */
  data: Buffer
  /** Byte offset after this instruction */
  nextOffset: number
}

/**
 * Read the next instruction from a script buffer.
 *
 * Handles OP_0..OP_PUSHDATA4 data push opcodes and returns
 * the opcode + associated data bytes.
 *
 * @param script - The raw script bytes
 * @param offset - Current read position
 * @returns The parsed instruction, or null if invalid
 */
function readInstruction(
  script: Buffer,
  offset: number,
): ScriptInstruction | null {
  if (offset >= script.length) {
    return null
  }

  const opcode = script[offset]
  let data = EMPTY_BUFFER
  let next = offset + 1

  if (opcode >= 0 && opcode < Opcode.OP_PUSHDATA1) {
    // Direct push: opcode is the byte count
    const len = opcode
    if (next + len > script.length) {
      return null
    }
    data = script.slice(next, next + len)
    next += len
  } else if (opcode === Opcode.OP_PUSHDATA1) {
    if (next >= script.length) {
      return null
    }
    const len = script[next]
    next++
    if (next + len > script.length) {
      return null
    }
    data = script.slice(next, next + len)
    next += len
  } else if (opcode === Opcode.OP_PUSHDATA2) {
    if (next + 2 > script.length) {
      return null
    }
    const len = script[next] | (script[next + 1] << 8)
    next += 2
    if (next + len > script.length) {
      return null
    }
    data = script.slice(next, next + len)
    next += len
  } else if (opcode === Opcode.OP_PUSHDATA4) {
    if (next + 4 > script.length) {
      return null
    }
    const len =
      script[next] |
      (script[next + 1] << 8) |
      (script[next + 2] << 16) |
      ((script[next + 3] << 24) >>> 0)
    next += 4
    if (next + len > script.length) {
      return null
    }
    data = script.slice(next, next + len)
    next += len
  }

  return { opcode, data, nextOffset: next }
}

// ─── Result Helpers ──────────────────────────────────────────────

function success(): ScriptResult {
  return { success: true, error: ScriptError.OK }
}

function failure(error: ScriptError): ScriptResult {
  return { success: false, error }
}

// ─── EvalScript ──────────────────────────────────────────────────

/**
 * Evaluate a script on the given stack.
 *
 * This is the core script execution engine. It processes each opcode
 * sequentially, manipulating the stack according to Lotus consensus
 * rules. Conditional execution (IF/ELSE/ENDIF) is tracked via the
 * ConditionStack.
 *
 * For client-side validation, this function verifies that a script
 * will execute successfully under lotusd consensus rules.
 *
 * @param stack - The data stack (modified in place)
 * @param scriptBuf - Raw script bytes to execute
 * @param flags - Script verification flags
 * @param checker - Signature verification interface
 * @param metrics - Execution metrics (modified in place)
 * @param execdata - Execution data for sighash (modified in place)
 * @returns ScriptResult indicating success or failure with error code
 */
export function evalScript(
  stack: StackElement[],
  scriptBuf: Buffer,
  flags: number,
  checker: SignatureChecker,
  metrics: ScriptExecutionMetrics,
  execdata: ScriptExecutionData,
): ScriptResult {
  if (scriptBuf.length > MAX_SCRIPT_SIZE) {
    return failure(ScriptError.SCRIPT_SIZE)
  }

  const altstack: StackElement[] = []
  const vfExec = new ConditionStack()
  let nOpCount = 0
  let opcodePos = 0
  let offset = 0
  // Track OP_CODESEPARATOR position for sighash
  let codeHashBegin = 0

  try {
    while (offset < scriptBuf.length) {
      const fExec = vfExec.allTrue()

      // Read next instruction
      const instr = readInstruction(scriptBuf, offset)
      if (!instr) {
        return failure(ScriptError.BAD_OPCODE)
      }

      const { opcode, data: pushData } = instr
      offset = instr.nextOffset

      if (pushData.length > MAX_SCRIPT_ELEMENT_SIZE) {
        return failure(ScriptError.PUSH_SIZE)
      }

      // Count non-push opcodes
      if (opcode > Opcode.OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT) {
        return failure(ScriptError.OP_COUNT)
      }

      // Check for disabled opcodes (always, even in non-executed branches)
      if (isOpcodeDisabled(opcode)) {
        return failure(ScriptError.DISABLED_OPCODE)
      }

      // OP_SCRIPTTYPE is never valid inside an executed script
      if (opcode === Opcode.OP_SCRIPTTYPE) {
        return failure(ScriptError.INVALID_OP_SCRIPTTYPE)
      }

      // ── Data push opcodes ───────────────────────────────────
      if (fExec && opcode >= 0 && opcode <= Opcode.OP_PUSHDATA4) {
        // Minimal push check is always required in Lotus
        if (!checkMinimalPush(pushData, opcode)) {
          return failure(ScriptError.MINIMALDATA)
        }
        stack.push(pushData)
      } else if (
        fExec ||
        (opcode >= Opcode.OP_IF && opcode <= Opcode.OP_ENDIF)
      ) {
        // ── Opcode dispatch ─────────────────────────────────
        const result = executeOpcode(
          opcode,
          stack,
          altstack,
          vfExec,
          fExec,
          flags,
          checker,
          metrics,
          execdata,
          scriptBuf,
          codeHashBegin,
          offset,
          opcodePos,
          nOpCount,
        )

        if (!result.success) {
          return result
        }

        // Update mutable state returned from executeOpcode
        if (result.codeHashBegin !== undefined) {
          codeHashBegin = result.codeHashBegin
        }
        if (result.nOpCount !== undefined) {
          nOpCount = result.nOpCount
        }
      }

      // Size limits: combined stack + altstack
      if (stack.length + altstack.length > MAX_STACK_SIZE) {
        return failure(ScriptError.STACK_SIZE)
      }

      opcodePos++
    }
  } catch {
    return failure(ScriptError.UNKNOWN)
  }

  if (!vfExec.isEmpty()) {
    return failure(ScriptError.UNBALANCED_CONDITIONAL)
  }

  return success()
}

// ─── Opcode Execution Result ─────────────────────────────────────

interface OpcodeResult extends ScriptResult {
  /** Updated codeHashBegin after OP_CODESEPARATOR */
  codeHashBegin?: number
  /** Updated opcount after OP_CHECKMULTISIG */
  nOpCount?: number
}

function opcodeSuccess(overrides?: Partial<OpcodeResult>): OpcodeResult {
  return { success: true, error: ScriptError.OK, ...overrides }
}

function opcodeFailure(error: ScriptError): OpcodeResult {
  return { success: false, error }
}

// ─── Opcode Execution ────────────────────────────────────────────

/**
 * Execute a single opcode.
 *
 * This function handles the massive switch statement from lotusd's
 * EvalScript. It modifies the stack, altstack, and condition stack
 * in place.
 */
function executeOpcode(
  opcode: number,
  stack: StackElement[],
  altstack: StackElement[],
  vfExec: ConditionStack,
  fExec: boolean,
  flags: number,
  checker: SignatureChecker,
  metrics: ScriptExecutionMetrics,
  execdata: ScriptExecutionData,
  scriptBuf: Buffer,
  codeHashBegin: number,
  currentOffset: number,
  opcodePos: number,
  nOpCount: number,
): OpcodeResult {
  switch (opcode) {
    // ── Push value opcodes ──────────────────────────────────
    case Opcode.OP_1NEGATE:
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
      const n = opcode - (Opcode.OP_1 - 1)
      const bn = new ScriptNum(BigInt(n))
      stack.push(bn.toBuffer())
      return opcodeSuccess()
    }

    // ── Control flow ────────────────────────────────────────
    case Opcode.OP_NOP:
      return opcodeSuccess()

    case Opcode.OP_CHECKLOCKTIMEVERIFY: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      // 5-byte bignums allowed for locktime (year 2038 fix)
      const nLockTime = ScriptNum.fromBuffer(stacktop(stack, -1), true, 5)
      if (nLockTime.isNegative()) {
        return opcodeFailure(ScriptError.NEGATIVE_LOCKTIME)
      }
      if (!checker.checkLockTime(nLockTime.value)) {
        return opcodeFailure(ScriptError.UNSATISFIED_LOCKTIME)
      }
      return opcodeSuccess()
    }

    case Opcode.OP_CHECKSEQUENCEVERIFY: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const nSequence = ScriptNum.fromBuffer(stacktop(stack, -1), true, 5)
      if (nSequence.isNegative()) {
        return opcodeFailure(ScriptError.NEGATIVE_LOCKTIME)
      }
      // If disable flag is set, CSV behaves as NOP
      const SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
      if ((Number(nSequence.value) & SEQUENCE_LOCKTIME_DISABLE_FLAG) !== 0) {
        return opcodeSuccess()
      }
      if (!checker.checkSequence(nSequence.value)) {
        return opcodeFailure(ScriptError.UNSATISFIED_LOCKTIME)
      }
      return opcodeSuccess()
    }

    case Opcode.OP_NOP1:
    case Opcode.OP_NOP4:
    case Opcode.OP_NOP5:
    case Opcode.OP_NOP6:
    case Opcode.OP_NOP7:
    case Opcode.OP_NOP8:
    case Opcode.OP_NOP9:
    case Opcode.OP_NOP10: {
      if (flags & ScriptFlags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
        return opcodeFailure(ScriptError.DISCOURAGE_UPGRADABLE_NOPS)
      }
      return opcodeSuccess()
    }

    case Opcode.OP_IF:
    case Opcode.OP_NOTIF: {
      let fValue = false
      if (fExec) {
        if (stack.length < 1) {
          return opcodeFailure(ScriptError.UNBALANCED_CONDITIONAL)
        }
        const vch = stacktop(stack, -1)
        if (flags & ScriptFlags.VERIFY_MINIMALIF) {
          if (vch.length > 1) {
            return opcodeFailure(ScriptError.MINIMALIF)
          }
          if (vch.length === 1 && vch[0] !== 1) {
            return opcodeFailure(ScriptError.MINIMALIF)
          }
        }
        fValue = castToBool(vch)
        if (opcode === Opcode.OP_NOTIF) {
          fValue = !fValue
        }
        popstack(stack)
      }
      vfExec.pushBack(fValue)
      return opcodeSuccess()
    }

    case Opcode.OP_ELSE: {
      if (vfExec.isEmpty()) {
        return opcodeFailure(ScriptError.UNBALANCED_CONDITIONAL)
      }
      vfExec.toggleTop()
      return opcodeSuccess()
    }

    case Opcode.OP_ENDIF: {
      if (vfExec.isEmpty()) {
        return opcodeFailure(ScriptError.UNBALANCED_CONDITIONAL)
      }
      vfExec.popBack()
      return opcodeSuccess()
    }

    case Opcode.OP_VERIFY: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      if (castToBool(stacktop(stack, -1))) {
        popstack(stack)
      } else {
        return opcodeFailure(ScriptError.VERIFY)
      }
      return opcodeSuccess()
    }

    case Opcode.OP_RETURN:
      return opcodeFailure(ScriptError.OP_RETURN)

    // ── Stack operations ────────────────────────────────────
    case Opcode.OP_TOALTSTACK: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      altstack.push(stacktop(stack, -1))
      popstack(stack)
      return opcodeSuccess()
    }

    case Opcode.OP_FROMALTSTACK: {
      if (altstack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_ALTSTACK_OPERATION)
      }
      stack.push(altstack[altstack.length - 1])
      altstack.pop()
      return opcodeSuccess()
    }

    case Opcode.OP_2DROP: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      popstack(stack)
      popstack(stack)
      return opcodeSuccess()
    }

    case Opcode.OP_2DUP: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      stack.push(stacktop(stack, -2))
      stack.push(stacktop(stack, -2))
      return opcodeSuccess()
    }

    case Opcode.OP_3DUP: {
      if (stack.length < 3) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      stack.push(stacktop(stack, -3))
      stack.push(stacktop(stack, -3))
      stack.push(stacktop(stack, -3))
      return opcodeSuccess()
    }

    case Opcode.OP_2OVER: {
      if (stack.length < 4) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      stack.push(stacktop(stack, -4))
      stack.push(stacktop(stack, -4))
      return opcodeSuccess()
    }

    case Opcode.OP_2ROT: {
      if (stack.length < 6) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const v1 = stacktop(stack, -6)
      const v2 = stacktop(stack, -5)
      stack.splice(stack.length - 6, 2)
      stack.push(v1, v2)
      return opcodeSuccess()
    }

    case Opcode.OP_2SWAP: {
      if (stack.length < 4) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      stackswap(stack, -4, -2)
      stackswap(stack, -3, -1)
      return opcodeSuccess()
    }

    case Opcode.OP_DEPTH: {
      const bn = new ScriptNum(BigInt(stack.length))
      stack.push(bn.toBuffer())
      return opcodeSuccess()
    }

    case Opcode.OP_DROP: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      popstack(stack)
      return opcodeSuccess()
    }

    case Opcode.OP_DUP: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      stack.push(stacktop(stack, -1))
      return opcodeSuccess()
    }

    case Opcode.OP_NIP: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      stack.splice(stack.length - 2, 1)
      return opcodeSuccess()
    }

    case Opcode.OP_OVER: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      stack.push(stacktop(stack, -2))
      return opcodeSuccess()
    }

    case Opcode.OP_PICK:
    case Opcode.OP_ROLL: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const n = ScriptNum.fromBuffer(stacktop(stack, -1), true).toNumber()
      popstack(stack)
      if (n < 0 || n >= stack.length) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const val = stacktop(stack, -n - 1)
      if (opcode === Opcode.OP_ROLL) {
        stack.splice(stack.length - n - 1, 1)
      }
      stack.push(val)
      return opcodeSuccess()
    }

    case Opcode.OP_ROT: {
      if (stack.length < 3) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      stackswap(stack, -3, -2)
      stackswap(stack, -2, -1)
      return opcodeSuccess()
    }

    case Opcode.OP_SWAP: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      stackswap(stack, -2, -1)
      return opcodeSuccess()
    }

    case Opcode.OP_TUCK: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const vch = stacktop(stack, -1)
      stack.splice(stack.length - 2, 0, vch)
      return opcodeSuccess()
    }

    case Opcode.OP_SIZE: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const bn = new ScriptNum(BigInt(stacktop(stack, -1).length))
      stack.push(bn.toBuffer())
      return opcodeSuccess()
    }

    // ── Bitwise logic ───────────────────────────────────────
    case Opcode.OP_AND:
    case Opcode.OP_OR:
    case Opcode.OP_XOR: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const a = stacktop(stack, -2)
      const b = stacktop(stack, -1)
      const longer = a.length >= b.length ? a : b
      const shorter = a.length >= b.length ? b : a
      const result = longer

      if (opcode === Opcode.OP_AND) {
        for (let i = 0; i < result.length; i++) {
          result[i] = i < shorter.length ? result[i] & shorter[i] : 0
        }
      } else if (opcode === Opcode.OP_OR) {
        for (let i = 0; i < shorter.length; i++) {
          result[i] |= shorter[i]
        }
      } else {
        for (let i = 0; i < shorter.length; i++) {
          result[i] ^= shorter[i]
        }
      }

      // Remove the shorter element, keep the longer (now modified)
      const depthShorter = a.length >= b.length ? -1 : -2
      stack.splice(stack.length + depthShorter, 1)
      stackset(stack, -1, result)
      return opcodeSuccess()
    }

    case Opcode.OP_EQUAL:
    case Opcode.OP_EQUALVERIFY: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const a2 = stacktop(stack, -2)
      const b2 = stacktop(stack, -1)
      const fEqual = a2.equals(b2)
      popstack(stack)
      popstack(stack)
      stack.push(fEqual ? TRUE_BUFFER : FALSE_BUFFER)
      if (opcode === Opcode.OP_EQUALVERIFY) {
        if (fEqual) {
          popstack(stack)
        } else {
          return opcodeFailure(ScriptError.EQUALVERIFY)
        }
      }
      return opcodeSuccess()
    }

    // ── Unary numeric ───────────────────────────────────────
    case Opcode.OP_1ADD:
    case Opcode.OP_1SUB:
    case Opcode.OP_NEGATE:
    case Opcode.OP_ABS:
    case Opcode.OP_NOT:
    case Opcode.OP_0NOTEQUAL: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      let bn = ScriptNum.fromBuffer(stacktop(stack, -1), true)
      const ONE = new ScriptNum(1n)
      switch (opcode) {
        case Opcode.OP_1ADD:
          bn = bn.add(ONE)
          break
        case Opcode.OP_1SUB:
          bn = bn.sub(ONE)
          break
        case Opcode.OP_NEGATE:
          bn = bn.negate()
          break
        case Opcode.OP_ABS:
          bn = bn.abs()
          break
        case Opcode.OP_NOT:
          bn = new ScriptNum(bn.isZero() ? 1n : 0n)
          break
        case Opcode.OP_0NOTEQUAL:
          bn = new ScriptNum(bn.isZero() ? 0n : 1n)
          break
      }
      popstack(stack)
      stack.push(bn.toBuffer())
      return opcodeSuccess()
    }

    // ── Binary numeric ──────────────────────────────────────
    case Opcode.OP_ADD:
    case Opcode.OP_SUB:
    case Opcode.OP_DIV:
    case Opcode.OP_MOD:
    case Opcode.OP_MULPOW2:
    case Opcode.OP_BOOLAND:
    case Opcode.OP_BOOLOR:
    case Opcode.OP_LESSTHAN:
    case Opcode.OP_GREATERTHAN:
    case Opcode.OP_LESSTHANOREQUAL:
    case Opcode.OP_GREATERTHANOREQUAL:
    case Opcode.OP_MIN:
    case Opcode.OP_MAX: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const bn1 = ScriptNum.fromBuffer(stacktop(stack, -2), true)
      const bn2 = ScriptNum.fromBuffer(stacktop(stack, -1), true)
      let bnResult: ScriptNum

      switch (opcode) {
        case Opcode.OP_ADD:
          bnResult = bn1.add(bn2)
          break
        case Opcode.OP_SUB:
          bnResult = bn1.sub(bn2)
          break
        case Opcode.OP_DIV:
          if (bn2.isZero()) {
            return opcodeFailure(ScriptError.DIV_BY_ZERO)
          }
          bnResult = bn1.div(bn2)
          break
        case Opcode.OP_MOD:
          if (bn2.isZero()) {
            return opcodeFailure(ScriptError.MOD_BY_ZERO)
          }
          bnResult = bn1.mod(bn2)
          break
        case Opcode.OP_MULPOW2:
          bnResult = bn1.mulpow2(bn2)
          break
        case Opcode.OP_BOOLAND:
          bnResult = new ScriptNum(!bn1.isZero() && !bn2.isZero() ? 1n : 0n)
          break
        case Opcode.OP_BOOLOR:
          bnResult = new ScriptNum(!bn1.isZero() || !bn2.isZero() ? 1n : 0n)
          break
        case Opcode.OP_LESSTHAN:
          bnResult = new ScriptNum(bn1.lt(bn2) ? 1n : 0n)
          break
        case Opcode.OP_GREATERTHAN:
          bnResult = new ScriptNum(bn1.gt(bn2) ? 1n : 0n)
          break
        case Opcode.OP_LESSTHANOREQUAL:
          bnResult = new ScriptNum(bn1.lte(bn2) ? 1n : 0n)
          break
        case Opcode.OP_GREATERTHANOREQUAL:
          bnResult = new ScriptNum(bn1.gte(bn2) ? 1n : 0n)
          break
        case Opcode.OP_MIN:
          bnResult = bn1.lt(bn2) ? bn1 : bn2
          break
        case Opcode.OP_MAX:
          bnResult = bn1.gt(bn2) ? bn1 : bn2
          break
        default:
          return opcodeFailure(ScriptError.BAD_OPCODE)
      }
      popstack(stack)
      popstack(stack)
      stack.push(bnResult.toBuffer())
      return opcodeSuccess()
    }

    case Opcode.OP_WITHIN: {
      if (stack.length < 3) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const x = ScriptNum.fromBuffer(stacktop(stack, -3), true)
      const min = ScriptNum.fromBuffer(stacktop(stack, -2), true)
      const max = ScriptNum.fromBuffer(stacktop(stack, -1), true)
      const fValue = min.lte(x) && x.lt(max)
      popstack(stack)
      popstack(stack)
      popstack(stack)
      stack.push(fValue ? TRUE_BUFFER : FALSE_BUFFER)
      return opcodeSuccess()
    }

    // ── Crypto ──────────────────────────────────────────────
    case Opcode.OP_RIPEMD160:
    case Opcode.OP_SHA256:
    case Opcode.OP_HASH160:
    case Opcode.OP_HASH256: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const data = stacktop(stack, -1)
      let hashResult: Buffer
      switch (opcode) {
        case Opcode.OP_RIPEMD160:
          hashResult = Hash.ripemd160(data)
          break
        case Opcode.OP_SHA256:
          hashResult = Hash.sha256(data)
          break
        case Opcode.OP_HASH160:
          hashResult = Hash.sha256ripemd160(data)
          break
        case Opcode.OP_HASH256:
          hashResult = Hash.sha256sha256(data)
          break
        default:
          return opcodeFailure(ScriptError.BAD_OPCODE)
      }
      popstack(stack)
      stack.push(hashResult)
      return opcodeSuccess()
    }

    case Opcode.OP_CODESEPARATOR: {
      execdata.codeseparatorPos = opcodePos
      return opcodeSuccess({ codeHashBegin: currentOffset })
    }

    case Opcode.OP_CHECKSIG:
    case Opcode.OP_CHECKSIGVERIFY: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const vchSig = stacktop(stack, -2)
      const vchPubKey = stacktop(stack, -1)

      let fSuccess = false
      if (vchSig.length > 0) {
        const scriptCode = scriptBuf.slice(codeHashBegin)
        fSuccess = checker.checkSignature(
          vchSig,
          vchPubKey,
          execdata,
          scriptCode,
          flags,
        )
        metrics.sigChecks += 1
        if (!fSuccess) {
          return opcodeFailure(ScriptError.SIG_NULLFAIL)
        }
      }
      popstack(stack)
      popstack(stack)
      stack.push(fSuccess ? TRUE_BUFFER : FALSE_BUFFER)
      if (opcode === Opcode.OP_CHECKSIGVERIFY) {
        if (fSuccess) {
          popstack(stack)
        } else {
          return opcodeFailure(ScriptError.CHECKSIGVERIFY)
        }
      }
      return opcodeSuccess()
    }

    case Opcode.OP_CHECKDATASIG:
    case Opcode.OP_CHECKDATASIGVERIFY: {
      if (stack.length < 3) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const cdsSig = stacktop(stack, -3)
      const cdsMsg = stacktop(stack, -2)
      const cdsPubKey = stacktop(stack, -1)

      let cdSuccess = false
      if (cdsSig.length > 0) {
        const msgHash = Hash.sha256(cdsMsg)
        cdSuccess = checker.verifySignature(cdsSig, cdsPubKey, msgHash)
        metrics.sigChecks += 1
        if (!cdSuccess) {
          return opcodeFailure(ScriptError.SIG_NULLFAIL)
        }
      }
      popstack(stack)
      popstack(stack)
      popstack(stack)
      stack.push(cdSuccess ? TRUE_BUFFER : FALSE_BUFFER)
      if (opcode === Opcode.OP_CHECKDATASIGVERIFY) {
        if (cdSuccess) {
          popstack(stack)
        } else {
          return opcodeFailure(ScriptError.CHECKDATASIGVERIFY)
        }
      }
      return opcodeSuccess()
    }

    case Opcode.OP_CHECKMULTISIG:
    case Opcode.OP_CHECKMULTISIGVERIFY: {
      return executeCheckmultisig(
        opcode,
        stack,
        flags,
        checker,
        metrics,
        execdata,
        scriptBuf,
        codeHashBegin,
        currentOffset,
        nOpCount,
      )
    }

    // ── Byte string operations ──────────────────────────────
    case Opcode.OP_CAT: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const catA = stacktop(stack, -2)
      const catB = stacktop(stack, -1)
      if (catA.length + catB.length > MAX_SCRIPT_ELEMENT_SIZE) {
        return opcodeFailure(ScriptError.PUSH_SIZE)
      }
      const catResult = BufferUtil.concat([catA, catB])
      popstack(stack)
      stackset(stack, -1, catResult)
      return opcodeSuccess()
    }

    case Opcode.OP_SPLIT: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const splitData = stacktop(stack, -2)
      const pos = ScriptNum.fromBuffer(stacktop(stack, -1), true).toNumber()
      if (pos < 0 || pos > splitData.length) {
        return opcodeFailure(ScriptError.INVALID_SPLIT_RANGE)
      }
      const n1 = splitData.slice(0, pos)
      const n2 = splitData.slice(pos)
      stackset(stack, -2, n1)
      stackset(stack, -1, n2)
      return opcodeSuccess()
    }

    case Opcode.OP_REVERSEBYTES: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const revData = stacktop(stack, -1)
      revData.reverse()
      stackset(stack, -1, revData)
      return opcodeSuccess()
    }

    case Opcode.OP_NUM2BIN: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const targetSize = ScriptNum.fromBuffer(
        stacktop(stack, -1),
        true,
      ).toNumber()
      if (targetSize > MAX_SCRIPT_ELEMENT_SIZE) {
        return opcodeFailure(ScriptError.PUSH_SIZE)
      }
      if (targetSize > MAX_NUM2BIN_SIZE) {
        return opcodeFailure(ScriptError.INVALID_NUM2BIN_SIZE)
      }
      popstack(stack)
      let rawnum = stacktop(stack, -1)
      rawnum = ScriptNum.minimallyEncode(rawnum)
      if (rawnum.length > targetSize) {
        return opcodeFailure(ScriptError.IMPOSSIBLE_ENCODING)
      }
      if (rawnum.length === targetSize) {
        stackset(stack, -1, rawnum)
        return opcodeSuccess()
      }
      // Pad to target size preserving sign
      let signbit = 0x00
      if (rawnum.length > 0) {
        signbit = rawnum[rawnum.length - 1] & 0x80
        rawnum[rawnum.length - 1] &= 0x7f
      }
      const padded = BufferUtil.alloc(targetSize, 0)
      rawnum.copy(padded)
      padded[targetSize - 1] = signbit
      stackset(stack, -1, padded)
      return opcodeSuccess()
    }

    case Opcode.OP_BIN2NUM: {
      if (stack.length < 1) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const encoded = ScriptNum.minimallyEncode(stacktop(stack, -1))
      if (!ScriptNum.isMinimallyEncoded(encoded)) {
        return opcodeFailure(ScriptError.INVALID_NUMBER_RANGE)
      }
      stackset(stack, -1, encoded)
      return opcodeSuccess()
    }

    // OP_RAWLEFTBITSHIFT is complex; for client-side validation
    // we implement a simplified version that matches lotusd behavior
    case Opcode.OP_RAWLEFTBITSHIFT: {
      if (stack.length < 2) {
        return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
      }
      const shiftData = stacktop(stack, -2)
      const signedBitshift = ScriptNum.fromBuffer(
        stacktop(stack, -1),
        true,
      ).toNumber()
      popstack(stack)

      if (shiftData.length === 0 || signedBitshift === 0) {
        stackset(stack, -1, shiftData)
        return opcodeSuccess()
      }

      let bitshift = Math.abs(signedBitshift)
      if (bitshift > shiftData.length * 8) {
        bitshift = shiftData.length * 8
      }

      const innerBitshift = bitshift % 8
      const byteshift = Math.floor(bitshift / 8)

      if (signedBitshift > 0) {
        // Left shift
        const mask = 0xff >> innerBitshift
        for (let idx = byteshift; idx < shiftData.length; idx++) {
          const bits = shiftData[idx]
          const off = idx - byteshift
          const removeMask = mask << innerBitshift
          shiftData[off] &= ~removeMask & 0xff
          shiftData[off] |= (bits & mask) << innerBitshift
          if (off > 0) {
            const removeMaskCarry = (~mask & 0xff) >> (8 - innerBitshift)
            shiftData[off - 1] &= ~removeMaskCarry & 0xff
            shiftData[off - 1] |= (bits & ~mask & 0xff) >> (8 - innerBitshift)
          }
        }
        if (byteshift < shiftData.length) {
          shiftData[shiftData.length - byteshift - 1] &=
            (0xff << innerBitshift) & 0xff
        }
        for (let i = shiftData.length - byteshift; i < shiftData.length; i++) {
          shiftData[i] = 0
        }
      } else {
        // Right shift
        const mask = (0xff << innerBitshift) & 0xff
        for (let idx = shiftData.length - byteshift - 1; idx >= 0; idx--) {
          const bits = shiftData[idx]
          const off = idx + byteshift
          const removeMask = (mask >> innerBitshift) & 0xff
          shiftData[off] &= ~removeMask & 0xff
          shiftData[off] |= (bits & mask) >> innerBitshift
          if (off + 1 < shiftData.length) {
            const removeMaskCarry =
              ((~mask & 0xff) << (8 - innerBitshift)) & 0xff
            shiftData[off + 1] &= ~removeMaskCarry & 0xff
            shiftData[off + 1] |=
              ((bits & ~mask & 0xff) << (8 - innerBitshift)) & 0xff
          }
        }
        for (let i = 0; i < byteshift; i++) {
          shiftData[i] = 0
        }
        if (byteshift < shiftData.length) {
          shiftData[byteshift] &= (0xff >> innerBitshift) & 0xff
        }
      }

      stackset(stack, -1, shiftData)
      return opcodeSuccess()
    }

    default:
      return opcodeFailure(ScriptError.BAD_OPCODE)
  }
}

// ─── OP_CHECKMULTISIG ────────────────────────────────────────────

/**
 * Execute OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY.
 *
 * Supports both legacy ECDSA multisig (null dummy element) and
 * Schnorr multisig (bitfield dummy element).
 *
 * Reference: lotusd interpreter.cpp OP_CHECKMULTISIG handler
 */
function executeCheckmultisig(
  opcode: number,
  stack: StackElement[],
  flags: number,
  checker: SignatureChecker,
  metrics: ScriptExecutionMetrics,
  execdata: ScriptExecutionData,
  scriptBuf: Buffer,
  codeHashBegin: number,
  _currentOffset: number,
  nOpCount: number,
): OpcodeResult {
  if (stack.length < 1) {
    return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
  }

  const nKeysCount = ScriptNum.fromBuffer(stacktop(stack, -1), true).toNumber()
  if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG) {
    return opcodeFailure(ScriptError.PUBKEY_COUNT)
  }

  let updatedOpCount = nOpCount + nKeysCount
  if (updatedOpCount > MAX_OPS_PER_SCRIPT) {
    return opcodeFailure(ScriptError.OP_COUNT)
  }

  const idxTopKey = 2
  const idxSigCount = idxTopKey + nKeysCount
  if (stack.length < idxSigCount) {
    return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
  }

  const nSigsCount = ScriptNum.fromBuffer(
    stacktop(stack, -idxSigCount),
    true,
  ).toNumber()
  if (nSigsCount < 0 || nSigsCount > nKeysCount) {
    return opcodeFailure(ScriptError.SIG_COUNT)
  }

  const idxTopSig = idxSigCount + 1
  const idxDummy = idxTopSig + nSigsCount
  if (stack.length < idxDummy) {
    return opcodeFailure(ScriptError.INVALID_STACK_OPERATION)
  }

  const scriptCode = scriptBuf.slice(codeHashBegin)
  let fSuccess = true

  const dummyElement = stacktop(stack, -idxDummy)

  if (dummyElement.length !== 0) {
    // Schnorr multisig path (bitfield dummy)
    // For client-side validation, we delegate to the checker
    // which has the transaction context
    let checkBits = 0
    for (let i = 0; i < dummyElement.length; i++) {
      checkBits |= dummyElement[i] << (8 * i)
    }

    // Count set bits
    let bitCount = 0
    let tmp = checkBits
    while (tmp) {
      bitCount += tmp & 1
      tmp >>>= 1
    }
    if (bitCount !== nSigsCount) {
      return opcodeFailure(ScriptError.INVALID_BIT_COUNT)
    }

    const idxBottomKey = idxTopKey + nKeysCount - 1
    const idxBottomSig = idxTopSig + nSigsCount - 1

    let iKey = 0
    for (let iSig = 0; iSig < nSigsCount; iSig++, iKey++) {
      if (checkBits >>> iKey === 0) {
        return opcodeFailure(ScriptError.INVALID_BIT_RANGE)
      }
      while (((checkBits >>> iKey) & 0x01) === 0) {
        iKey++
      }
      if (iKey >= nKeysCount) {
        return opcodeFailure(ScriptError.PUBKEY_COUNT)
      }

      const vchSig = stacktop(stack, -idxBottomSig + iSig)
      const vchPubKey = stacktop(stack, -idxBottomKey + iKey)

      if (
        !checker.checkSignature(vchSig, vchPubKey, execdata, scriptCode, flags)
      ) {
        return opcodeFailure(ScriptError.SIG_NULLFAIL)
      }
      metrics.sigChecks += 1
    }

    if (checkBits >>> iKey !== 0) {
      return opcodeFailure(ScriptError.INVALID_BIT_COUNT)
    }
  } else {
    // Legacy ECDSA multisig path (null dummy)
    let nSigsRemaining = nSigsCount
    let nKeysRemaining = nKeysCount

    while (fSuccess && nSigsRemaining > 0) {
      const vchSig = stacktop(stack, -idxTopSig - (nSigsCount - nSigsRemaining))
      const vchPubKey = stacktop(
        stack,
        -idxTopKey - (nKeysCount - nKeysRemaining),
      )

      const fOk = checker.checkSignature(
        vchSig,
        vchPubKey,
        execdata,
        scriptCode,
        flags,
      )

      if (fOk) {
        nSigsRemaining--
      }
      nKeysRemaining--

      if (nSigsRemaining > nKeysRemaining) {
        fSuccess = false
      }
    }

    // NULLFAIL check
    let allSigsNull = true
    for (let i = 0; i < nSigsCount; i++) {
      if (stacktop(stack, -idxTopSig - i).length > 0) {
        allSigsNull = false
        break
      }
    }
    if (!fSuccess && !allSigsNull) {
      return opcodeFailure(ScriptError.SIG_NULLFAIL)
    }

    if (!allSigsNull) {
      metrics.sigChecks += nKeysCount
    }
  }

  // Clean up stack
  for (let i = 0; i < idxDummy; i++) {
    popstack(stack)
  }

  stack.push(fSuccess ? TRUE_BUFFER : FALSE_BUFFER)
  if (opcode === Opcode.OP_CHECKMULTISIGVERIFY) {
    if (fSuccess) {
      popstack(stack)
    } else {
      return opcodeFailure(ScriptError.CHECKMULTISIGVERIFY)
    }
  }

  return opcodeSuccess({ nOpCount: updatedOpCount })
}

// ─── Taproot Verification ────────────────────────────────────────

/**
 * Check if a scriptPubKey is a valid Pay-to-Taproot output.
 *
 * Valid formats:
 * - OP_SCRIPTTYPE OP_1 <33-byte commitment>
 * - OP_SCRIPTTYPE OP_1 <33-byte commitment> <32-byte state>
 *
 * Reference: lotusd/src/script/taproot.cpp IsPayToTaproot()
 */
function isPayToTaproot(scriptPubKey: Buffer): boolean {
  if (scriptPubKey.length < TAPROOT_SIZE_WITHOUT_STATE) {
    return false
  }
  if (
    scriptPubKey[0] !== Opcode.OP_SCRIPTTYPE ||
    scriptPubKey[1] !== TAPROOT_SCRIPTTYPE
  ) {
    return false
  }
  // First push (commitment) must be 33 bytes
  if (scriptPubKey[2] !== 33) {
    return false
  }
  if (scriptPubKey.length === TAPROOT_SIZE_WITHOUT_STATE) {
    return true
  }
  // With state: must be exactly TAPROOT_SIZE_WITH_STATE and state push is 32 bytes
  return (
    scriptPubKey.length === TAPROOT_SIZE_WITH_STATE &&
    scriptPubKey[TAPROOT_SIZE_WITHOUT_STATE] === 32
  )
}

/**
 * Check signature encoding for Taproot key-path spending.
 *
 * Key-path spending requires:
 * - Schnorr signature (64 bytes raw + 1 byte sighash = 65 bytes)
 * - SIGHASH_LOTUS algorithm bits
 *
 * Reference: lotusd/src/script/sigencoding.cpp CheckTransactionSignatureEncoding
 *            + CheckSighashEncoding with SCRIPT_TAPROOT_KEY_SPEND_PATH
 */
function checkTaprootKeySpendSigEncoding(sig: Buffer): ScriptError | null {
  if (sig.length === 0) {
    return null // empty sig is allowed (will fail verification)
  }
  // Must be Schnorr: 64-byte sig + 1-byte sighash = 65 bytes
  if (sig.length !== 65) {
    return ScriptError.SIG_BADLENGTH
  }
  // Check sighash type: must have SIGHASH_LOTUS (algorithm bits 0x60)
  const hashtype = sig[sig.length - 1]
  if (
    (hashtype & Signature.SIGHASH_ALGORITHM_MASK) !==
    Signature.SIGHASH_LOTUS
  ) {
    return ScriptError.TAPROOT_KEY_SPEND_MUST_USE_LOTUS_SIGHASH
  }
  return null
}

/**
 * Check public key encoding (compressed or uncompressed).
 *
 * Reference: lotusd/src/script/sigencoding.cpp CheckPubKeyEncoding
 */
function checkPubKeyEncoding(pubkey: Buffer): ScriptError | null {
  if (pubkey.length === 33) {
    if (pubkey[0] === 0x02 || pubkey[0] === 0x03) {
      return null
    }
  } else if (pubkey.length === 65) {
    if (pubkey[0] === 0x04) {
      return null
    }
  }
  return ScriptError.PUBKEYTYPE
}

/**
 * Verify a Taproot spend (key-path or script-path).
 *
 * This implements the full VerifyTaprootSpend from lotusd:
 * - Key-path: Single Schnorr signature verified against commitment
 * - Script-path: Control block proves script inclusion, then script is executed
 *
 * Reference: lotusd/src/script/interpreter.cpp VerifyTaprootSpend()
 */
function verifyTaprootSpend(
  stack: StackElement[],
  scriptSig: Buffer,
  scriptPubKey: Buffer,
  flags: number,
  checker: SignatureChecker,
  metrics: ScriptExecutionMetrics,
): ScriptResult {
  // Check if Taproot is disabled
  if (flags & ScriptFlags.DISABLE_TAPROOT_SIGHASH_LOTUS) {
    return failure(ScriptError.TAPROOT_PHASEOUT)
  }

  // Verify scriptPubKey is valid P2TR
  if (!isPayToTaproot(scriptPubKey)) {
    return failure(ScriptError.SCRIPTTYPE_MALFORMED_SCRIPT)
  }

  // Extract commitment pubkey: bytes [TAPROOT_INTRO_SIZE..TAPROOT_SIZE_WITHOUT_STATE]
  const vchPubkey = scriptPubKey.slice(
    TAPROOT_INTRO_SIZE,
    TAPROOT_SIZE_WITHOUT_STATE,
  )

  // Stack must not be empty
  if (stack.length === 0) {
    return failure(ScriptError.INVALID_STACK_OPERATION)
  }

  // Check for annex (not supported in Lotus)
  if (
    stack.length >= 2 &&
    stack[stack.length - 1].length > 0 &&
    stack[stack.length - 1][0] === TAPROOT_ANNEX_TAG
  ) {
    return failure(ScriptError.TAPROOT_ANNEX_NOT_SUPPORTED)
  }

  // ── Key-path spending ─────────────────────────────────────
  if (stack.length === 1) {
    const vchSig = stack[stack.length - 1]
    const sigFlags = flags | ScriptFlags.TAPROOT_KEY_SPEND_PATH

    // Check signature encoding (must be Schnorr + SIGHASH_LOTUS)
    const sigErr = checkTaprootKeySpendSigEncoding(vchSig)
    if (sigErr !== null) {
      return failure(sigErr)
    }

    // Check pubkey encoding
    const pkErr = checkPubKeyEncoding(vchPubkey)
    if (pkErr !== null) {
      return failure(pkErr)
    }

    // Verify signature
    if (
      vchSig.length === 0 ||
      !checker.checkSignature(
        vchSig,
        vchPubkey,
        undefined,
        BufferUtil.alloc(0),
        sigFlags,
      )
    ) {
      return failure(ScriptError.TAPROOT_VERIFY_SIGNATURE_FAILED)
    }

    metrics.sigChecks += 1
    return success()
  }

  // ── Script-path spending ──────────────────────────────────
  const controlBlock = stack[stack.length - 1]
  const scriptBytes = stack[stack.length - 2]
  const execScript = scriptBytes

  // Remove control block and script from stack
  stack.pop()
  stack.pop()

  // Validate control block size
  const sizeRemainder =
    (controlBlock.length - TAPROOT_CONTROL_BASE_SIZE) %
    TAPROOT_CONTROL_NODE_SIZE
  if (
    controlBlock.length < TAPROOT_CONTROL_BASE_SIZE ||
    controlBlock.length > TAPROOT_CONTROL_MAX_SIZE ||
    sizeRemainder !== 0
  ) {
    return failure(ScriptError.TAPROOT_WRONG_CONTROL_SIZE)
  }

  // Check leaf version (only tapscript 0xc0 supported)
  if ((controlBlock[0] & TAPROOT_LEAF_MASK) !== TAPROOT_LEAF_TAPSCRIPT) {
    return failure(ScriptError.TAPROOT_LEAF_VERSION_NOT_SUPPORTED)
  }

  // Verify Taproot commitment (merkle proof)
  const commitResult = verifyTaprootCommitment(
    controlBlock,
    vchPubkey,
    Script.fromBuffer(execScript),
  )
  if (!commitResult.success) {
    return failure(ScriptError.TAPROOT_VERIFY_COMMITMENT_FAILED)
  }

  // Push state onto stack if present
  // Reference: lotusd/src/script/interpreter.cpp lines 2136-2140
  if (scriptPubKey.length === TAPROOT_SIZE_WITH_STATE) {
    const stateStart = TAPROOT_SIZE_WITHOUT_STATE + 1 // skip push opcode
    const stateEnd = TAPROOT_SIZE_WITH_STATE
    stack.push(scriptPubKey.slice(stateStart, stateEnd))
  }

  // Execute the revealed script
  // Use the tapleaf hash as the executed script hash
  const taprootExecdata: ScriptExecutionData = {
    codeseparatorPos: 0xffffffff,
    executedScriptHash: commitResult.tapleafHash,
  }
  const evalResult = evalScript(
    stack,
    execScript,
    flags,
    checker,
    metrics,
    taprootExecdata,
  )
  if (!evalResult.success) {
    return evalResult
  }

  // Check final stack state
  if (stack.length === 0 || !castToBool(stack[stack.length - 1])) {
    return failure(ScriptError.EVAL_FALSE)
  }

  // Post-conditions (CLEANSTACK, INPUT_SIGCHECKS)
  return verifyPostConditions(stack, scriptSig, flags, metrics)
}

/**
 * Dispatch OP_SCRIPTTYPE to the appropriate verifier.
 *
 * Currently only Taproot (OP_1) is supported.
 *
 * Reference: lotusd/src/script/interpreter.cpp VerifyScriptType()
 */
function verifyScriptType(
  stack: StackElement[],
  scriptSig: Buffer,
  scriptPubKey: Buffer,
  flags: number,
  checker: SignatureChecker,
  metrics: ScriptExecutionMetrics,
): ScriptResult {
  // scriptPubKey must have at least 2 bytes: OP_SCRIPTTYPE + type
  if (scriptPubKey.length === 1) {
    return failure(ScriptError.SCRIPTTYPE_MALFORMED_SCRIPT)
  }

  if (scriptPubKey[1] === TAPROOT_SCRIPTTYPE) {
    return verifyTaprootSpend(
      stack,
      scriptSig,
      scriptPubKey,
      flags,
      checker,
      metrics,
    )
  }

  // Unknown script type
  return failure(ScriptError.SCRIPTTYPE_INVALID_TYPE)
}

/**
 * Verify post-conditions after script execution.
 *
 * Checks CLEANSTACK and INPUT_SIGCHECKS constraints.
 *
 * Reference: lotusd/src/script/interpreter.cpp VerifyScriptPostConditions()
 */
function verifyPostConditions(
  stack: StackElement[],
  scriptSig: Buffer,
  flags: number,
  metrics: ScriptExecutionMetrics,
): ScriptResult {
  if (flags & ScriptFlags.VERIFY_CLEANSTACK) {
    if (stack.length !== 1) {
      return failure(ScriptError.CLEANSTACK)
    }
  }

  if (flags & ScriptFlags.VERIFY_INPUT_SIGCHECKS) {
    if (scriptSig.length < metrics.sigChecks * 43 - 60) {
      return failure(ScriptError.INPUT_SIGCHECKS)
    }
  }

  return success()
}

// ─── VerifyScript ────────────────────────────────────────────────

/**
 * Verify a scriptSig + scriptPubKey pair.
 *
 * This is the main entry point for client-side transaction validation.
 * It evaluates scriptSig, then scriptPubKey, handling P2SH and
 * OP_SCRIPTTYPE (Taproot) dispatch.
 *
 * For a wallet building transactions, call this after signing to
 * confirm the transaction will be accepted by the network.
 *
 * @param scriptSig - The unlocking script (raw bytes)
 * @param scriptPubKey - The locking script (raw bytes)
 * @param flags - Script verification flags
 * @param checker - Signature verification interface
 * @returns ScriptResult with success status and error code
 */
export function verifyScript(
  scriptSig: Buffer,
  scriptPubKey: Buffer,
  flags: number,
  checker: SignatureChecker,
): ScriptResult {
  // scriptSig must be push-only
  if (!isPushOnly(scriptSig)) {
    return failure(ScriptError.SIG_PUSHONLY)
  }

  const metrics: ScriptExecutionMetrics = { sigChecks: 0 }

  // Step 1: Evaluate scriptSig onto the stack
  const stack: StackElement[] = []
  const sigExecdata = makeExecdata(BufferUtil.alloc(0))
  const sigResult = evalScript(
    stack,
    scriptSig,
    flags,
    checker,
    metrics,
    sigExecdata,
  )
  if (!sigResult.success) {
    return sigResult
  }

  // Step 2: Check for OP_SCRIPTTYPE (Taproot dispatch)
  if (scriptPubKey.length > 0 && scriptPubKey[0] === Opcode.OP_SCRIPTTYPE) {
    const stResult = verifyScriptType(
      stack,
      scriptSig,
      scriptPubKey,
      flags,
      checker,
      metrics,
    )
    return stResult
  }

  // Step 3: Evaluate scriptPubKey with the stack from scriptSig
  const stackCopy = stack.map(el => el.slice())
  const pubkeyExecdata = makeExecdata(scriptPubKey)
  const pubkeyResult = evalScript(
    stack,
    scriptPubKey,
    flags,
    checker,
    metrics,
    pubkeyExecdata,
  )
  if (!pubkeyResult.success) {
    return pubkeyResult
  }

  // Step 4: Check final stack state
  if (stack.length === 0) {
    return failure(ScriptError.EVAL_FALSE)
  }
  if (!castToBool(stack[stack.length - 1])) {
    return failure(ScriptError.EVAL_FALSE)
  }

  // Step 5: P2SH evaluation
  if (isPayToScriptHash(scriptPubKey)) {
    if (!isPushOnly(scriptSig)) {
      return failure(ScriptError.SIG_PUSHONLY)
    }

    // Restore stack from scriptSig evaluation
    const p2shStack = stackCopy
    if (p2shStack.length === 0) {
      return failure(ScriptError.EVAL_FALSE)
    }

    const serializedScript = p2shStack[p2shStack.length - 1]
    p2shStack.pop()

    const p2shExecdata = makeExecdata(serializedScript)
    const p2shResult = evalScript(
      p2shStack,
      serializedScript,
      flags,
      checker,
      metrics,
      p2shExecdata,
    )
    if (!p2shResult.success) {
      return p2shResult
    }

    if (p2shStack.length === 0) {
      return failure(ScriptError.EVAL_FALSE)
    }
    if (!castToBool(p2shStack[p2shStack.length - 1])) {
      return failure(ScriptError.EVAL_FALSE)
    }

    // Use P2SH stack for post-conditions
    stack.length = 0
    stack.push(...p2shStack)
  }

  // Step 6: Post-conditions (CLEANSTACK, INPUT_SIGCHECKS)
  return verifyPostConditions(stack, scriptSig, flags, metrics)
}

// ─── Script Classification Helpers ───────────────────────────────

/**
 * Check if a script is push-only (contains only data push opcodes).
 *
 * @param scriptBuf - Raw script bytes
 * @returns true if the script only contains push operations
 */
function isPushOnly(scriptBuf: Buffer): boolean {
  let offset = 0
  while (offset < scriptBuf.length) {
    const instr = readInstruction(scriptBuf, offset)
    if (!instr) {
      return false
    }
    // Any opcode > OP_16 is not a push
    if (instr.opcode > Opcode.OP_16) {
      return false
    }
    offset = instr.nextOffset
  }
  return true
}

/**
 * Check if a script is Pay-to-Script-Hash (P2SH).
 *
 * P2SH format: OP_HASH160 <20 bytes> OP_EQUAL
 *
 * @param scriptBuf - Raw script bytes
 * @returns true if the script matches P2SH pattern
 */
function isPayToScriptHash(scriptBuf: Buffer): boolean {
  return (
    scriptBuf.length === 23 &&
    scriptBuf[0] === Opcode.OP_HASH160 &&
    scriptBuf[1] === 0x14 &&
    scriptBuf[22] === Opcode.OP_EQUAL
  )
}

/**
 * Create a ScriptExecutionData for a given script.
 *
 * @param script - The script bytes to hash
 * @returns Initialized execution data
 */
function makeExecdata(script: Buffer): ScriptExecutionData {
  return {
    codeseparatorPos: 0xffffffff,
    executedScriptHash: Hash.sha256sha256(
      script.length > 0 ? script : BufferUtil.alloc(0),
    ),
  }
}

// ─── Interpreter Class (Backward Compatibility) ──────────────────

/**
 * Class-based wrapper around the functional interpreter API.
 *
 * Provides backward compatibility with existing code that expects:
 * - Static flag constants (e.g., `Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID`)
 * - An instance `verify()` method with transaction context
 * - An `errstr` property for error diagnostics
 *
 * New code should prefer the functional `evalScript()` / `verifyScript()`
 * API directly, using `ScriptFlags` enum for flag constants.
 */
export class Interpreter {
  /** Last error string from verify(), empty on success */
  errstr: string = ''

  // ─── Static Flag Constants ──────────────────────────────────
  // These match the ScriptFlags enum values for backward compat

  static SCRIPT_VERIFY_NONE = ScriptFlags.VERIFY_NONE
  static SCRIPT_TAPROOT_KEY_SPEND_PATH = ScriptFlags.TAPROOT_KEY_SPEND_PATH
  static SCRIPT_DISABLE_TAPROOT_SIGHASH_LOTUS =
    ScriptFlags.DISABLE_TAPROOT_SIGHASH_LOTUS
  static SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS =
    ScriptFlags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS
  static SCRIPT_VERIFY_CLEANSTACK = ScriptFlags.VERIFY_CLEANSTACK
  static SCRIPT_VERIFY_MINIMALIF = ScriptFlags.VERIFY_MINIMALIF
  static SCRIPT_ENABLE_SIGHASH_FORKID = ScriptFlags.ENABLE_SIGHASH_FORKID
  static SCRIPT_ENABLE_REPLAY_PROTECTION = ScriptFlags.ENABLE_REPLAY_PROTECTION
  static SCRIPT_VERIFY_INPUT_SIGCHECKS = ScriptFlags.VERIFY_INPUT_SIGCHECKS

  /**
   * Verify a scriptSig + scriptPubKey pair in the context of a transaction.
   *
   * This is the high-level entry point used by Transaction.verify().
   * It constructs a TransactionSignatureChecker from the provided
   * transaction context and delegates to verifyScript().
   *
   * @param scriptSig - The unlocking script
   * @param scriptPubKey - The locking script
   * @param tx - The spending transaction
   * @param nin - The input index being verified
   * @param flags - Script verification flags
   * @param satoshis - The value of the output being spent (for BIP143/Lotus sighash)
   * @returns true if verification succeeds
   */
  verify(
    scriptSig: Script,
    scriptPubKey: Script,
    tx: any,
    nin: number,
    flags: number,
    satoshis?: bigint,
  ): boolean {
    this.errstr = ''

    const sigBuf = scriptSig.toBuffer()
    const pubkeyBuf = scriptPubKey.toBuffer()

    const checker = new TransactionSignatureChecker(tx, nin, satoshis)
    const result = verifyScript(sigBuf, pubkeyBuf, flags, checker)

    if (!result.success) {
      this.errstr = result.error
    }

    return result.success
  }
}

// ─── TransactionSignatureChecker ─────────────────────────────────

/**
 * Signature checker that verifies signatures against a spending transaction.
 *
 * This bridges the interpreter's SignatureChecker interface with the
 * existing xpi-ts Transaction/Signature/Schnorr/ECDSA modules.
 *
 * Reference: lotusd TransactionSignatureChecker
 */
class TransactionSignatureChecker implements SignatureChecker {
  private tx: any
  private nin: number
  private satoshis: bigint | undefined

  constructor(tx: any, nin: number, satoshis?: bigint) {
    this.tx = tx
    this.nin = nin
    this.satoshis = satoshis
  }

  verifySignature(
    signature: Buffer,
    publicKey: Buffer,
    sighash: Buffer,
  ): boolean {
    try {
      // Import dynamically to avoid circular deps at module level
      const pubkey = PublicKey.fromBuffer(publicKey)

      if (isSchnorrSignature(signature)) {
        // Schnorr signature (64 bytes)
        const sig = Signature.fromSchnorr(signature)
        return Schnorr.verify(sighash, sig, pubkey)
      } else {
        // ECDSA signature (DER-encoded)
        const sig = Signature.fromDER(signature)
        const ecdsa = new ECDSA()
        ecdsa.hashbuf = sighash
        ecdsa.sig = sig
        ecdsa.pubkey = pubkey
        ecdsa.verify()
        return ecdsa.verified
      }
    } catch {
      return false
    }
  }

  checkSignature(
    signature: Buffer,
    publicKey: Buffer,
    execdata: ScriptExecutionData | undefined,
    scriptCode: Buffer,
    flags: number,
  ): boolean {
    if (signature.length === 0) {
      return false
    }

    try {
      // Extract sighash type from last byte
      const hashtype = signature[signature.length - 1]

      // Raw signature without sighash byte
      // Schnorr tx-format: 64-byte sig + 1-byte sighash = 65 bytes
      // ECDSA tx-format: DER sig (variable) + 1-byte sighash
      const rawSig = signature.slice(0, signature.length - 1)

      // Compute the sighash for this input
      const subscript = Script.fromBuffer(scriptCode)
      const sighashBuf = computeSighash(
        this.tx,
        hashtype,
        this.nin,
        subscript,
        this.satoshis !== undefined
          ? BN.fromNumber(Number(this.satoshis))
          : undefined,
        flags,
      )

      return this.verifySignature(rawSig, publicKey, sighashBuf)
    } catch {
      return false
    }
  }

  checkLockTime(lockTime: bigint): boolean {
    const LOCKTIME_THRESHOLD = 500_000_000n

    // nLockTime type must match: both block height or both timestamp
    const txLockTime = BigInt(this.tx.nLockTime || 0)
    if (
      (txLockTime < LOCKTIME_THRESHOLD && lockTime >= LOCKTIME_THRESHOLD) ||
      (txLockTime >= LOCKTIME_THRESHOLD && lockTime < LOCKTIME_THRESHOLD)
    ) {
      return false
    }

    // Lock time must be satisfied
    if (lockTime > txLockTime) {
      return false
    }

    // Input must not be finalized (sequence != 0xffffffff)
    const input = this.tx.inputs?.[this.nin]
    if (input && input.sequenceNumber === 0xffffffff) {
      return false
    }

    return true
  }

  checkSequence(sequence: bigint): boolean {
    const SEQUENCE_LOCKTIME_DISABLE_FLAG = 1n << 31n
    const SEQUENCE_LOCKTIME_TYPE_FLAG = 1n << 22n
    const SEQUENCE_LOCKTIME_MASK = 0x0000ffffn

    // Sequence disable flag means CSV is satisfied
    if (sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) {
      return true
    }

    // Transaction version must be >= 2
    const txVersion = this.tx.version || 1
    if (txVersion < 2) {
      return false
    }

    const input = this.tx.inputs?.[this.nin]
    if (!input) {
      return false
    }

    const txSequence = BigInt(input.sequenceNumber || 0)

    // Disable flag on the input means it's not locked
    if (txSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) {
      return false
    }

    // Type must match (both time-based or both height-based)
    if (
      (sequence & SEQUENCE_LOCKTIME_TYPE_FLAG) !==
      (txSequence & SEQUENCE_LOCKTIME_TYPE_FLAG)
    ) {
      return false
    }

    // Masked value must be satisfied
    if (
      (sequence & SEQUENCE_LOCKTIME_MASK) >
      (txSequence & SEQUENCE_LOCKTIME_MASK)
    ) {
      return false
    }

    return true
  }
}

/**
 * Copyright 2025-2026 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * Script Interpreter Types and Constants
 *
 * Defines all types, error codes, script flags, and constants used by
 * the Lotus script interpreter. These mirror the lotusd consensus rules
 * but are tailored for client-side transaction validation.
 *
 * Reference: lotusd/src/script/script.h, script_flags.h, script_error.h
 *
 * @module InterpreterTypes
 */

import type { Buffer } from 'buffer/'
import { Script } from '../../script'

// ─── Script Limits ──────────────────────────────────────────────────

/** Maximum number of bytes pushable to the stack */
export const MAX_SCRIPT_ELEMENT_SIZE = 520

/** Maximum number of non-push operations per script */
export const MAX_OPS_PER_SCRIPT = 400

/** Maximum number of public keys per multisig */
export const MAX_PUBKEYS_PER_MULTISIG = 20

/** Maximum script length in bytes */
export const MAX_SCRIPT_SIZE = 10_000

/** Maximum number of values on script interpreter stack */
export const MAX_STACK_SIZE = 1_000

/** Maximum number of bytes OP_NUM2BIN can produce */
export const MAX_NUM2BIN_SIZE = 68

/**
 * Threshold for nLockTime: below this value it is interpreted as
 * block number, otherwise as UNIX timestamp.
 */
export const LOCKTIME_THRESHOLD = 500_000_000

/** Maximum element size for CScriptNum (8 bytes = int64 range) */
export const SCRIPTNUM_MAX_ELEMENT_SIZE = 8

// ─── Script Verification Flags ──────────────────────────────────────

/**
 * Script verification flags matching lotusd consensus.
 *
 * For client-side validation, the standard set of flags should be used
 * to ensure crafted transactions will pass node validation.
 */
export enum ScriptFlags {
  VERIFY_NONE = 0,

  /** Require Lotus sighash and Schnorr for Taproot key spend */
  TAPROOT_KEY_SPEND_PATH = 1 << 0,

  /** Disable Taproot scripts and SIGHASH_LOTUS */
  DISABLE_TAPROOT_SIGHASH_LOTUS = 1 << 1,

  /** Discourage upgradable NOPs (NOP1, NOP4-NOP10) */
  VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7,

  /** Require exactly one stack element after evaluation */
  VERIFY_CLEANSTACK = 1 << 8,

  /** Require OP_IF/NOTIF argument to be exactly 0x01 or empty */
  VERIFY_MINIMALIF = 1 << 13,

  /** Accept SIGHASH_FORKID or SIGHASH_LOTUS signatures */
  ENABLE_SIGHASH_FORKID = 1 << 16,

  /** Activate replay protection with different fork id */
  ENABLE_REPLAY_PROTECTION = 1 << 17,

  /** Require sigchecks in input to satisfy scriptSig length bound */
  VERIFY_INPUT_SIGCHECKS = 1 << 22,
}

/**
 * Standard flags for client-side transaction validation.
 *
 * This combination matches what lotusd uses for mempool acceptance,
 * ensuring crafted transactions will be accepted by the network.
 */
export const STANDARD_SCRIPT_VERIFY_FLAGS =
  ScriptFlags.VERIFY_CLEANSTACK |
  ScriptFlags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
  ScriptFlags.VERIFY_MINIMALIF |
  ScriptFlags.ENABLE_SIGHASH_FORKID |
  ScriptFlags.VERIFY_INPUT_SIGCHECKS

// ─── Script Error Codes ─────────────────────────────────────────────

/**
 * Script execution error codes matching lotusd ScriptError enum.
 *
 * These provide detailed failure reasons for script evaluation,
 * enabling client-side wallets to diagnose why a transaction
 * would be rejected before broadcasting.
 */
export enum ScriptError {
  OK = 'OK',
  UNKNOWN = 'UNKNOWN',
  EVAL_FALSE = 'EVAL_FALSE',
  OP_RETURN = 'OP_RETURN',

  // Size limits
  SCRIPT_SIZE = 'SCRIPT_SIZE',
  PUSH_SIZE = 'PUSH_SIZE',
  OP_COUNT = 'OP_COUNT',
  STACK_SIZE = 'STACK_SIZE',
  SIG_COUNT = 'SIG_COUNT',
  PUBKEY_COUNT = 'PUBKEY_COUNT',
  INPUT_SIGCHECKS = 'INPUT_SIGCHECKS',

  // Operand checks
  INVALID_OPERAND_SIZE = 'INVALID_OPERAND_SIZE',
  INVALID_NUMBER_RANGE = 'INVALID_NUMBER_RANGE',
  IMPOSSIBLE_ENCODING = 'IMPOSSIBLE_ENCODING',
  INVALID_SPLIT_RANGE = 'INVALID_SPLIT_RANGE',
  INVALID_BIT_COUNT = 'INVALID_BIT_COUNT',

  // Failed verify operations
  VERIFY = 'VERIFY',
  EQUALVERIFY = 'EQUALVERIFY',
  CHECKMULTISIGVERIFY = 'CHECKMULTISIGVERIFY',
  CHECKSIGVERIFY = 'CHECKSIGVERIFY',
  CHECKDATASIGVERIFY = 'CHECKDATASIGVERIFY',
  NUMEQUALVERIFY = 'NUMEQUALVERIFY',

  // Logical/Format/Canonical errors
  BAD_OPCODE = 'BAD_OPCODE',
  DISABLED_OPCODE = 'DISABLED_OPCODE',
  INVALID_STACK_OPERATION = 'INVALID_STACK_OPERATION',
  INVALID_ALTSTACK_OPERATION = 'INVALID_ALTSTACK_OPERATION',
  UNBALANCED_CONDITIONAL = 'UNBALANCED_CONDITIONAL',

  // Divisor errors
  DIV_BY_ZERO = 'DIV_BY_ZERO',
  MOD_BY_ZERO = 'MOD_BY_ZERO',

  // Bitfield errors
  INVALID_BITFIELD_SIZE = 'INVALID_BITFIELD_SIZE',
  INVALID_BIT_RANGE = 'INVALID_BIT_RANGE',

  // CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY
  NEGATIVE_LOCKTIME = 'NEGATIVE_LOCKTIME',
  UNSATISFIED_LOCKTIME = 'UNSATISFIED_LOCKTIME',

  // Malleability
  SIG_HASHTYPE = 'SIG_HASHTYPE',
  SIG_DER = 'SIG_DER',
  MINIMALDATA = 'MINIMALDATA',
  SIG_PUSHONLY = 'SIG_PUSHONLY',
  SIG_HIGH_S = 'SIG_HIGH_S',
  PUBKEYTYPE = 'PUBKEYTYPE',
  CLEANSTACK = 'CLEANSTACK',
  MINIMALIF = 'MINIMALIF',
  SIG_NULLFAIL = 'SIG_NULLFAIL',

  // Schnorr
  SIG_BADLENGTH = 'SIG_BADLENGTH',
  SIG_NONSCHNORR = 'SIG_NONSCHNORR',

  // Softfork safeness
  DISCOURAGE_UPGRADABLE_NOPS = 'DISCOURAGE_UPGRADABLE_NOPS',

  // Anti replay
  ILLEGAL_FORKID = 'ILLEGAL_FORKID',
  MUST_USE_FORKID = 'MUST_USE_FORKID',

  // OP_NUM2BIN
  INVALID_NUM2BIN_SIZE = 'INVALID_NUM2BIN_SIZE',

  // OP_SCRIPTTYPE
  INVALID_OP_SCRIPTTYPE = 'INVALID_OP_SCRIPTTYPE',
  SCRIPTTYPE_INVALID_TYPE = 'SCRIPTTYPE_INVALID_TYPE',
  SCRIPTTYPE_MALFORMED_SCRIPT = 'SCRIPTTYPE_MALFORMED_SCRIPT',

  // Taproot
  TAPROOT_KEY_SPEND_MUST_USE_LOTUS_SIGHASH = 'TAPROOT_KEY_SPEND_MUST_USE_LOTUS_SIGHASH',
  TAPROOT_KEY_SPEND_MUST_USE_SCHNORR_SIG = 'TAPROOT_KEY_SPEND_MUST_USE_SCHNORR_SIG',
  TAPROOT_VERIFY_SIGNATURE_FAILED = 'TAPROOT_VERIFY_SIGNATURE_FAILED',
  TAPROOT_ANNEX_NOT_SUPPORTED = 'TAPROOT_ANNEX_NOT_SUPPORTED',
  TAPROOT_WRONG_CONTROL_SIZE = 'TAPROOT_WRONG_CONTROL_SIZE',
  TAPROOT_VERIFY_COMMITMENT_FAILED = 'TAPROOT_VERIFY_COMMITMENT_FAILED',
  TAPROOT_LEAF_VERSION_NOT_SUPPORTED = 'TAPROOT_LEAF_VERSION_NOT_SUPPORTED',
  TAPROOT_PHASEOUT = 'TAPROOT_PHASEOUT',
}

// ─── Interpreter Result Types ───────────────────────────────────────

/**
 * Result of script evaluation or verification.
 *
 * Provides both the success/failure boolean and a detailed error code
 * for diagnostics. Client-side wallets can use the error code to
 * provide meaningful feedback about why a transaction would fail.
 */
export interface ScriptResult {
  /** Whether the script evaluation succeeded */
  success: boolean
  /** Detailed error code (ScriptError.OK on success) */
  error: ScriptError
}

/**
 * Metrics collected during script execution.
 *
 * Tracks signature check count for INPUT_SIGCHECKS validation.
 */
export interface ScriptExecutionMetrics {
  /** Number of signature checks performed */
  sigChecks: number
}

/**
 * Data generated during script execution for sighash computation.
 *
 * Reference: lotusd/src/script/script_exec_data.h
 */
export interface ScriptExecutionData {
  /** Opcode position of the last executed OP_CODESEPARATOR */
  codeseparatorPos: number
  /** SHA-256d of the complete script being executed */
  executedScriptHash: Buffer
}

/**
 * Interface for signature verification during script execution.
 *
 * Client-side implementations provide transaction context so the
 * interpreter can verify signatures against the spending transaction.
 *
 * Reference: lotusd BaseSignatureChecker / TransactionSignatureChecker
 */
export interface SignatureChecker {
  /**
   * Verify a raw signature against a sighash
   *
   * @param signature - The raw signature bytes (without sighash byte)
   * @param publicKey - The public key bytes
   * @param sighash - The 32-byte sighash to verify against
   * @returns true if the signature is valid
   */
  verifySignature(
    signature: Buffer,
    publicKey: Buffer,
    sighash: Buffer,
  ): boolean

  /**
   * Check a transaction signature (with sighash type byte appended)
   *
   * @param signature - Signature with sighash type byte
   * @param publicKey - The public key bytes
   * @param execdata - Script execution data for sighash computation
   * @param scriptCode - The script code for sighash computation
   * @param flags - Script verification flags
   * @returns true if the signature is valid
   */
  checkSignature(
    signature: Buffer,
    publicKey: Buffer,
    execdata: ScriptExecutionData | undefined,
    scriptCode: Buffer,
    flags: number,
  ): boolean

  /**
   * Check OP_CHECKLOCKTIMEVERIFY constraint
   *
   * @param lockTime - The lock time value from the stack
   * @returns true if the lock time constraint is satisfied
   */
  checkLockTime(lockTime: bigint): boolean

  /**
   * Check OP_CHECKSEQUENCEVERIFY constraint
   *
   * @param sequence - The sequence value from the stack
   * @returns true if the sequence constraint is satisfied
   */
  checkSequence(sequence: bigint): boolean
}

/**
 * A no-op signature checker that always returns false.
 *
 * Used when evaluating scripts that should not contain signature
 * operations (e.g., scriptSig evaluation in isolation).
 */
export const NULL_SIGNATURE_CHECKER: SignatureChecker = {
  verifySignature: () => false,
  checkSignature: () => false,
  checkLockTime: () => false,
  checkSequence: () => false,
}

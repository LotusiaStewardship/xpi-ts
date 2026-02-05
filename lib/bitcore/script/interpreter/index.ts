/**
 * Copyright 2025-2026 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * Script Interpreter Module Barrel Export
 *
 * Re-exports all public types, constants, and functions from the
 * interpreter module for convenient consumption.
 *
 * Usage:
 * ```typescript
 * import {
 *   verifyScript,
 *   evalScript,
 *   ScriptError,
 *   ScriptFlags,
 *   STANDARD_SCRIPT_VERIFY_FLAGS,
 * } from './script/interpreter-index'
 * ```
 *
 * @module InterpreterIndex
 */

// Types, constants, and interfaces
export {
  MAX_SCRIPT_ELEMENT_SIZE,
  MAX_OPS_PER_SCRIPT,
  MAX_PUBKEYS_PER_MULTISIG,
  MAX_SCRIPT_SIZE,
  MAX_STACK_SIZE,
  MAX_NUM2BIN_SIZE,
  LOCKTIME_THRESHOLD,
  SCRIPTNUM_MAX_ELEMENT_SIZE,
  STANDARD_SCRIPT_VERIFY_FLAGS,
  ScriptFlags,
  ScriptError,
  NULL_SIGNATURE_CHECKER,
  type ScriptResult,
  type ScriptExecutionMetrics,
  type ScriptExecutionData,
  type SignatureChecker,
} from './types'

// Script number arithmetic
export { ScriptNum, ScriptNumError } from './script-num'

// Condition stack for IF/ELSE/ENDIF
export { ConditionStack } from './condition-stack'

// Core interpreter functions and class
export { evalScript, verifyScript, Interpreter } from './interpreter'

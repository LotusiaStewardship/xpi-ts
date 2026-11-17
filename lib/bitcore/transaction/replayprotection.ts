/**
 * Replay protection (Lotus "First Chronicles") for signers.
 *
 * Once the median time past (MTP) of the chain tip reaches the activation
 * time, the node validates the NEXT block with SCRIPT_ENABLE_REPLAY_PROTECTION.
 * With that flag the interpreter hashes every signature with the sighash
 * fork value 0xff0000 | (0 ^ 0xdead) = 0xffdead instead of 0.
 *
 * A signer that wants its transaction to be valid in the next block must
 * therefore compute the sighash with the fork value of the rules of the next
 * block:
 *
 *   tip MTP >= activation time  ->  0xffdead
 *   otherwise (or no tip)       ->  0
 *
 * The tip MTP is `mediantime` in the node's getblockchaininfo.
 *
 * The fork value sits in the upper 24 bits of the 32-bit sighash type and is
 * part of the sighash preimage, but it never appears on the wire: the
 * signature in the scriptSig only carries the low byte of the sighash type.
 *
 * Activation time, in order of precedence:
 *   1. an explicit `activationTime` argument (e.g. a regtest node started
 *      with -replayprotectionactivationtime)
 *   2. the environment variable LOTUS_REPLAY_PROTECTION_ACTIVATION_TIME
 *      (integer seconds; read only where `process` exists, ignored in
 *      browsers)
 *   3. the built-in chain parameter (REPLAY_PROTECTION_ACTIVATION_TIME)
 *
 * The library never derives the fork value from the wall clock: an untouched
 * Transaction signs with fork value 0, and callers pick the value from the
 * chain state (getNextBlockSighashForkValue(), getReplayProtectionWindow()).
 *
 * Nothing here is consensus: this module only picks what a signer hashes.
 */

import { Interpreter } from '../script/interpreter'
import { Network, get as getNetwork } from '../networks'

/** Fork value of every signature before First Chronicles. */
export const SIGHASH_FORK_VALUE_DEFAULT = 0

/**
 * Fork value the interpreter uses once SCRIPT_ENABLE_REPLAY_PROTECTION is
 * set: 0xff0000 | (SIGHASH_FORK_VALUE_DEFAULT ^ 0xdead).
 */
export const SIGHASH_FORK_VALUE_REPLAY_PROTECTED = 0xffdead

/**
 * First Chronicles activation time (MTP of the parent block) per network,
 * as in the node's chain parameters (firstChroniclesActivationTime):
 * - mainnet: 1813587000
 * - testnet: mainnet - 21 days
 * - regtest: same as mainnet (tests override it with
 *   -replayprotectionactivationtime)
 */
export const REPLAY_PROTECTION_ACTIVATION_TIME: Readonly<
  Record<'livenet' | 'testnet' | 'regtest', number>
> = Object.freeze({
  livenet: 1813587000,
  testnet: 1813587000 - 21 * 24 * 3600,
  regtest: 1813587000,
})

/** The only two fork values a Lotus node will ever accept. */
export function isKnownSighashForkValue(forkValue: number): boolean {
  return (
    forkValue === SIGHASH_FORK_VALUE_DEFAULT ||
    forkValue === SIGHASH_FORK_VALUE_REPLAY_PROTECTED
  )
}

/** Fork value carried by a 32-bit sighash type (its upper 24 bits). */
export function getSighashForkValue(sighashType: number): number {
  return (sighashType >>> 8) & 0xffffff
}

/**
 * Same as the node's SigHashType::withForkValue(): keep the low byte (base type,
 * algorithm, ANYONECANPAY) and put `forkValue` in the upper 24 bits.
 * Always returns an unsigned 32-bit number.
 */
export function withSighashForkValue(
  sighashType: number,
  forkValue: number,
): number {
  if (!Number.isInteger(forkValue) || forkValue < 0 || forkValue > 0xffffff) {
    throw new Error(`Invalid sighash fork value: ${forkValue}`)
  }
  return ((forkValue << 8) | (sighashType & 0xff)) >>> 0
}

/**
 * Script flags under which a signature made with `forkValue` verifies:
 * the replay-protection flag maps the signature's fork value 0 onto
 * 0xffdead, so a signature hashed with 0xffdead only verifies with it.
 */
export function replayProtectionFlagsForForkValue(forkValue: number): number {
  return forkValue === SIGHASH_FORK_VALUE_REPLAY_PROTECTED
    ? Interpreter.SCRIPT_ENABLE_REPLAY_PROTECTION
    : 0
}

function networkName(
  network?: Network | string,
): 'livenet' | 'testnet' | 'regtest' {
  if (network === undefined || network === null) {
    return 'livenet'
  }
  if (typeof network === 'string') {
    const n = network.toLowerCase()
    // node chain names ("main", "test", "regtest") and xpi-ts names
    if (n === 'main' || n === 'mainnet' || n === 'livenet') return 'livenet'
    if (n === 'test' || n === 'testnet') return 'testnet'

    if (n === 'regtest') return 'regtest'
    const found = getNetwork(network)
    if (found) return found.name as 'livenet' | 'testnet' | 'regtest'
    throw new Error(`Unknown network: ${network}`)
  }
  return network.name as 'livenet' | 'testnet' | 'regtest'
}

/**
 * Environment variable that overrides the built-in activation time when no
 * explicit activation time is given. Integer seconds.
 * Meant for test setups (e.g. a regtest node started with
 * -replayprotectionactivationtime); it applies to every network.
 */
export const REPLAY_PROTECTION_ACTIVATION_TIME_ENV =
  'LOTUS_REPLAY_PROTECTION_ACTIVATION_TIME'

/**
 * Activation time from LOTUS_REPLAY_PROTECTION_ACTIVATION_TIME, or undefined
 * when it is unset/empty or when there is no `process` (browsers). A value
 * that is not a non-negative integer throws: silently signing with the
 * wrong fork value would be worse.
 */
function envActivationTime(): number | undefined {
  if (typeof process === 'undefined' || !process || !process.env) {
    return undefined
  }
  const raw = process.env[REPLAY_PROTECTION_ACTIVATION_TIME_ENV]
  if (raw === undefined || raw.trim() === '') {
    return undefined
  }
  const value = raw.trim()
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new Error(
      `Invalid ${REPLAY_PROTECTION_ACTIVATION_TIME_ENV}: ${JSON.stringify(raw)} (expected integer seconds)`,
    )
  }
  return Number(value)
}

/**
 * Activation time of replay protection for `network`. An explicit
 * `override` (e.g. a regtest node run with
 * -replayprotectionactivationtime) wins; then the environment
 * variable LOTUS_REPLAY_PROTECTION_ACTIVATION_TIME (only where `process`
 * exists); then the built-in chain parameter.
 */
export function getReplayProtectionActivationTime(
  network?: Network | string,
  override?: number | null,
): number {
  if (typeof override === 'number' && Number.isFinite(override)) {
    return override
  }
  // validate the network name even when the environment overrides the time
  const builtIn = REPLAY_PROTECTION_ACTIVATION_TIME[networkName(network)]
  const fromEnv = envActivationTime()
  return fromEnv !== undefined ? fromEnv : builtIn
}

/**
 * Same predicate as the node's IsReplayProtectionEnabled(): true when the
 * block AFTER the tip is validated with SCRIPT_ENABLE_REPLAY_PROTECTION,
 * i.e. tip MTP >= activation time. No tip (undefined/null) -> false.
 */
export function isReplayProtectionEnabledForNextBlock(
  tipMedianTimePast: number | null | undefined,
  activationTime: number,
): boolean {
  if (
    typeof tipMedianTimePast !== 'number' ||
    !Number.isFinite(tipMedianTimePast)
  ) {
    return false
  }
  return tipMedianTimePast >= activationTime
}

export interface NextBlockForkValueArgs {
  /** Median time past of the current chain tip (seconds). */
  tipMedianTimePast: number | null | undefined
  /**
   * Network (xpi-ts Network, or a name: livenet/main/mainnet,
   * testnet/test, regtest).
   */
  network?: Network | string
  /** Explicit activation time, if any (wins over the default). */
  activationTime?: number | null
}

/**
 * Fork value a signer must use for a transaction to be valid in the next
 * block.
 */
export function getNextBlockSighashForkValue(
  args: NextBlockForkValueArgs,
): number {
  const activation = getReplayProtectionActivationTime(
    args.network,
    args.activationTime,
  )
  return isReplayProtectionEnabledForNextBlock(
    args.tipMedianTimePast,
    activation,
  )
    ? SIGHASH_FORK_VALUE_REPLAY_PROTECTED
    : SIGHASH_FORK_VALUE_DEFAULT
}

function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v)
}

/** Default margin around the activation time flagged as `nearBoundary`. */
export const REPLAY_PROTECTION_DEFAULT_MARGIN_SECONDS = 3600

export interface ReplayProtectionStatus {
  /** Fork value to sign with for the next block (0 or 0xffdead). */
  forkValue: number
  /** True when the next block is validated with replay protection. */
  active: boolean
  /** Activation time used for the window. */
  activationTime: number
  /** activationTime - tip MTP; negative once the activation is past. */
  secondsToActivation: number
  /**
   * |activationTime - tip MTP| <= margin: the fork value may flip between
   * reading the tip and the transaction reaching a block (or a
   * reorg may flip it back). Warn, hold, or be ready to re-sign.
   */
  nearBoundary: boolean
}

export interface ReplayProtectionWindowArgs {
  /** Median time past of the current chain tip (seconds). Required. */
  tipMedianTimePast: number
  network?: Network | string
  /** Explicit activation time (wins over env var and built-in). */
  activationTime?: number | null
  /** Margin for `nearBoundary`, seconds (default 3600). */
  marginSeconds?: number
}

function checkMargin(margin: number): number {
  if (!isFiniteNumber(margin) || margin < 0) {
    throw new Error(`Invalid replay protection margin: ${margin}`)
  }
  return margin
}

/**
 * Where the tip stands relative to the activation time, from the tip MTP
 * alone (next-block rule).
 */
export function getReplayProtectionWindow(
  args: ReplayProtectionWindowArgs,
): ReplayProtectionStatus {
  if (!isFiniteNumber(args.tipMedianTimePast)) {
    throw new Error('tipMedianTimePast is required for the replay window')
  }
  const margin = checkMargin(
    args.marginSeconds ?? REPLAY_PROTECTION_DEFAULT_MARGIN_SECONDS,
  )
  const activationTime = getReplayProtectionActivationTime(
    args.network,
    args.activationTime,
  )
  const active = isReplayProtectionEnabledForNextBlock(
    args.tipMedianTimePast,
    activationTime,
  )
  const secondsToActivation = activationTime - args.tipMedianTimePast
  return {
    forkValue: active
      ? SIGHASH_FORK_VALUE_REPLAY_PROTECTED
      : SIGHASH_FORK_VALUE_DEFAULT,
    active,
    activationTime,
    secondsToActivation,
    nearBoundary: Math.abs(secondsToActivation) <= margin,
  }
}

const REFUSAL_PATTERN =
  /mandatory-script-verify-flag|non-mandatory-script-verify-flag|script-verify/i

function errorMessage(err: unknown, depth = 0): string | undefined {
  if (typeof err === 'string') return err
  if (!err || typeof err !== 'object' || depth > 2) return undefined
  const o = err as { message?: unknown; error?: unknown }
  if (typeof o.message === 'string') return o.message
  // JSON-RPC style {error: {message}} or {error: "..."}
  if (o.error !== undefined) return errorMessage(o.error, depth + 1)
  return undefined
}

/**
 * True when a broadcast error looks like a script verification refusal,
 * which is what a signature made with the wrong fork value gets
 * ("mandatory-script-verify-flag-failed ..."). Accepts a string, an Error,
 * or any object with a `message` (or a JSON-RPC `error`). On such a
 * refusal: read the tip again, re-sign once, broadcast again.
 */
export function isReplayProtectionRefusal(err: unknown): boolean {
  const msg = errorMessage(err)
  return typeof msg === 'string' && REFUSAL_PATTERN.test(msg)
}

// ─── Time-locked transactions ────────────────────────────────────

/** nLockTime at or above this is a timestamp (BIP65/BIP113), below a height. */
const LOCKTIME_THRESHOLD = 500000000
/** A final input: nLockTime is ignored when every input has it. */
const SEQUENCE_FINAL = 0xffffffff

/** What getSighashForkValueForTransaction() reads from a transaction. */
export interface TimeLockedTransactionLike {
  nLockTime: number
  inputs: ReadonlyArray<{ sequenceNumber: number }>
}

/**
 * Fork value for a transaction that may only become minable later.
 *
 * - The next block already uses 0xffdead: 0xffdead.
 * - The transaction is timestamp-locked (nLockTime >= 500000000), its lock
 *   is enforced (at least one input has sequence != 0xffffffff), and
 *   nLockTime >= activationTime - 1: 0xffdead. Under BIP113 such a
 *   transaction is final only in a block whose parent MTP > nLockTime, so
 *   parent MTP >= activationTime: every block that can include it is
 *   validated with replay protection, even though the next block is not.
 * - Otherwise: the next-block value.
 *
 * Height locks are not mapped: when a future height will be reached, and
 * which MTP its parent will have, is unknown in advance, so there is no
 * safe answer. Sign a height-locked transaction close to its height, with
 * the fork value of that time.
 */
export function getSighashForkValueForTransaction(
  tx: TimeLockedTransactionLike,
  nextBlockForkValue: number,
  activationTime: number,
): number {
  if (!isKnownSighashForkValue(nextBlockForkValue)) {
    throw new Error(
      `Unsupported sighash fork value ${nextBlockForkValue} (expected 0 or 0xffdead)`,
    )
  }
  if (nextBlockForkValue === SIGHASH_FORK_VALUE_REPLAY_PROTECTED) {
    return nextBlockForkValue
  }
  if (!isFiniteNumber(activationTime)) {
    throw new Error(`Invalid activation time: ${activationTime}`)
  }
  const lockTime = Number(tx.nLockTime)
  if (!(lockTime >= LOCKTIME_THRESHOLD)) {
    return nextBlockForkValue
  }
  const lockEnforced = tx.inputs.some(
    input => Number(input.sequenceNumber) !== SEQUENCE_FINAL,
  )
  if (lockEnforced && lockTime >= activationTime - 1) {
    return SIGHASH_FORK_VALUE_REPLAY_PROTECTED
  }
  return nextBlockForkValue
}

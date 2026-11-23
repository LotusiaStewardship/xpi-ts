/**
 * Chain identity constants for Lotus
 *
 * Lotus commits every signature to a chain-specific fork id once replay
 * protection is active. The value is implicit in the signature — it is not
 * carried in the transaction — so a signer has to choose the same value the
 * verifying node derives from its script flags.
 *
 * Reference: lotusd/src/script/sighashtype.h (CHAIN_FORK_ID)
 * Reference: lotusd/src/validation.cpp (IsReplayProtectionEnabled)
 */

/**
 * The Lotus chain's fork id, committed by every signature while replay
 * protection is active.
 *
 * A signature made for this value is invalid on any chain using a different
 * fork id, including Napoleon running the stock `0xffdead` transform, and a
 * signature made for another chain is invalid here.
 *
 * Do not change this value without a coordinated hard fork.
 */
export const CHAIN_FORK_ID = 0x4c4f54 // "LOT"

/** `CHAIN_FORK_ID` in hex, for messages and documentation. */
export const CHAIN_FORK_ID_HEX = `0x${CHAIN_FORK_ID.toString(16)}`

/**
 * Mainnet replay-protection activation: the median-time-past threshold at the
 * 2nd Kings boundary, 2026-12-21 20:50 UTC.
 *
 * Reference: lotusd/src/chainparams.cpp (secondKingsActivationTime)
 */
export const REPLAY_PROTECTION_ACTIVATION_TIME = 1797886200

/**
 * Testnet activation, 21 days ahead of mainnet so wallets and nodes can
 * rehearse the boundary.
 */
export const TESTNET_REPLAY_PROTECTION_ACTIVATION_TIME =
  REPLAY_PROTECTION_ACTIVATION_TIME - 21 * 24 * 60 * 60

/**
 * How long past the activation timestamp the automatic policy waits before
 * signing with the chain fork id.
 *
 * Replay protection switches on when the previous block's median time past
 * reaches the activation timestamp. MTP is the median of the last 11 block
 * timestamps, so on Lotus's 2-minute block spacing it trails wall clock by
 * roughly 12 minutes, and block-production jitter stretches that further.
 * Signing with the new fork id before MTP crosses produces transactions the
 * network rejects; this margin keeps the default policy on the safe side.
 */
export const REPLAY_PROTECTION_ACTIVATION_MARGIN = 30 * 60

/**
 * The only fork ids a Lotus signature can commit to.
 *
 * `0` is the pre-activation value every chain accepts; `CHAIN_FORK_ID` is the
 * post-activation value only Lotus accepts. Any other value verifies on
 * neither side of the split.
 */
export type ForkId = 0 | typeof CHAIN_FORK_ID

/**
 * How a signer chooses its fork id.
 *
 * `'auto'` follows the mainnet activation. A number pins the value, which
 * tests, regtest nodes, testnet callers and anyone who knows the chain's
 * median time past should use; `'auto'` does not know about testnet's earlier
 * activation.
 */
export type ForkIdPolicy = 'auto' | ForkId

/**
 * The fork id implied by a wall-clock time under the automatic policy.
 *
 * @param unixSeconds - Time to evaluate, in seconds since the epoch
 * @param activationTime - MTP activation threshold for the network
 * @returns `CHAIN_FORK_ID` once the activation and safety margin have passed,
 *   otherwise `0`
 */
export function chainForkIdAt(
  unixSeconds: number = Math.floor(Date.now() / 1000),
  activationTime: number = REPLAY_PROTECTION_ACTIVATION_TIME,
): ForkId {
  return unixSeconds >= activationTime + REPLAY_PROTECTION_ACTIVATION_MARGIN
    ? CHAIN_FORK_ID
    : 0
}

/**
 * Resolve a fork id policy to the value a signature must commit to.
 *
 * @param policy - Policy to resolve; `undefined` is treated as `'auto'`
 * @param unixSeconds - Time used by the automatic policy
 * @returns The resolved fork id
 * @throws Error if the policy is a fork id this chain cannot verify
 */
export function resolveForkId(
  policy: ForkIdPolicy | undefined,
  unixSeconds?: number,
): ForkId {
  if (policy === undefined || policy === 'auto') {
    return chainForkIdAt(unixSeconds)
  }

  if (policy === 0 || policy === CHAIN_FORK_ID) {
    return policy
  }

  // Unreachable for typed callers; JavaScript callers can pass any number.
  const invalid = policy as unknown as number
  throw new Error(
    `Invalid Lotus fork id 0x${invalid.toString(16)}: only 0 (pre-activation) ` +
      `and ${CHAIN_FORK_ID_HEX} (${CHAIN_FORK_ID}) verify on this chain`,
  )
}

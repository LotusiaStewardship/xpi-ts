/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */

/**
 * Taproot + MuSig2 Integration
 *
 * This module provides integration between MuSig2 key aggregation and
 * Taproot outputs, enabling privacy-preserving multi-signature spending
 * via Taproot key paths.
 *
 * Key Features:
 * - Use MuSig2 aggregated keys as Taproot internal keys
 * - Handle Taproot tweaking for aggregated keys
 * - Support both key-path and script-path spending
 * - Full compatibility with existing Taproot implementation
 *
 * @module TaprootMuSig
 */

import { PublicKey } from '../publickey.js'
import { PrivateKey } from '../privatekey.js'
import { Address } from '../address.js'
import { Script } from '../script.js'
import { BN, Point, Hash } from '../crypto/index.js'
import {
  musigKeyAgg,
  musigPartialSign,
  musigPartialSigVerify,
  type MuSigKeyAggContext,
  type MuSigNonce,
  type MuSigAggregatedNonce,
  musigTaggedHash,
  MUSIG_TAG_NONCE_COEFF,
} from '../crypto/musig2.js'
import {
  buildKeyPathTaproot,
  buildScriptPathTaproot,
  calculateTapTweak,
  tweakPublicKey,
  tweakPrivateKey,
  type TapNode,
  type TapLeaf,
} from '../taproot.js'

/**
 * Result of MuSig2 Taproot key creation
 */
export interface MuSigTaprootKeyResult {
  /** Aggregated public key (before Taproot tweak) */
  aggregatedPubKey: PublicKey

  /** Taproot commitment (aggregated key + tweak) */
  commitment: PublicKey

  /** Taproot output script */
  script: Script

  /** Key aggregation context (needed for signing) */
  keyAggContext: MuSigKeyAggContext

  /** Merkle root (if using script tree) */
  merkleRoot: Buffer

  /** Taproot tweak value */
  tweak: Buffer
}

/**
 * Build a MuSig2 aggregated key for Taproot (key-path only)
 *
 * Creates a Taproot output using MuSig2 aggregated key as the internal key.
 * When spent via key path, the transaction looks like a single-sig spend,
 * providing maximum privacy for multi-sig.
 *
 * Algorithm:
 * 1. Aggregate signer public keys: Q = Σ(aᵢ·Pᵢ)
 * 2. Compute Taproot tweak: t = H("TapTweak", Q || merkle_root)
 * 3. Compute commitment: C = Q + t·G
 * 4. Build Taproot script: OP_SCRIPTTYPE OP_1 <33-byte C>
 *
 * @param signerPubKeys - Array of signer public keys to aggregate
 * @param state - Optional 32-byte Taproot state
 * @returns MuSig2 Taproot key result with all necessary data for signing
 *
 * @example
 * ```typescript
 * const result = buildMuSigTaprootKey([
 *   alice.publicKey,
 *   bob.publicKey,
 *   carol.publicKey
 * ])
 *
 * console.log('Taproot script:', result.script.toString())
 * console.log('Aggregated key:', result.aggregatedPubKey.toString())
 * console.log('Commitment:', result.commitment.toString())
 *
 * // Use result.script as output in transaction
 * // Use result.keyAggContext when signing
 * ```
 */
export function buildMuSigTaprootKey(
  signerPubKeys: PublicKey[],
  state?: Buffer,
): MuSigTaprootKeyResult {
  // Step 1: Aggregate signer public keys
  const keyAggContext = musigKeyAgg(signerPubKeys)
  const aggregatedPubKey = keyAggContext.aggregatedPubKey

  // Step 2: For key-path only, merkle root is all zeros
  const merkleRoot = Buffer.alloc(32)

  // Step 3: Compute Taproot tweak
  const tweak = calculateTapTweak(aggregatedPubKey, merkleRoot)

  // Step 4: Compute commitment (tweaked aggregated key)
  const commitment = tweakPublicKey(aggregatedPubKey, merkleRoot)

  // Step 5: Build Taproot script
  const script = buildKeyPathTaproot(aggregatedPubKey, state)

  return {
    aggregatedPubKey,
    commitment,
    script,
    keyAggContext,
    merkleRoot,
    tweak,
  }
}

/**
 * Build a MuSig2 aggregated key for Taproot with script tree
 *
 * Creates a Taproot output using MuSig2 aggregated key as the internal key,
 * with alternative spending conditions in a script tree.
 *
 * Algorithm:
 * 1. Aggregate signer public keys: Q = Σ(aᵢ·Pᵢ)
 * 2. Build script tree and compute merkle root
 * 3. Compute Taproot tweak: t = H("TapTweak", Q || merkle_root)
 * 4. Compute commitment: C = Q + t·G
 * 5. Build Taproot script with commitment
 *
 * @param signerPubKeys - Array of signer public keys
 * @param scriptTree - Taproot script tree structure
 * @param state - Optional 32-byte Taproot state
 * @returns MuSig2 Taproot key result with script tree info
 *
 * @example
 * ```typescript
 * // 3-of-3 with timelock fallback
 * const tree = {
 *   type: 'leaf',
 *   script: timelockScript
 * }
 *
 * const result = buildMuSigTaprootKeyWithScripts(
 *   [alice.publicKey, bob.publicKey, carol.publicKey],
 *   tree
 * )
 *
 * // Cooperative spend: Use MuSig2 key path
 * // Fallback: Use timelock script path
 * ```
 */
export function buildMuSigTaprootKeyWithScripts(
  signerPubKeys: PublicKey[],
  scriptTree: TapNode,
  state?: Buffer,
): MuSigTaprootKeyResult & { leaves: TapLeaf[] } {
  // Step 1: Aggregate signer public keys
  const keyAggContext = musigKeyAgg(signerPubKeys)
  const aggregatedPubKey = keyAggContext.aggregatedPubKey

  // Step 2: Build script tree
  const { script, commitment, merkleRoot, leaves } = buildScriptPathTaproot(
    aggregatedPubKey,
    scriptTree,
    state,
  )

  // Step 3: Compute Taproot tweak
  const tweak = calculateTapTweak(aggregatedPubKey, merkleRoot)

  return {
    aggregatedPubKey,
    commitment,
    script,
    keyAggContext,
    merkleRoot,
    tweak,
    leaves,
  }
}

/**
 * Create MuSig2 partial signature for Taproot key path spending
 *
 * BIP327 Approach: Only signer 0 adds the tweak term
 *
 * Algorithm:
 * 1. All signers compute normal partial signature: s_i = k + e·a_i·x_i
 *    (where e uses the COMMITMENT in challenge hash!)
 * 2. Signer 0 ONLY: Add tweak correction term
 *
 * The key insight: when verifying against commitment Q' = Q + t·G,
 * we need s·G = R + e·Q', but normal MuSig2 gives s·G = R + e·Q.
 * So signer 0 adds e·t to bridge the gap: (R + e·Q + e·t·G) = R + e·Q'
 *
 * @param secretNonce - Signer's secret nonce
 * @param privateKey - Signer's private key (UNTWEAKED)
 * @param keyAggContext - Key aggregation context (with INTERNAL key)
 * @param signerIndex - Index of this signer
 * @param aggregatedNonce - Aggregated nonces from all signers
 * @param message - Message to sign (transaction sighash)
 * @param tweak - Taproot tweak (from result.tweak)
 * @returns Partial signature for Taproot spending
 */
export function signTaprootKeyPathWithMuSig2(
  secretNonce: MuSigNonce,
  privateKey: PrivateKey,
  keyAggContext: MuSigKeyAggContext,
  signerIndex: number,
  aggregatedNonce: MuSigAggregatedNonce,
  message: Buffer,
  tweak: Buffer,
): BN {
  const n = Point.getN()

  // Compute commitment Q' = Q + t·G
  const commitment = keyAggContext.aggregatedPubKey.addScalar(tweak)

  // ALL signers use commitment in challenge hash
  const modifiedKeyAggContext: MuSigKeyAggContext = {
    ...keyAggContext,
    aggregatedPubKey: commitment,
  }

  // Compute normal partial signature using commitment
  const partialSig = musigPartialSign(
    secretNonce,
    privateKey,
    modifiedKeyAggContext,
    signerIndex,
    aggregatedNonce,
    message,
  )

  // BIP327: Only signer 0 adds the correction term
  if (signerIndex === 0) {
    // The partial signature gives: s_i·G = R_i + e·a_i·P_i
    // When summed: s·G = R + e·(Σ a_i·P_i) = R + e·Q
    // But we need: s·G = R + e·Q' = R + e·(Q + t·G) = R + e·Q + e·t·G
    // So signer 0 adds: e·t

    // Recompute challenge e with commitment
    const { R1, R2 } = aggregatedNonce

    const nonceCoefData = Buffer.concat([
      commitment.toBuffer(), // Use commitment!
      Point.pointToCompressed(R1),
      Point.pointToCompressed(R2),
      message,
    ])
    const b = new BN(
      musigTaggedHash(MUSIG_TAG_NONCE_COEFF, nonceCoefData),
      'be',
    )

    const R = R1.add(R2.mul(b))
    const R_x = R.getX().toArrayLike(Buffer, 'be', 32)
    const commitment_compressed = Point.pointToCompressed(commitment.point)
    const challengeData = Buffer.concat([R_x, commitment_compressed, message])
    const e = new BN(Hash.sha256(challengeData), 'be').umod(n)

    // Add e·t
    const tweakBN = new BN(tweak, 'be').umod(n)
    const tweakTerm = e.mul(tweakBN).umod(n)

    return partialSig.add(tweakTerm).umod(n)
  }

  return partialSig
}

/**
 * Verify MuSig2 partial signature for Taproot key path
 *
 * For signer 0: must subtract the tweak term before verification
 * For other signers: verify normally with commitment
 *
 * @param partialSig - Partial signature to verify
 * @param publicNonce - Signer's public nonce
 * @param publicKey - Signer's public key
 * @param keyAggContext - Key aggregation context
 * @param signerIndex - Index of the signer
 * @param aggregatedNonce - Aggregated nonces
 * @param message - Message being signed
 * @param tweak - Taproot tweak (from result.tweak)
 * @returns true if partial signature is valid
 */
export function verifyTaprootKeyPathMuSigPartial(
  partialSig: BN,
  publicNonce: [Point, Point],
  publicKey: PublicKey,
  keyAggContext: MuSigKeyAggContext,
  signerIndex: number,
  aggregatedNonce: MuSigAggregatedNonce,
  message: Buffer,
  tweak: Buffer,
): boolean {
  const n = Point.getN()

  // Compute commitment
  const commitment = keyAggContext.aggregatedPubKey.addScalar(tweak)

  // Modified context with commitment
  const modifiedKeyAggContext: MuSigKeyAggContext = {
    ...keyAggContext,
    aggregatedPubKey: commitment,
  }

  // For signer 0: subtract the tweak term before verifying
  let adjustedPartialSig = partialSig

  if (signerIndex === 0) {
    // Recompute challenge e with commitment
    const { R1, R2 } = aggregatedNonce

    const nonceCoefData = Buffer.concat([
      commitment.toBuffer(),
      Point.pointToCompressed(R1),
      Point.pointToCompressed(R2),
      message,
    ])
    const b = new BN(
      musigTaggedHash(MUSIG_TAG_NONCE_COEFF, nonceCoefData),
      'be',
    )

    const R = R1.add(R2.mul(b))
    const R_x = R.getX().toArrayLike(Buffer, 'be', 32)
    const commitment_compressed = Point.pointToCompressed(commitment.point)
    const challengeData = Buffer.concat([R_x, commitment_compressed, message])
    const e = new BN(Hash.sha256(challengeData), 'be').umod(n)

    // Subtract e·t from partial signature
    const tweakBN = new BN(tweak, 'be').umod(n)
    const tweakTerm = e.mul(tweakBN).umod(n)
    adjustedPartialSig = partialSig.sub(tweakTerm).umod(n)
  }

  return musigPartialSigVerify(
    adjustedPartialSig,
    publicNonce,
    publicKey,
    modifiedKeyAggContext,
    signerIndex,
    aggregatedNonce,
    message,
  )
}

/**
 * Helper to check if a script is a MuSig2 Taproot output
 *
 * Note: There's no way to detect if a Taproot script uses MuSig2
 * because the aggregated key looks like a regular public key.
 * This function just checks if it's a valid Taproot script.
 *
 * @param script - Script to check
 * @returns true if it's a Taproot script (may or may not use MuSig2)
 */
export function isMuSigTaprootOutput(script: Script): boolean {
  // MuSig2 Taproot outputs are indistinguishable from regular Taproot
  return script.isPayToTaproot()
}

/**
 * Utility to create Taproot address from MuSig2 aggregated key
 *
 * @param signerPubKeys - Array of signer public keys
 * @param network - Network for address ('livenet' or 'testnet')
 * @param state - Optional 32-byte state
 * @returns Taproot address and key info
 */
export function createMuSigTaprootAddress(
  signerPubKeys: PublicKey[],
  network: string = 'livenet',
  state?: Buffer,
): {
  address: Address
  script: Script
  commitment: PublicKey
  keyAggContext: MuSigKeyAggContext
} {
  const result = buildMuSigTaprootKey(signerPubKeys, state)

  // Create address from commitment
  const address = Address.fromTaprootCommitment(result.commitment, network)

  return {
    address,
    script: result.script,
    commitment: result.commitment,
    keyAggContext: result.keyAggContext,
  }
}

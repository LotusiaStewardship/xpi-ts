/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */

/**
 * MuSig2 Multi-Signature Scheme for Lotus
 *
 * Implements MuSig2 (BIP327) adapted for Lotus Schnorr signatures.
 *
 * Key Differences from BIP327:
 * - Uses 33-byte compressed public keys (not x-only 32-byte)
 * - Challenge hash: e = Hash(R.x || compressed(Q) || m) (33-byte key!)
 * - Nonce handling accounts for Lotus quadratic residue checks
 *
 * WARNING: This is a multi-party signature scheme. Improper use can lead to:
 * - Loss of funds (nonce reuse reveals private keys)
 * - Security vulnerabilities (rogue key attacks)
 * - Protocol failures (equivocation, invalid signatures)
 *
 * Always:
 * - Use fresh nonces for each message
 * - Verify partial signatures before aggregation
 * - Use secure random number generation
 * - Clear secret nonces from memory after use
 *
 * Reference: BIP327 - MuSig2 for BIP340-compatible Multi-Signatures
 *            (adapted for Lotus Schnorr)
 *
 * @module MuSig2
 */

import { PublicKey } from '../publickey.js'
import { PrivateKey } from '../privatekey.js'
import { Point } from './point.js'
import { BN } from './bn.js'
import { Hash } from './hash.js'
import { Signature } from './signature.js'

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Key Aggregation Context
 *
 * Contains the aggregated public key and per-key coefficients needed for
 * signing and verification.
 */
export interface MuSigKeyAggContext {
  /** Original public keys in order */
  pubkeys: PublicKey[]

  /** Key aggregation coefficient for each signer */
  keyAggCoeff: Map<number, BN>

  /** Aggregated public key Q = Σ(aᵢ · Pᵢ) */
  aggregatedPubKey: PublicKey
}

/**
 * Secret and Public Nonce Pair
 *
 * Each signer generates two nonce pairs for security against Wagner's attack.
 */
export interface MuSigNonce {
  /** Secret nonces (k₁, k₂) - MUST be kept secret and cleared after use */
  secretNonces: [BN, BN]

  /** Public nonces (R₁, R₂) = (k₁·G, k₂·G) - shared with other signers */
  publicNonces: [Point, Point]
}

/**
 * Aggregated Nonce
 *
 * Result of combining all signers' public nonces.
 */
export interface MuSigAggregatedNonce {
  /** Aggregated first nonce R₁ = Σ(R₁,ᵢ) */
  R1: Point

  /** Aggregated second nonce R₂ = Σ(R₂,ᵢ) */
  R2: Point
}

// ============================================================================
// Constants
// ============================================================================

/** Tag for key aggregation list hash (BIP327) */
export const MUSIG_TAG_KEYSORT = 'KeyAgg list'

/** Tag for key aggregation coefficient (BIP327) */
export const MUSIG_TAG_KEYAGG_COEFF = 'KeyAgg coefficient'

/** Tag for nonce aggregation coefficient (BIP327) */
export const MUSIG_TAG_NONCE_COEFF = 'MuSig/noncecoef'

/** Tag for auxiliary random data in nonce generation (BIP327) */
const MUSIG_TAG_AUX = 'MuSig/aux'

/** Tag for nonce generation (BIP327) */
export const MUSIG_TAG_NONCE = 'MuSig/nonce'

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Tagged hash for MuSig2
 *
 * Same as Taproot tagged hashing:
 * tag_hash = SHA256(tag)
 * tagged_hash = SHA256(tag_hash || tag_hash || data)
 *
 * @param tag - Tag string
 * @param data - Data to hash
 * @returns 32-byte hash
 */
export function musigTaggedHash(tag: string, data: Buffer): Buffer {
  const tagHash = Hash.sha256(Buffer.from(tag, 'utf8'))
  const combined = Buffer.concat([tagHash, tagHash, data])
  return Hash.sha256(combined)
}

/**
 * Hash public keys to create key aggregation list hash
 *
 * L = H("KeyAgg list", P₁ || P₂ || ... || Pₙ)
 *
 * @param pubkeys - Array of public keys (33-byte compressed)
 * @returns 32-byte hash
 */
function hashKeys(pubkeys: PublicKey[]): Buffer {
  const data = Buffer.concat(pubkeys.map(pk => pk.toBuffer()))
  return musigTaggedHash(MUSIG_TAG_KEYSORT, data)
}

/**
 * Compute key aggregation coefficient
 *
 * aᵢ = H("KeyAgg coefficient", L || Pᵢ)
 *
 * Special case: If there's only one unique key, coefficient is 1
 * Special case: If key is the second key and equals first key, coefficient is 1
 *
 * @param L - Key aggregation list hash
 * @param pubkey - Public key
 * @param isSecondKey - Whether this is the second key in the list
 * @param equalsFirstKey - Whether this key equals the first key
 * @returns Key aggregation coefficient
 */
function keyAggCoeff(
  L: Buffer,
  pubkey: PublicKey,
  isSecondKey: boolean,
  equalsFirstKey: boolean,
): BN {
  // Special case: second key equals first key → coefficient = 1
  if (isSecondKey && equalsFirstKey) {
    return new BN(1)
  }

  const data = Buffer.concat([L, pubkey.toBuffer()])
  const hash = musigTaggedHash(MUSIG_TAG_KEYAGG_COEFF, data)
  return new BN(hash, 'be')
}

// ============================================================================
// Key Aggregation
// ============================================================================

/**
 * Aggregate multiple public keys into a single key
 *
 * This is the first step in MuSig2. Each signer provides their public key,
 * and this function computes the aggregated public key that will be used
 * for signing.
 *
 * Algorithm:
 * 1. Sort public keys lexicographically (ensures deterministic ordering)
 * 2. Compute L = H("KeyAgg list", P₁ || P₂ || ... || Pₙ)
 * 3. For each key Pᵢ: compute aᵢ = H("KeyAgg coefficient", L || Pᵢ)
 * 4. Q = Σ(aᵢ · Pᵢ)
 *
 * Security: The key coefficients prevent rogue key attacks where an attacker
 * chooses their key maliciously to control the aggregated key.
 *
 * IMPORTANT: Public keys are sorted lexicographically BEFORE aggregation to ensure
 * all participants generate the same aggregated key and Taproot address regardless
 * of the order keys are provided. This is critical for multi-party coordination.
 *
 * @param pubkeys - Array of public keys to aggregate (will be sorted, must be unique)
 * @returns Key aggregation context with aggregated key and coefficients
 * @throws Error if pubkeys array is empty or contains invalid keys
 *
 * @example
 * ```typescript
 * const alice = new PrivateKey()
 * const bob = new PrivateKey()
 *
 * // Keys will be sorted automatically - order doesn't matter
 * const ctx = musigKeyAgg([alice.publicKey, bob.publicKey])
 * console.log('Aggregated key:', ctx.aggregatedPubKey.toString())
 * ```
 */
export function musigKeyAgg(pubkeys: PublicKey[]): MuSigKeyAggContext {
  if (pubkeys.length === 0) {
    throw new Error('Cannot aggregate zero public keys')
  }

  // Validate all public keys
  for (const pk of pubkeys) {
    if (!pk || !pk.point) {
      throw new Error('Invalid public key')
    }
  }

  // CRITICAL: Sort public keys lexicographically to ensure deterministic ordering
  // This ensures all participants generate the same aggregated key and Taproot address
  const sortedPubkeys = [...pubkeys].sort((a, b) => {
    const bufA = a.toBuffer()
    const bufB = b.toBuffer()
    return bufA.compare(bufB)
  })

  // Step 1: Compute key aggregation list hash (using sorted keys)
  const L = hashKeys(sortedPubkeys)

  // Step 2: Compute key aggregation coefficients (using sorted keys)
  const keyAggCoeffMap = new Map<number, BN>()
  const firstKey = sortedPubkeys[0]

  for (let i = 0; i < sortedPubkeys.length; i++) {
    const isSecond = i === 1
    const equalsFirst = sortedPubkeys[i].toString() === firstKey.toString()

    const coeff = keyAggCoeff(L, sortedPubkeys[i], isSecond, equalsFirst)
    keyAggCoeffMap.set(i, coeff)
  }

  // Step 3: Compute aggregated public key Q = Σ(aᵢ · Pᵢ) (using sorted keys)
  let Q: Point | null = null
  const n = Point.getN()

  for (let i = 0; i < sortedPubkeys.length; i++) {
    const coeff = keyAggCoeffMap.get(i)!
    const pk = sortedPubkeys[i]

    // aᵢ · Pᵢ
    const term = pk.point.mul(coeff.umod(n))

    if (Q === null) {
      Q = term
    } else {
      Q = Q.add(term)
    }
  }

  if (!Q) {
    throw new Error('Key aggregation failed: result is null')
  }

  // Validate the aggregated key
  Q.validate()

  const aggregatedPubKey = new PublicKey(Q, {
    compressed: true,
    network: sortedPubkeys[0].network,
  })

  return {
    pubkeys: sortedPubkeys, // Return sorted keys for consistency
    keyAggCoeff: keyAggCoeffMap,
    aggregatedPubKey,
  }
}

// ============================================================================
// Nonce Generation
// ============================================================================

/**
 * Generate secret and public nonces for MuSig2 signing
 *
 * Each signer must generate fresh nonces for each message. MuSig2 uses two
 * nonce pairs (k₁, k₂) for security against Wagner's attack.
 *
 * ⚠️ SECURITY CRITICAL ⚠️
 * - NEVER reuse nonces! Nonce reuse reveals your private key!
 * - This function uses RFC6979-style deterministic nonce generation
 * - Deterministic nonces prevent reuse even with hardware failures
 * - Protects against weak/backdoored random number generators
 * - Nonces are reproducible and can be unit tested
 *
 * Nonce Generation (RFC6979-style):
 * 1. Compute auxiliary hash: aux = H("MuSig/aux", privkey || Q || m || extra)
 * 2. Generate k₁ = H("MuSig/nonce", aux || 0x01) mod n
 * 3. Generate k₂ = H("MuSig/nonce", aux || 0x02) mod n
 * 4. Compute R₁ = k₁ · G, R₂ = k₂ · G
 *
 * For additional randomness (recommended), provide `extraInput` with 32 random bytes.
 * This makes nonces non-deterministic while maintaining security properties.
 *
 * Reference:
 * - BIP327 (MuSig2)
 * - RFC6979 (Deterministic ECDSA)
 * - Lotus Schnorr Specification (secure signature generation)
 *
 * @param privateKey - Signer's private key
 * @param aggregatedPubKey - Aggregated public key (from musigKeyAgg)
 * @param message - Optional message to be signed (for deterministic nonces)
 * @param extraInput - Optional extra randomness (32 bytes recommended). Use crypto.randomBytes(32) for non-deterministic nonces.
 * @returns Secret and public nonce pair
 *
 * @example Deterministic nonces (for testing)
 * ```typescript
 * const nonce = musigNonceGen(
 *   privateKey,
 *   ctx.aggregatedPubKey,
 *   message
 * )
 * ```
 *
 * @example Non-deterministic nonces with extra randomness (recommended for production)
 * ```typescript
 * import crypto from 'crypto'
 * const nonce = musigNonceGen(
 *   privateKey,
 *   ctx.aggregatedPubKey,
 *   message,
 *   crypto.randomBytes(32)  // Add 32 bytes of random entropy
 * )
 * ```
 */
export function musigNonceGen(
  privateKey: PrivateKey,
  aggregatedPubKey: PublicKey,
  message?: Buffer,
  extraInput?: Buffer,
): MuSigNonce {
  const G = Point.getG()
  const n = Point.getN()

  // Generate session ID by hashing inputs for deterministic nonces (RFC6979-style)
  // This follows the security recommendations from the Schnorr specification:
  // - Deterministic: No nonce reuse even with hardware failure
  // - Secure: No reliance on CSRNG quality
  // - Auditable: Can be unit tested
  //
  // Session ID = H("MuSig/aux", privkey || aggregatedPubKey || message || extraInput)
  const sessionData = Buffer.concat([
    privateKey.bn.toArrayLike(Buffer, 'be', 32),
    aggregatedPubKey.toBuffer(),
    message || Buffer.alloc(32),
    extraInput || Buffer.alloc(32),
  ])

  // Apply auxiliary hash for domain separation (BIP327 recommendation)
  const auxHash = musigTaggedHash(MUSIG_TAG_AUX, sessionData)

  // Generate two independent nonces using tagged hash with auxiliary data
  // This is deterministic but can be made non-deterministic by providing random extraInput
  const rand1 = musigTaggedHash(
    MUSIG_TAG_NONCE,
    Buffer.concat([auxHash, Buffer.from([0x01])]),
  )
  const rand2 = musigTaggedHash(
    MUSIG_TAG_NONCE,
    Buffer.concat([auxHash, Buffer.from([0x02])]),
  )

  // Convert to scalars (mod n)
  let k1 = new BN(rand1, 'be').umod(n)
  let k2 = new BN(rand2, 'be').umod(n)

  // Ensure nonces are not zero
  if (k1.isZero()) {
    k1 = new BN(1)
  }
  if (k2.isZero()) {
    k2 = new BN(1)
  }

  // Compute public nonces R1 = k1*G, R2 = k2*G
  const R1 = G.mul(k1)
  const R2 = G.mul(k2)

  // Validate points
  R1.validate()
  R2.validate()

  return {
    secretNonces: [k1, k2],
    publicNonces: [R1, R2],
  }
}

// ============================================================================
// Nonce Aggregation
// ============================================================================

/**
 * Aggregate public nonces from all signers
 *
 * After each signer generates their nonces, they share their public nonces.
 * This function aggregates them into a single nonce pair.
 *
 * Algorithm:
 * 1. R₁ = Σ(R₁,ᵢ) - Sum of first public nonces
 * 2. R₂ = Σ(R₂,ᵢ) - Sum of second public nonces
 *
 * @param publicNonces - Array of public nonce pairs from all signers
 * @returns Aggregated nonce pair
 * @throws Error if array is empty or contains invalid nonces
 *
 * @example
 * ```typescript
 * const aggNonce = musigNonceAgg([
 *   aliceNonce.publicNonces,
 *   bobNonce.publicNonces
 * ])
 * ```
 */
export function musigNonceAgg(
  publicNonces: Array<[Point, Point]>,
): MuSigAggregatedNonce {
  if (publicNonces.length === 0) {
    throw new Error('Cannot aggregate zero nonces')
  }

  // Validate all nonces
  for (const [R1, R2] of publicNonces) {
    if (!R1 || !R2) {
      throw new Error('Invalid public nonce')
    }
    R1.validate()
    R2.validate()
  }

  // Sum all R1 nonces
  let R1_agg = publicNonces[0][0]
  for (let i = 1; i < publicNonces.length; i++) {
    R1_agg = R1_agg.add(publicNonces[i][0])
  }

  // Sum all R2 nonces
  let R2_agg = publicNonces[0][1]
  for (let i = 1; i < publicNonces.length; i++) {
    R2_agg = R2_agg.add(publicNonces[i][1])
  }

  // Validate aggregated nonces
  R1_agg.validate()
  R2_agg.validate()

  return {
    R1: R1_agg,
    R2: R2_agg,
  }
}

// ============================================================================
// Partial Signature
// ============================================================================

/**
 * Create a partial signature
 *
 * Each signer creates a partial signature using their secret nonce and
 * private key. These partial signatures are later aggregated into a full
 * Schnorr signature.
 *
 * Algorithm (Lotus Schnorr adaptation):
 * 1. Compute b = H("MuSig/noncecoef", Q || R₁ || R₂ || m)
 * 2. Compute effective nonce: k = k₁ + b·k₂ (mod n)
 * 3. Compute effective public nonce: R = R₁ + b·R₂
 * 4. Check if R.y is quadratic residue, negate k if not (Lotus specific!)
 * 5. Compute challenge: e = H(R.x || compressed(Q) || m) (Lotus format!)
 * 6. Compute partial signature: sᵢ = k + e·aᵢ·xᵢ (mod n)
 *
 * @param secretNonce - Signer's secret nonce (from musigNonceGen)
 * @param privateKey - Signer's private key
 * @param keyAggContext - Key aggregation context (from musigKeyAgg)
 * @param signerIndex - Index of this signer in the pubkeys array
 * @param aggregatedNonce - Aggregated nonces (from musigNonceAgg)
 * @param message - Message to sign (typically transaction sighash)
 * @returns Partial signature sᵢ
 *
 * @example
 * ```typescript
 * const partialSig = musigPartialSign(
 *   nonce,
 *   privateKey,
 *   ctx,
 *   0,  // Alice is signer 0
 *   aggNonce,
 *   message
 * )
 * ```
 */
export function musigPartialSign(
  secretNonce: MuSigNonce,
  privateKey: PrivateKey,
  keyAggContext: MuSigKeyAggContext,
  signerIndex: number,
  aggregatedNonce: MuSigAggregatedNonce,
  message: Buffer,
): BN {
  const n = Point.getN()
  const [k1, k2] = secretNonce.secretNonces
  const { R1, R2 } = aggregatedNonce

  // Step 1: Compute nonce coefficient b = H("MuSig/noncecoef", Q || R1 || R2 || m)
  const Q = keyAggContext.aggregatedPubKey
  const nonceCoefData = Buffer.concat([
    Q.toBuffer(), // 33 bytes compressed
    Point.pointToCompressed(R1), // 33 bytes compressed
    Point.pointToCompressed(R2), // 33 bytes compressed
    message, // 32 bytes
  ])
  const b = new BN(musigTaggedHash(MUSIG_TAG_NONCE_COEFF, nonceCoefData), 'be')

  // Step 2: Compute effective nonce k = k1 + b*k2 (mod n)
  let k = k1.add(b.mul(k2)).umod(n)

  // Step 3: Compute effective public nonce R = R1 + b*R2
  const R = R1.add(R2.mul(b))

  // Step 4: LOTUS SPECIFIC - Check if R.y is quadratic residue, negate k if not
  // This ensures the final signature's R point has an even Y coordinate
  if (!R.hasSquare()) {
    k = n.sub(k).umod(n)
  }

  // Step 5: Compute challenge e = H(R.x || compressed(Q) || m) - LOTUS FORMAT!
  const R_x = R.getX().toArrayLike(Buffer, 'be', 32)
  const Q_compressed = Point.pointToCompressed(Q.point) // 33 bytes!
  const challengeData = Buffer.concat([R_x, Q_compressed, message])
  const e = new BN(Hash.sha256(challengeData), 'be').umod(n)

  // Step 6: Get key aggregation coefficient for this signer
  const a = keyAggContext.keyAggCoeff.get(signerIndex)
  if (!a) {
    throw new Error(`Invalid signer index: ${signerIndex}`)
  }

  // Step 7: Compute partial signature: s_i = k + e*a*x (mod n)
  const x = privateKey.bn
  const s = k.add(e.mul(a).mul(x)).umod(n)

  return s
}

// ============================================================================
// Partial Signature Verification
// ============================================================================

/**
 * Verify a partial signature
 *
 * Before aggregating partial signatures, each should be verified to ensure
 * correctness and detect malicious signers.
 *
 * Verification equation:
 * sᵢ·G = Rᵢ + e·aᵢ·Pᵢ
 *
 * @param partialSig - Partial signature to verify
 * @param publicNonce - Signer's public nonce pair
 * @param publicKey - Signer's public key
 * @param keyAggContext - Key aggregation context
 * @param signerIndex - Index of the signer
 * @param aggregatedNonce - Aggregated nonces
 * @param message - Message being signed
 * @returns true if partial signature is valid
 *
 * @example
 * ```typescript
 * const valid = musigPartialSigVerify(
 *   bobPartialSig,
 *   bobNonce.publicNonces,
 *   bob.publicKey,
 *   ctx,
 *   1,  // Bob is signer 1
 *   aggNonce,
 *   message
 * )
 * ```
 */
export function musigPartialSigVerify(
  partialSig: BN,
  publicNonce: [Point, Point],
  publicKey: PublicKey,
  keyAggContext: MuSigKeyAggContext,
  signerIndex: number,
  aggregatedNonce: MuSigAggregatedNonce,
  message: Buffer,
): boolean {
  try {
    const G = Point.getG()
    const n = Point.getN()
    const [R1_i, R2_i] = publicNonce
    const { R1, R2 } = aggregatedNonce
    const Q = keyAggContext.aggregatedPubKey

    // Step 1: Compute nonce coefficient b = H("MuSig/noncecoef", Q || R1 || R2 || m)
    const nonceCoefData = Buffer.concat([
      Q.toBuffer(),
      Point.pointToCompressed(R1),
      Point.pointToCompressed(R2),
      message,
    ])
    const b = new BN(
      musigTaggedHash(MUSIG_TAG_NONCE_COEFF, nonceCoefData),
      'be',
    )

    // Step 2: Compute effective public nonce for this signer: Ri = R1,i + b*R2,i
    const R_i = R1_i.add(R2_i.mul(b))

    // Step 3: Compute effective aggregated nonce: R = R1 + b*R2
    const R = R1.add(R2.mul(b))

    // Handle Lotus nonce negation (if R.y not quadratic residue, negate)
    const negated = !R.hasSquare()

    // Step 4: Compute challenge e = H(R.x || compressed(Q) || m) - LOTUS FORMAT!
    const R_x = R.getX().toArrayLike(Buffer, 'be', 32)
    const Q_compressed = Point.pointToCompressed(Q.point)
    const challengeData = Buffer.concat([R_x, Q_compressed, message])
    const e = new BN(Hash.sha256(challengeData), 'be').umod(n)

    // Step 5: Get key aggregation coefficient for this signer
    const a = keyAggContext.keyAggCoeff.get(signerIndex)
    if (!a) {
      throw new Error(`Invalid signer index: ${signerIndex}`)
    }

    // Step 6: Verify equation: s_i * G = R_i + e * a * P_i
    // (or s_i * G = -R_i + e * a * P_i if R was negated)
    //
    // Left side: s_i * G
    const lhs = G.mul(partialSig.umod(n))

    // Right side: R_i + e * a * P_i (or -R_i + e * a * P_i)
    const eaP = publicKey.point.mul(e.mul(a).umod(n))
    // If R was negated, we need to use -R_i in verification
    // Point negation: multiply by -1 = (n-1)
    const R_i_adjusted = negated ? R_i.mul(n.sub(new BN(1))) : R_i
    const rhs = R_i_adjusted.add(eaP)

    // Check if points are equal
    return lhs.eq(rhs)
  } catch (error) {
    // Any error in verification means invalid signature
    return false
  }
}

// ============================================================================
// Signature Aggregation
// ============================================================================

/**
 * Aggregate partial signatures into final Schnorr signature
 *
 * After collecting all partial signatures, the aggregator combines them
 * into a standard 64-byte Schnorr signature that can be verified with
 * the aggregated public key.
 *
 * Algorithm:
 * 1. Compute b = H("MuSig/noncecoef", Q || R₁ || R₂ || m)
 * 2. Compute R = R₁ + b·R₂
 * 3. Compute s = Σ(sᵢ) mod n
 * 4. Return signature (R.x, s)
 *
 * @param partialSigs - Array of partial signatures from all signers
 * @param aggregatedNonce - Aggregated nonces
 * @param message - Message that was signed
 * @param aggregatedPubKey - Aggregated public key (for verification)
 * @param sighashType - Optional sighash type to embed in signature (e.g., SIGHASH_ALL | SIGHASH_LOTUS)
 * @returns Final 64-byte Schnorr signature with nhashtype set
 *
 * @example
 * ```typescript
 * const signature = musigSigAgg(
 *   [alicePartialSig, bobPartialSig],
 *   aggNonce,
 *   message,
 *   ctx.aggregatedPubKey
 * )
 *
 * // Verify with standard Schnorr verification
 * const valid = Schnorr.verify(
 *   message,
 *   signature,
 *   ctx.aggregatedPubKey,
 *   'big'
 * )
 * ```
 */
export function musigSigAgg(
  partialSigs: BN[],
  aggregatedNonce: MuSigAggregatedNonce,
  message: Buffer,
  aggregatedPubKey: PublicKey,
  sighashType?: number,
): Signature {
  if (partialSigs.length === 0) {
    throw new Error('Cannot aggregate zero partial signatures')
  }

  const n = Point.getN()
  const { R1, R2 } = aggregatedNonce

  // Step 1: Compute nonce coefficient b = H("MuSig/noncecoef", Q || R1 || R2 || m)
  const nonceCoefData = Buffer.concat([
    aggregatedPubKey.toBuffer(),
    Point.pointToCompressed(R1),
    Point.pointToCompressed(R2),
    message,
  ])
  const b = new BN(musigTaggedHash(MUSIG_TAG_NONCE_COEFF, nonceCoefData), 'be')

  // Step 2: Compute effective nonce R = R1 + b*R2
  const R = R1.add(R2.mul(b))

  // Step 3: Handle Lotus quadratic residue check
  // If R.y is not a quadratic residue, the signing process negated all k values
  // So we don't need to do anything here - the partial sigs already account for it

  // Step 4: Sum all partial signatures: s = Σ(s_i) mod n
  let s = new BN(0)
  for (const partialSig of partialSigs) {
    s = s.add(partialSig).umod(n)
  }

  // Validate s is not zero
  if (s.isZero()) {
    throw new Error('Aggregated signature s is zero (invalid)')
  }

  // Step 5: Create Signature object with (R.x, s)
  // CRITICAL: Use Signature data object format with compressed and isSchnorr flags
  // This matches how Schnorr.sign() creates signatures
  const r = R.getX()

  const signature = new Signature({
    r: r,
    s: s,
    compressed: true,
    isSchnorr: true,
    nhashtype: sighashType, // BUG FIX: Set sighash type for proper transaction serialization
  })

  // Note: The caller should verify this signature with:
  // Schnorr.verify(message, signature, aggregatedPubKey, 'big')
  // When serializing to transaction format, toTxFormat() will append the sighash byte

  return signature
}

// ============================================================================
// Exports
// ============================================================================

/**
 * MuSig2 Module Exports
 *
 * Core functions:
 * - musigKeyAgg: Aggregate public keys
 * - musigNonceGen: Generate signing nonces
 * - musigNonceAgg: Aggregate nonces from all signers
 * - musigPartialSign: Create partial signature
 * - musigPartialSigVerify: Verify a partial signature
 * - musigSigAgg: Aggregate partial signatures into final signature
 *
 * Types:
 * - MuSigKeyAggContext: Key aggregation result
 * - MuSigNonce: Secret and public nonce pair
 * - MuSigAggregatedNonce: Aggregated nonces
 */

export default {
  musigKeyAgg,
  musigNonceGen,
  musigNonceAgg,
  musigPartialSign,
  musigPartialSigVerify,
  musigSigAgg,
  musigTaggedHash,
}

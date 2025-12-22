/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */

/**
 * MuSig2 Signer - High-Level Wrapper for Common MuSig2 Operations
 *
 * This class provides a simplified, developer-friendly API for common MuSig2 workflows,
 * hiding the complexity of the underlying cryptographic operations while maintaining
 * full control when needed.
 *
 * Features:
 * - Simplified signing workflow (2 methods: prepare + sign)
 * - Automatic message hashing (ensures 32-byte messages for Lotus Schnorr)
 * - Both direct and session-based signing modes
 * - Taproot integration helpers
 * - Built-in validation and error handling
 * - Transaction signing utilities
 *
 * Common Use Cases:
 * 1. Simple message signing (2-of-2, 3-of-3, etc.)
 * 2. Taproot transaction signing with MuSig2
 * 3. Coordinated multi-party signing sessions
 * 4. Batch signing operations
 *
 * @module MuSig2Signer
 */

import { PrivateKey } from '../privatekey.js'
import { PublicKey } from '../publickey.js'
import { Signature } from '../crypto/signature.js'
import { Hash } from '../crypto/hash.js'
import { Point } from '../crypto/point.js'
import { Random } from '../crypto/random.js'
import { Script } from '../script.js'
import { Address } from '../address.js'
import {
  musigKeyAgg,
  musigNonceGen,
  musigNonceAgg,
  musigPartialSign,
  musigPartialSigVerify,
  musigSigAgg,
  type MuSigKeyAggContext,
  type MuSigNonce,
  type MuSigAggregatedNonce,
} from '../crypto/musig2.js'
import {
  MuSigSessionManager,
  MuSigSessionPhase,
  type MuSigSession,
} from './session.js'
import {
  buildMuSigTaprootKey,
  buildMuSigTaprootKeyWithScripts,
  signTaprootKeyPathWithMuSig2,
  type MuSigTaprootKeyResult,
} from '../taproot/musig2.js'
import { Transaction } from '../transaction/transaction.js'
import { sighash } from '../transaction/sighash.js'
import { BN } from '../crypto/bn.js'

/**
 * Configuration for creating a MuSig2 signer
 */
export interface MuSig2SignerConfig {
  /** All signers' public keys (in order - must be consistent!) */
  signers: PublicKey[]

  /** This signer's private key */
  myPrivateKey: PrivateKey

  /** Optional: Extra randomness for nonce generation */
  extraInput?: Buffer
}

/**
 * Result of preparing a MuSig2 signing session
 */
export interface MuSig2PrepareResult {
  /** Key aggregation context */
  keyAggContext: MuSigKeyAggContext

  /** This signer's public nonces (share with other signers) */
  myPublicNonces: [Point, Point]

  /** Secret nonces (KEEP PRIVATE! Only store temporarily) */
  mySecretNonces: [BN, BN]

  /** This signer's index in the signers array */
  myIndex: number

  /** Session identifier (for tracking) */
  sessionId?: string
}

/**
 * Result of completing MuSig2 signing
 */
export interface MuSig2SignResult {
  /** Final aggregated signature */
  signature: Signature

  /** Aggregated public key */
  aggregatedPubKey: PublicKey

  /** Whether this signer created the final signature (or received it) */
  isAggregator: boolean
}

/**
 * Taproot-specific signing result
 */
export interface MuSig2TaprootSignResult extends MuSig2SignResult {
  /** Taproot commitment (tweaked aggregated key) */
  commitment: PublicKey

  /** Taproot script */
  script: Script

  /** Taproot address */
  address: Address
}

/**
 * High-level MuSig2 Signer
 *
 * Simplifies common MuSig2 operations for developers.
 *
 * @example
 * ```typescript
 * // Simple 2-of-2 signing
 * const signer = new MuSig2Signer({
 *   signers: [alice.publicKey, bob.publicKey],
 *   myPrivateKey: alice,
 * })
 *
 * // Prepare (round 1)
 * const prepare = await signer.prepare(message)
 * // Share prepare.myPublicNonces with Bob
 *
 * // After receiving Bob's nonces
 * const signature = await signer.sign(
 *   prepare,
 *   [prepare.myPublicNonces, bobNonces], // All nonces
 *   message,
 *   [bobPartialSig], // Collected partial signatures (excluding mine)
 * )
 * ```
 */
export class MuSig2Signer {
  private config: MuSig2SignerConfig
  private sessionManager?: MuSigSessionManager

  /**
   * Create a new MuSig2 signer
   *
   * @param config - Signer configuration
   */
  constructor(config: MuSig2SignerConfig) {
    // Validate configuration
    if (!config.signers || config.signers.length === 0) {
      throw new Error('MuSig2Signer: At least one signer required')
    }

    if (!config.myPrivateKey) {
      throw new Error('MuSig2Signer: myPrivateKey is required')
    }

    // Find this signer's index
    const myPubKey = config.myPrivateKey.publicKey
    const myIndex = config.signers.findIndex(
      signer => signer.toString() === myPubKey.toString(),
    )

    if (myIndex === -1) {
      throw new Error(
        'MuSig2Signer: myPrivateKey does not correspond to any signer',
      )
    }

    this.config = config
  }

  /**
   * Prepare for signing (Round 1: Generate nonces)
   *
   * This is the first step in MuSig2 signing. Each signer calls this method
   * and shares their public nonces with all other signers.
   *
   * 🔒 PRODUCTION SECURITY: This method automatically adds 32 bytes of random
   * entropy to nonce generation (unless extraInput is explicitly provided in config).
   * This provides defense-in-depth on top of RFC6979 deterministic generation.
   *
   * @param message - Message to sign (will be hashed to 32 bytes if needed)
   * @param useSession - If true, use session manager for state tracking
   * @returns Preparation result with public nonces to share
   */
  prepare(
    message: Buffer | string,
    useSession: boolean = false,
  ): MuSig2PrepareResult {
    // Normalize message to 32 bytes
    const normalizedMessage = this._normalizeMessage(message)

    // Perform key aggregation (sorts keys internally for deterministic ordering)
    const keyAggContext = musigKeyAgg(this.config.signers)

    // SECURITY: Add random entropy by default if not explicitly provided
    // This provides defense-in-depth on top of RFC6979 deterministic generation
    const entropy =
      this.config.extraInput !== undefined
        ? this.config.extraInput
        : Random.getRandomBuffer(32)

    // Generate nonces with RFC6979 + randomness
    const nonce = musigNonceGen(
      this.config.myPrivateKey,
      keyAggContext.aggregatedPubKey,
      normalizedMessage,
      entropy,
    )

    // Find myIndex in the SORTED key list (from keyAggContext.pubkeys)
    const myIndex = keyAggContext.pubkeys.findIndex(
      s => s.toString() === this.config.myPrivateKey.publicKey.toString(),
    )!

    const result: MuSig2PrepareResult = {
      keyAggContext,
      myPublicNonces: nonce.publicNonces,
      mySecretNonces: nonce.secretNonces,
      myIndex,
    }

    // If using session manager, initialize session
    if (useSession) {
      if (!this.sessionManager) {
        this.sessionManager = new MuSigSessionManager()
      }

      const session = this.sessionManager.createSession(
        this.config.signers,
        this.config.myPrivateKey,
        normalizedMessage,
      )

      // Generate nonces in session
      this.sessionManager.generateNonces(
        session,
        this.config.myPrivateKey,
        this.config.extraInput,
      )

      result.sessionId = session.sessionId
    }

    return result
  }

  /**
   * Sign a message (Round 2: Create partial signature)
   *
   * After all signers have shared their public nonces, each signer calls
   * this method to create their partial signature.
   *
   * @param prepare - Result from prepare() method
   * @param allPublicNonces - All signers' public nonces (in signer order!)
   * @param message - Same message used in prepare()
   * @returns Partial signature to share with other signers
   */
  createPartialSignature(
    prepare: MuSig2PrepareResult,
    allPublicNonces: Array<[Point, Point]>,
    message: Buffer | string,
  ): BN {
    // Normalize message
    const normalizedMessage = this._normalizeMessage(message)

    // Aggregate nonces
    const aggregatedNonce = musigNonceAgg(allPublicNonces)

    // Create secret nonce from prepare result
    const secretNonce: MuSigNonce = {
      secretNonces: prepare.mySecretNonces,
      publicNonces: prepare.myPublicNonces,
    }

    // Create partial signature
    return musigPartialSign(
      secretNonce,
      this.config.myPrivateKey,
      prepare.keyAggContext,
      prepare.myIndex,
      aggregatedNonce,
      normalizedMessage,
    )
  }

  /**
   * Verify a partial signature from another signer
   *
   * Before aggregating, verify all received partial signatures to detect
   * malicious or invalid signatures.
   *
   * @param partialSig - Partial signature to verify
   * @param publicNonce - Signer's public nonce
   * @param publicKey - Signer's public key
   * @param signerIndex - Index of the signer
   * @param prepare - Result from prepare() method
   * @param allPublicNonces - All public nonces (for aggregation)
   * @param message - Message being signed
   * @returns true if partial signature is valid
   */
  verifyPartialSignature(
    partialSig: BN,
    publicNonce: [Point, Point],
    publicKey: PublicKey,
    signerIndex: number,
    prepare: MuSig2PrepareResult,
    allPublicNonces: Array<[Point, Point]>,
    message: Buffer | string,
  ): boolean {
    const normalizedMessage = this._normalizeMessage(message)
    const aggregatedNonce = musigNonceAgg(allPublicNonces)

    return musigPartialSigVerify(
      partialSig,
      publicNonce,
      publicKey,
      prepare.keyAggContext,
      signerIndex,
      aggregatedNonce,
      normalizedMessage,
    )
  }

  /**
   * Complete signing by aggregating all partial signatures
   *
   * After collecting all partial signatures (including your own), call this
   * method to produce the final signature.
   *
   * @param prepare - Result from prepare() method
   * @param allPublicNonces - All signers' public nonces (in order)
   * @param message - Message being signed
   * @param allPartialSigs - All partial signatures (in signer order!)
   * @returns Final aggregated signature
   */
  sign(
    prepare: MuSig2PrepareResult,
    allPublicNonces: Array<[Point, Point]>,
    message: Buffer | string,
    allPartialSigs: BN[],
  ): MuSig2SignResult {
    // Validate inputs
    if (allPublicNonces.length !== this.config.signers.length) {
      throw new Error(
        `Invalid number of public nonces: expected ${this.config.signers.length}, got ${allPublicNonces.length}`,
      )
    }

    if (allPartialSigs.length !== this.config.signers.length) {
      throw new Error(
        `Invalid number of partial signatures: expected ${this.config.signers.length}, got ${allPartialSigs.length}`,
      )
    }

    // Normalize message
    const normalizedMessage = this._normalizeMessage(message)

    // Aggregate nonces
    const aggregatedNonce = musigNonceAgg(allPublicNonces)

    // Aggregate partial signatures
    const signature = musigSigAgg(
      allPartialSigs,
      aggregatedNonce,
      normalizedMessage,
      prepare.keyAggContext.aggregatedPubKey,
    )

    return {
      signature,
      aggregatedPubKey: prepare.keyAggContext.aggregatedPubKey,
      isAggregator: true, // This signer aggregated the signatures
    }
  }

  /**
   * Prepare for Taproot MuSig2 signing
   *
   * Creates a MuSig2 aggregated key and applies Taproot tweaking.
   * Use this when creating Taproot outputs that will be spent via MuSig2.
   *
   * @param state - Optional 32-byte state data (e.g., NFT metadata hash)
   * @returns Taproot-specific preparation result
   */
  prepareTaproot(
    state?: Buffer,
  ): MuSigTaprootKeyResult & { keyAggContext: MuSigKeyAggContext } {
    const result = buildMuSigTaprootKey(this.config.signers, state)

    // Get key aggregation context
    const keyAggContext = musigKeyAgg(this.config.signers)

    return {
      ...result,
      keyAggContext,
    }
  }

  /**
   * Sign a Taproot transaction input using MuSig2
   *
   * Creates a partial signature for spending a Taproot output via MuSig2 key path.
   *
   * @param prepare - Result from prepareTaproot()
   * @param allPublicNonces - All signers' public nonces
   * @param transaction - Transaction being signed
   * @param inputIndex - Index of the input to sign
   * @param amount - Amount of the output being spent
   * @param sighashType - Signature hash type (default: SIGHASH_ALL | SIGHASH_LOTUS)
   * @returns Partial signature for Taproot spending
   */
  signTaprootInput(
    prepare: MuSigTaprootKeyResult & { keyAggContext: MuSigKeyAggContext },
    allPublicNonces: Array<[Point, Point]>,
    transaction: Transaction,
    inputIndex: number,
    amount: number,
    sighashType?: number,
  ): BN {
    // Get transaction sighash
    const sigType =
      sighashType || Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS
    const satoshisBN = new BN(amount)
    const sighashBuffer = sighash(
      transaction,
      sigType,
      inputIndex,
      prepare.script,
      satoshisBN,
    )

    // Normalize to 32 bytes
    const normalizedSighash = this._normalizeMessage(sighashBuffer)

    // Aggregate nonces
    const aggregatedNonce = musigNonceAgg(allPublicNonces)

    // SECURITY: Add random entropy by default if not explicitly provided
    const entropy =
      this.config.extraInput !== undefined
        ? this.config.extraInput
        : Random.getRandomBuffer(32)

    // Get my nonces (we'll generate them fresh or use session state)
    const nonce = musigNonceGen(
      this.config.myPrivateKey,
      prepare.keyAggContext.aggregatedPubKey,
      normalizedSighash,
      entropy,
    )

    // Find myIndex in the SORTED key list (from keyAggContext.pubkeys)
    const myIndex = prepare.keyAggContext.pubkeys.findIndex(
      s => s.toString() === this.config.myPrivateKey.publicKey.toString(),
    )!

    // Create Taproot-specific partial signature
    return signTaprootKeyPathWithMuSig2(
      nonce,
      this.config.myPrivateKey,
      prepare.keyAggContext,
      myIndex,
      aggregatedNonce,
      normalizedSighash,
      prepare.tweak,
    )
  }

  /**
   * Complete Taproot transaction signing
   *
   * Aggregates all partial signatures for a Taproot MuSig2 spend.
   *
   * @param prepare - Result from prepareTaproot()
   * @param allPublicNonces - All signers' public nonces
   * @param allPartialSigs - All partial signatures (in signer order)
   * @param transaction - Transaction being signed
   * @param inputIndex - Index of input being signed
   * @param amount - Amount being spent
   * @param sighashType - Signature hash type
   * @returns Final signature for Taproot input
   */
  completeTaprootSigning(
    prepare: MuSigTaprootKeyResult & { keyAggContext: MuSigKeyAggContext },
    allPublicNonces: Array<[Point, Point]>,
    allPartialSigs: BN[],
    transaction: Transaction,
    inputIndex: number,
    amount: number,
    sighashType?: number,
  ): Signature {
    // Get sighash
    const sigType =
      sighashType || Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS
    const satoshisBN = new BN(amount)
    const sighashBuffer = sighash(
      transaction,
      sigType,
      inputIndex,
      prepare.script,
      satoshisBN,
    )
    const normalizedSighash = this._normalizeMessage(sighashBuffer)

    // Aggregate nonces
    const aggregatedNonce = musigNonceAgg(allPublicNonces)

    // Aggregate signatures (use commitment for Taproot!)
    return musigSigAgg(
      allPartialSigs,
      aggregatedNonce,
      normalizedSighash,
      prepare.commitment, // Use commitment (tweaked key) for Taproot!
    )
  }

  /**
   * Create a session-based signer (for coordinated signing)
   *
   * Returns a session manager and session for advanced use cases where you
   * need fine-grained control over the signing process.
   *
   * @param message - Message to sign
   * @param metadata - Optional session metadata
   * @returns Session manager and initialized session
   */
  createSession(
    message: Buffer | string,
    metadata?: Record<string, unknown>,
  ): {
    manager: MuSigSessionManager
    session: MuSigSession
  } {
    if (!this.sessionManager) {
      this.sessionManager = new MuSigSessionManager()
    }

    const normalizedMessage = this._normalizeMessage(message)
    const session = this.sessionManager.createSession(
      this.config.signers,
      this.config.myPrivateKey,
      normalizedMessage,
      metadata,
    )

    return {
      manager: this.sessionManager,
      session,
    }
  }

  /**
   * Get this signer's public key
   */
  get myPublicKey(): PublicKey {
    return this.config.myPrivateKey.publicKey
  }

  /**
   * Get all signers' public keys
   */
  get allSigners(): PublicKey[] {
    return [...this.config.signers]
  }

  /**
   * Get this signer's index (based on lexicographically sorted keys)
   */
  get myIndex(): number {
    // Sort keys lexicographically (same as musigKeyAgg does)
    const sortedSigners = [...this.config.signers].sort((a, b) => {
      const bufA = a.toBuffer()
      const bufB = b.toBuffer()
      return bufA.compare(bufB)
    })

    return sortedSigners.findIndex(
      s => s.toString() === this.config.myPrivateKey.publicKey.toString(),
    )!
  }

  // Private helper methods

  /**
   * Normalize message to 32 bytes (required for Lotus Schnorr)
   *
   * If message is a string or not exactly 32 bytes, hash it to 32 bytes.
   */
  private _normalizeMessage(message: Buffer | string): Buffer {
    if (typeof message === 'string') {
      // Hash string to 32 bytes
      return Hash.sha256(Buffer.from(message, 'utf8'))
    }

    if (message.length === 32) {
      // Already 32 bytes
      return message
    }

    // Hash to 32 bytes
    return Hash.sha256(message)
  }
}

/**
 * Helper function to create a MuSig2 signer quickly
 *
 * @param signers - All signers' public keys
 * @param myPrivateKey - This signer's private key
 * @returns New MuSig2Signer instance
 *
 * @example
 * ```typescript
 * const signer = createMuSig2Signer(
 *   [alice.publicKey, bob.publicKey],
 *   alice
 * )
 * ```
 */
export function createMuSig2Signer(
  signers: PublicKey[],
  myPrivateKey: PrivateKey,
): MuSig2Signer {
  return new MuSig2Signer({ signers, myPrivateKey })
}

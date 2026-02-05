/**
 * Copyright 2025-2026 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * Taproot Implementation for Lotus
 *
 * Implements Pay-To-Taproot (P2TR) script support based on lotusd implementation.
 *
 * Key Differences from BIP341:
 * - Uses 33-byte compressed public keys (not x-only 32-byte)
 * - Internal key parity encoded in control block first bit
 * - Requires SIGHASH_LOTUS for key path spending
 * - Requires Schnorr signatures for key path spending
 *
 * Script Format:
 * - Without state: OP_SCRIPTTYPE OP_1 <33-byte commitment>
 * - With state: OP_SCRIPTTYPE OP_1 <33-byte commitment> <32-byte state>
 *
 * Reference: lotusd/src/script/taproot.cpp
 *
 * @module Taproot
 */
import { Hash } from '../crypto/hash'
import { PUBKEY_PREFIX_EVEN, PUBKEY_PREFIX_ODD, PublicKey } from '../publickey'
import { PrivateKey } from '../privatekey'
import { Script } from '../script'
import { Opcode } from '../opcode'
import { BN } from '../crypto/bn'
import { BufferWriter } from '../encoding/bufferwriter'
import { BufferUtil } from '../util/buffer'
import { Signature } from '../crypto/signature'
import type { Buffer } from 'buffer/'

/**
 * Taproot Leaf Node
 *
 * Represents a leaf node in the Taproot script tree, holding a script and an optional leaf version.
 *
 * @property script - The script for this leaf node. Can be a Script object or a BufferUtil.
 * @property [leafVersion] - Optional leaf version byte (defaults to 0xc0 for tapscript if not provided).
 */
export interface TapLeafNode {
  /** Script for this leaf (Script object or Buffer) */
  script: Script | Buffer
  /** Optional leaf version (defaults to 0xc0 for tapscript) */
  leafVersion?: number
}

/**
 * Taproot Script Tree Branch Node
 *
 * Represents a branch node in the Taproot Merkle tree, consisting of two children.
 * Each child can itself be either a leaf node ({@link TapLeafNode}) or another branch node.
 *
 * @example
 * // Branch node combining two leaves
 * const branch: TapBranchNode = {
 *   left: { script: script1 },
 *   right: { script: script2 }
 * }
 *
 * // Branch node combining a branch and a leaf
 * const nestedBranch: TapBranchNode = {
 *   left: {
 *     left: { script: script1 },
 *     right: { script: script2 }
 *   },
 *   right: { script: script3 }
 * }
 */
export interface TapBranchNode {
  /** Left child node (can be leaf or branch) */
  left: TapNode
  /** Right child node (can be leaf or branch) */
  right: TapNode
}

/**
 * Union type for Taproot script tree nodes
 *
 * Can be either a leaf node ({@link TapLeafNode}) or a branch node ({@link TapBranchNode})
 */
export type TapNode = TapLeafNode | TapBranchNode

/**
 * Individual leaf in the Taproot tree with its Merkle path
 */
/**
 * Individual leaf in the Taproot tree with its Merkle path
 *
 * Represents a fully processed leaf node including its computed hash
 * and the Merkle path needed to prove inclusion in the tree.
 */
export interface TapLeaf {
  /** The script for this leaf */
  script: Script
  /** Leaf version byte (e.g., 0xc0 for tapscript) */
  leafVersion: number
  /** Computed tapleaf hash (32 bytes) */
  leafHash: Buffer
  /** Array of sibling hashes for Merkle proof */
  merklePath: Buffer[]
}

/**
 * Result of building a Taproot tree
 */
export interface TapTreeBuildResult {
  /** Merkle root of the tree */
  merkleRoot: Buffer
  /** Array of leaf scripts with their merkle paths */
  leaves: TapLeaf[]
}

// Taproot Constants
/** Mask for extracting leaf version from control block first byte (clears parity bit) */
export const TAPROOT_LEAF_MASK = 0xfe
/** Default leaf version for tapscript (0xc0) */
export const TAPROOT_LEAF_TAPSCRIPT = 0xc0
/** Base size of control block: 1 byte control + 32 bytes internal pubkey */
export const TAPROOT_CONTROL_BASE_SIZE = 33
/** Size of each Merkle path node in control block */
export const TAPROOT_CONTROL_NODE_SIZE = 32
/** Maximum number of Merkle path nodes allowed in control block */
export const TAPROOT_CONTROL_MAX_NODE_COUNT = 128
/** Maximum control block size: base + max nodes (33 + 32 * 128 = 4129 bytes) */
export const TAPROOT_CONTROL_MAX_SIZE =
  TAPROOT_CONTROL_BASE_SIZE +
  TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT

export const TAPROOT_SCRIPTTYPE = Opcode.OP_1
export const TAPROOT_INTRO_SIZE = 3 // OP_SCRIPTTYPE + OP_1 + push length

// Public key size constants (must be declared before use)
export const PUBKEY_COMPRESSED_SIZE = 33 // Compressed public key size
export const PUBKEY_UNCOMPRESSED_SIZE = 65 // Uncompressed public key size
export const PUBKEY_XCOORD_SIZE = 32 // X-coordinate size
/** SHA256 hash size in bytes (used for merkle nodes, tweaks, and state commitments) */
export const SHA256_HASH_SIZE = 32

/** State push opcode size: 0x20 (32) for pushing 32-byte state */
export const TAPROOT_STATE_PUSH_SIZE = 32

/** Size of P2TR output without state: intro (3) + pubkey (33) = 36 bytes */
export const TAPROOT_SIZE_WITHOUT_STATE =
  TAPROOT_INTRO_SIZE + PUBKEY_COMPRESSED_SIZE // 36 bytes

/** Size of P2TR output with state: intro (3) + pubkey (33) + state_push (1) + state (32) = 69 bytes
 * Matches lotusd: TAPROOT_INTRO_SIZE + CPubKey::COMPRESSED_SIZE + 33
 * The final 33 = 1 byte push opcode (0x20) + 32 bytes state hash
 */
export const TAPROOT_SIZE_WITH_STATE =
  TAPROOT_INTRO_SIZE + PUBKEY_COMPRESSED_SIZE + 1 + SHA256_HASH_SIZE // 69 bytes

/** SIGHASH_ALL | SIGHASH_LOTUS */
export const TAPROOT_SIGHASH_TYPE =
  Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS

/** Annex tag byte for Taproot witness stack (0x50). Reference: lotusd/src/script/interpreter.cpp */
export const TAPROOT_ANNEX_TAG = 0x50

/**
 * Tag for TapLeaf hash calculation
 * Used in: tapleaf_hash = SHA256_Tag("TapLeaf", leaf_version || compact_size(script) || script)
 * @see {@link calculateTapLeaf}
 */
export const TAPROOT_TAG_TAPLEAF = 'TapLeaf'

/**
 * Tag for TapBranch hash calculation
 * Used in: tapbranch_hash = SHA256_Tag("TapBranch", left || right) where left < right lexicographically
 * @see {@link calculateTapBranch}
 */
export const TAPROOT_TAG_TAPBRANCH = 'TapBranch'

/**
 * Tag for TapTweak hash calculation
 * Used in: tweak = SHA256_Tag("TapTweak", internal_pubkey || merkle_root)
 * @see {@link calculateTapTweak}
 */
export const TAPROOT_TAG_TAPTWEAK = 'TapTweak'

/**
 * Tagged hash for Taproot
 *
 * Implements BIP340-style tagged hashing:
 * tag_hash = SHA256(tag)
 * tagged_hash = SHA256(tag_hash || tag_hash || data)
 *
 * @param tag - Tag string (e.g., "TapTweak", "TapLeaf", "TapBranch")
 * @param data - Data to hash
 * @returns SHA256_HASH_SIZE-byte hash
 */
export function taggedHash(tag: string, data: Buffer): Buffer {
  const tagHash = Hash.sha256(BufferUtil.from(tag, 'utf8'))
  const combined = BufferUtil.concat([tagHash, tagHash, data])
  return Hash.sha256(combined)
}

/**
 * Calculate TapTweak hash
 *
 * tweak = SHA256_Tag("TapTweak", internal_pubkey || merkle_root)
 *
 * @param internalPubKey - PUBKEY_COMPRESSED_SIZE-byte internal public key
 * @param merkleRoot - SHA256_HASH_SIZE-byte merkle root (or empty buffer for key-only)
 * @returns SHA256_HASH_SIZE-byte tweak hash
 */
export function calculateTapTweak(
  internalPubKey: PublicKey,
  merkleRoot: Buffer = BufferUtil.alloc(SHA256_HASH_SIZE),
): Buffer {
  return taggedHash(
    TAPROOT_TAG_TAPTWEAK,
    BufferUtil.concat([internalPubKey.toBuffer(), merkleRoot]),
  )
}

/**
 * Calculate TapLeaf hash
 *
 * tapleaf_hash = SHA256_Tag("TapLeaf", leaf_version || compact_size(script) || script)
 *
 * @param script - Tapscript
 * @param leafVersion - Leaf version (default: 0xc0 for tapscript)
 * @returns SHA256_HASH_SIZE-byte tapleaf hash
 */
export function calculateTapLeaf(
  script: Script | Buffer,
  leafVersion: number = TAPROOT_LEAF_TAPSCRIPT,
): Buffer {
  const scriptBuf = BufferUtil.isBuffer(script) ? script : script.toBuffer()
  const writer = new BufferWriter()

  writer.writeUInt8(leafVersion)
  writer.writeVarintNum(scriptBuf.length)
  writer.write(scriptBuf)

  return taggedHash(TAPROOT_TAG_TAPLEAF, writer.toBuffer())
}

/**
 * Calculate TapBranch hash
 *
 * tapbranch_hash = SHA256_Tag("TapBranch", left || right)
 * where left and right are ordered lexicographically
 *
 * @param left - Left branch hash
 * @param right - Right branch hash
 * @returns SHA256_HASH_SIZE-byte tapbranch hash
 */
export function calculateTapBranch(left: Buffer, right: Buffer): Buffer {
  // Order lexicographically
  const ordered =
    BufferUtil.compare(left, right) < 0
      ? BufferUtil.concat([left, right])
      : BufferUtil.concat([right, left])

  return taggedHash(TAPROOT_TAG_TAPBRANCH, ordered)
}

/**
 * Tweak a public key for Taproot
 *
 * tweaked_pubkey = internal_pubkey + tweak * G
 *
 * @param internalPubKey - Internal public key
 * @param merkleRoot - Merkle root of script tree (or empty for key-only)
 * @returns Tweaked public key
 */
export function tweakPublicKey(
  internalPubKey: PublicKey,
  merkleRoot: Buffer = BufferUtil.alloc(SHA256_HASH_SIZE),
): PublicKey {
  const tweak = calculateTapTweak(internalPubKey, merkleRoot)
  return internalPubKey.addScalar(tweak)
}

/**
 * Tweak a private key for Taproot
 *
 * tweaked_privkey = (internal_privkey + tweak) mod n
 *
 * @param internalPrivKey - Internal private key
 * @param merkleRoot - Merkle root of script tree (or empty for key-only)
 * @returns Tweaked private key
 */
export function tweakPrivateKey(
  internalPrivKey: PrivateKey,
  merkleRoot: Buffer = BufferUtil.alloc(SHA256_HASH_SIZE),
): PrivateKey {
  const internalPubKey = internalPrivKey.publicKey
  const tweak = calculateTapTweak(internalPubKey, merkleRoot)

  // Add tweak to private key (mod n)
  const tweakBN = new BN(tweak)
  const privKeyBN = internalPrivKey.bn
  const tweakedBN = privKeyBN.add(tweakBN).umod(PublicKey.getN())

  return new PrivateKey(tweakedBN)
}

/**
 * Type guard to check if a node is a leaf
 */
export function isTapLeafNode(node: TapNode): node is TapLeafNode {
  return 'script' in node
}

/**
 * Type guard to check if a node is a branch
 */
export function isTapBranchNode(node: TapNode): node is TapBranchNode {
  return 'left' in node && 'right' in node
}

/**
 * Build a Taproot script tree
 *
 * @param tree - Tree structure (leaf or branch)
 * @returns Tree build result with merkle root and paths
 */
export function buildTapTree(tree: TapNode): TapTreeBuildResult {
  // Check if this is a leaf node (has script property)
  if (isTapLeafNode(tree)) {
    // Type narrowed to TapLeafNode
    const leafNode = tree
    const leafVersion = leafNode.leafVersion || TAPROOT_LEAF_TAPSCRIPT
    const scriptBuf = BufferUtil.isBuffer(leafNode.script)
      ? leafNode.script
      : leafNode.script.toBuffer()
    const leafHash = calculateTapLeaf(scriptBuf, leafVersion)

    return {
      merkleRoot: leafHash,
      leaves: [
        {
          script: Script.fromBuffer(scriptBuf),
          leafVersion,
          leafHash,
          merklePath: [],
        },
      ],
    }
  }

  // Branch node (has left and right properties)
  // Type is automatically narrowed to TapBranchNode
  const leftResult = buildTapTree(tree.left)
  const rightResult = buildTapTree(tree.right)

  const branchHash = calculateTapBranch(
    leftResult.merkleRoot,
    rightResult.merkleRoot,
  )

  // Add the right merkle root to left leaves' paths
  const leftLeaves = leftResult.leaves.map(leaf => ({
    ...leaf,
    merklePath: [...leaf.merklePath, rightResult.merkleRoot],
  }))

  // Add the left merkle root to right leaves' paths
  const rightLeaves = rightResult.leaves.map(leaf => ({
    ...leaf,
    merklePath: [...leaf.merklePath, leftResult.merkleRoot],
  }))

  return {
    merkleRoot: branchHash,
    leaves: [...leftLeaves, ...rightLeaves],
  }
}

/**
 * Create a Taproot control block
 *
 * Control block format:
 * - 1 byte: leaf_version | parity_bit
 * - SHA256_HASH_SIZE bytes: internal public key X-coordinate (without PUBKEY_PREFIX_EVEN/PUBKEY_PREFIX_ODD prefix)
 * - SHA256_HASH_SIZE*n bytes: merkle path
 *
 * Total size: PUBKEY_COMPRESSED_SIZE + SHA256_HASH_SIZE*n bytes
 *
 * The parity bit (bit 0 of first byte) indicates if the internal pubkey's
 * Y-coordinate is even (0) or odd (1), allowing reconstruction of the full
 * 33-byte compressed public key during verification.
 *
 * Reference: lotusd/src/script/taproot.cpp lines 43-54
 *
 * @param internalPubKey - Internal public key (PUBKEY_COMPRESSED_SIZE-byte compressed)
 * @param leafIndex - Index of the leaf being spent
 * @param tree - Taproot tree structure
 * @returns Control block buffer
 */
export function createControlBlock(
  internalPubKey: PublicKey,
  leafIndex: number,
  tree: TapNode,
): Buffer {
  const treeResult = buildTapTree(tree)

  if (leafIndex < 0 || leafIndex >= treeResult.leaves.length) {
    throw new Error(`Invalid leaf index: ${leafIndex}`)
  }

  const leaf = treeResult.leaves[leafIndex]
  const pubKeyBytes = internalPubKey.toBuffer()

  // First byte: leaf version with parity bit
  // Parity is 1 if y-coordinate is odd (pubkey byte is PUBKEY_PREFIX_ODD), 0 if even (PUBKEY_PREFIX_EVEN)
  const parity = pubKeyBytes[0] === PUBKEY_PREFIX_ODD ? 1 : 0
  const controlByte = (leaf.leafVersion & TAPROOT_LEAF_MASK) | parity

  const writer = new BufferWriter()
  writer.writeUInt8(controlByte)

  // Next SHA256_HASH_SIZE bytes: x-coordinate only (not the full PUBKEY_COMPRESSED_SIZE-byte compressed key)
  // Parity is already encoded in the control byte above
  // Control block format: [control_byte][SHA256_HASH_SIZE-byte x-coord][merkle_path...]
  writer.write(pubKeyBytes.slice(1, PUBKEY_COMPRESSED_SIZE)) // Skip the PUBKEY_PREFIX_EVEN/PUBKEY_PREFIX_ODD prefix, write only x-coordinate

  // Merkle path
  for (const node of leaf.merklePath) {
    writer.write(node)
  }

  return writer.toBuffer()
}

/**
 * Apply a tweak scalar directly to a public key
 *
 * This is used internally by verifyTaprootCommitment where we already have the tweak hash
 * and need to add it as a scalar to the public key without re-hashing.
 *
 * @param internalPubKey - Internal public key
 * @param tweak - The tweak scalar (already computed hash)
 * @returns Tweaked public key
 */
export function applyTweakToPublicKey(
  internalPubKey: PublicKey,
  tweak: Buffer,
): PublicKey {
  return internalPubKey.addScalar(tweak)
}

/**
 * Verify a Taproot commitment
 *
 * Verifies that the control block proves that script is part of the commitment.
 * Matches lotusd/src/script/taproot.cpp VerifyTaprootCommitment().
 *
 * @param controlBlock - Control block (TAPROOT_CONTROL_BASE_SIZE + SHA256_HASH_SIZE*n bytes)
 * @param commitment - Public key that has been committed to (PUBKEY_COMPRESSED_SIZE bytes)
 * @param script - Script we are proving inclusion in commitment for
 * @returns Object containing tapleafHash and success boolean
 */
export function verifyTaprootCommitment(
  controlBlock: Buffer,
  commitment: Buffer,
  script: Script,
): { tapleafHash: Buffer; success: boolean } {
  try {
    // Validate control block size
    if (controlBlock.length < TAPROOT_CONTROL_BASE_SIZE) {
      return { tapleafHash: BufferUtil.alloc(SHA256_HASH_SIZE), success: false }
    }

    const pathLen = Math.floor(
      (controlBlock.length - TAPROOT_CONTROL_BASE_SIZE) /
        TAPROOT_CONTROL_NODE_SIZE,
    )

    // Calculate merkle root from control block
    const leafVersion = controlBlock[0] & TAPROOT_LEAF_MASK
    let leafHash = calculateTapLeaf(script, leafVersion)
    let merkleHash = leafHash

    // Process merkle path nodes
    for (let i = 0; i < pathLen; i++) {
      const nodeOffset =
        TAPROOT_CONTROL_BASE_SIZE + i * TAPROOT_CONTROL_NODE_SIZE
      const node = controlBlock.slice(
        nodeOffset,
        nodeOffset + TAPROOT_CONTROL_NODE_SIZE,
      )

      // Lexicographic ordering like lotusd
      if (BufferUtil.compare(merkleHash, node) < 0) {
        merkleHash = calculateTapBranch(merkleHash, node)
      } else {
        merkleHash = calculateTapBranch(node, merkleHash)
      }
    }

    // Extract internal pubkey from control block
    // We encode the parity of the internal pubkey in the first bit of the control block.
    const pubkeyBytes = controlBlock.slice(0, TAPROOT_CONTROL_BASE_SIZE)
    const pubkeyBuffer = BufferUtil.from(pubkeyBytes)

    // Parity of internal pubkey is encoded in the first bit
    pubkeyBuffer[0] =
      pubkeyBuffer[0] & 1 ? PUBKEY_PREFIX_ODD : PUBKEY_PREFIX_EVEN
    const internalPubKey = new PublicKey(pubkeyBuffer)

    // Calculate tweak hash and apply directly to public key (like lotusd AddScalar)
    const tweakHash = calculateTapTweak(internalPubKey, merkleHash)

    // Verify commitment matches
    const commitmentKey = new PublicKey(commitment)
    const expectedCommitment = applyTweakToPublicKey(internalPubKey, tweakHash)

    return {
      tapleafHash: leafHash,
      success: commitmentKey.toString() === expectedCommitment.toString(),
    }
  } catch (e) {
    return { tapleafHash: BufferUtil.alloc(SHA256_HASH_SIZE), success: false }
  }
}

/**
 * Extract the commitment public key from a Taproot script
 *
 * @param script - P2TR script
 * @returns Commitment public key
 * @throws Error if not a valid P2TR script
 */
export function extractTaprootCommitment(script: Script): PublicKey {
  if (!script.isTaprootOut()) {
    throw new Error('Not a valid Pay-To-Taproot script')
  }

  return PublicKey.fromBuffer(script.chunks[2].buf!)
}

/**
 * Extract the state from a Taproot script (if present)

 * @param script - P2TR script to extract state from
 * @returns State buffer (32 bytes) or null if script has no state
 */
export function extractTaprootState(script: Script): Buffer | null {
  if (!script.isTaprootOut()) {
    return null
  }

  // P2TR with state has exactly 4 chunks
  if (script.chunks.length !== 4) {
    return null
  }

  return script.chunks[3].buf!
}

/**
 * Build a Pay-To-Taproot script
 *
 * @deprecated Use Script.buildPayToTaproot instead
 * @param commitment - Commitment public key (tweaked)
 * @param state - Optional 32-byte state (only for script-path spending)
 * @returns P2TR script
 */
export function buildPayToTaproot(
  _commitment: PublicKey,
  _state?: Buffer,
): Script {
  throw new Error(
    'This function has been deprecated. Used Script.buildTaprootOut instead',
  )
}

/**
 * Build a simple key-path-only Taproot output
 *
 * @param internalPubKey - Internal public key
 * @returns P2TR script (key-path has no state)
 */
export function buildKeyPathTaproot(internalPubKey: PublicKey): Script {
  // For key-path only, merkle root is all zeros
  const merkleRoot = BufferUtil.alloc(SHA256_HASH_SIZE)
  const commitment = tweakPublicKey(internalPubKey, merkleRoot)
  return Script.buildTaprootOut(commitment)
}

/**
 * Build a script-path Taproot output
 *
 * @param internalPubKey - Internal public key
 * @param tree - Taproot script tree
 * @param state - Optional 32-byte state
 * @returns P2TR script and tree info
 */
export function buildScriptPathTaproot(
  internalPubKey: PublicKey,
  tree: TapNode,
  state?: Buffer,
): {
  script: Script
  commitment: PublicKey
  merkleRoot: Buffer
  leaves: TapLeaf[]
} {
  const treeInfo = buildTapTree(tree)
  const commitment = tweakPublicKey(internalPubKey, treeInfo.merkleRoot)
  const script = Script.buildTaprootOut(commitment, state)

  return {
    script,
    commitment,
    merkleRoot: treeInfo.merkleRoot,
    leaves: treeInfo.leaves,
  }
}

/**
 * Verify Taproot script path spending
 *
 * Verifies that a script is correctly committed to in a Taproot output
 * by validating the merkle proof in the control block.
 *
 * @param internalPubKey - Internal public key X-coordinate (SHA256_HASH_SIZE bytes, without prefix)
 * @param script - Script being revealed
 * @param commitmentPubKey - Commitment public key from scriptPubKey (PUBKEY_COMPRESSED_SIZE bytes)
 * @param leafVersion - Leaf version from control block
 * @param merklePath - Merkle path nodes from control block
 * @param parity - Parity bit from control block (0=even Y, 1=odd Y)
 * @returns true if verification succeeds
 */
export function verifyTaprootScriptPath(
  internalPubKey: Buffer,
  script: Script,
  commitmentPubKey: Buffer,
  leafVersion: number,
  merklePath: Buffer[],
  parity: number,
): boolean {
  try {
    // Reconstruct full 33-byte compressed pubkey from 32-byte x-coordinate and parity
    // internalPubKey is 32 bytes (x-coordinate only)
    // parity bit tells us the prefix: 0 = PUBKEY_PREFIX_EVEN (even), 1 = PUBKEY_PREFIX_ODD (odd)
    const pubkeyPrefix = parity === 0 ? PUBKEY_PREFIX_EVEN : PUBKEY_PREFIX_ODD
    const fullPubkey = BufferUtil.concat([
      BufferUtil.from([pubkeyPrefix]),
      internalPubKey,
    ])

    // Calculate leaf hash
    let leafHash = calculateTapLeaf(script, leafVersion)

    // Walk up the merkle tree
    for (const pathNode of merklePath) {
      // Sort hashes lexicographically before combining
      if (BufferUtil.compare(leafHash, pathNode) < 0) {
        leafHash = calculateTapBranch(leafHash, pathNode)
      } else {
        leafHash = calculateTapBranch(pathNode, leafHash)
      }
    }

    // Calculate expected commitment from internal key and merkle root
    const internalKey = new PublicKey(fullPubkey)
    const expectedCommitment = tweakPublicKey(internalKey, leafHash)

    // Verify commitment matches scriptPubkey commitment
    // Note: We don't check parity against commitment like BIP341 does.
    // The parity was already used to reconstruct the internal pubkey above.
    // Reference: lotusd/src/script/taproot.cpp lines 59-65
    const actualCommitment = new PublicKey(commitmentPubKey)
    if (expectedCommitment.toString() !== actualCommitment.toString()) {
      return false
    }

    return true
  } catch (e) {
    return false
  }
}

/**
 * Verify Taproot script path spending using control block
 *
 * Convenience wrapper that uses the new verifyTaprootCommitment function.
 *
 * @param controlBlock - Control block (33 + 32*n bytes)
 * @param commitment - Commitment public key from scriptPubKey (33 bytes)
 * @param script - Script being revealed
 * @returns true if verification succeeds
 */
export function verifyTaprootScriptPathFromControlBlock(
  controlBlock: Buffer,
  commitment: Buffer,
  script: Script,
): boolean {
  const result = verifyTaprootCommitment(controlBlock, commitment, script)
  return result.success
}

/**
 * Result of Taproot spend verification
 */
export interface TaprootVerifyResult {
  /** Whether verification succeeded */
  success: boolean
  /** Error message if verification failed */
  error?: string
  /** Script to execute (for script path spending) */
  scriptToExecute?: Script
  /** Stack after verification (for script path spending) */
  stack?: Buffer[]
}

/**
 * Verify Taproot spending (key path or script path)
 *
 * This is the main entry point for Taproot verification, handling both:
 * - Key path spending: Single Schnorr signature
 * - Script path spending: Script + control block + merkle proof
 *
 * Reference: lotusd/src/script/interpreter.cpp VerifyTaprootSpend() lines 2074-2165
 *
 * @param scriptPubkey - The Taproot scriptPubKey being spent
 * @param stack - Stack from scriptSig execution
 * @param tx - Transaction being verified
 * @param nin - Input index
 * @param flags - Script verification flags
 * @param satoshisBN - Amount being spent (for sighash)
 * @returns Verification result with error or script to execute
 */
export function verifyTaprootSpend(
  scriptPubkey: Script,
  stack: Buffer[],
  flags: number,
): TaprootVerifyResult {
  // Import locally to avoid circular dependency
  const SCRIPT_DISABLE_TAPROOT_SIGHASH_LOTUS = 1 << 22
  const SCRIPT_TAPROOT_KEY_SPEND_PATH = 1 << 23
  const TAPROOT_ANNEX_TAG = 0x50

  // Check if Taproot is disabled
  if (flags & SCRIPT_DISABLE_TAPROOT_SIGHASH_LOTUS) {
    return { success: false, error: 'SCRIPT_ERR_TAPROOT_PHASEOUT' }
  }

  // Verify scriptPubkey is valid P2TR
  if (!scriptPubkey.isTaprootOut()) {
    return { success: false, error: 'SCRIPT_ERR_SCRIPTTYPE_MALFORMED_SCRIPT' }
  }

  // Extract commitment pubkey from scriptPubkey
  const scriptBuf = scriptPubkey.toBuffer()
  const vchPubkey = scriptBuf.slice(
    TAPROOT_INTRO_SIZE,
    TAPROOT_SIZE_WITHOUT_STATE,
  )

  // Stack must not be empty
  if (stack.length === 0) {
    return { success: false, error: 'SCRIPT_ERR_INVALID_STACK_OPERATION' }
  }

  // Check for annex (not supported)
  if (
    stack.length >= 2 &&
    stack[stack.length - 1].length > 0 &&
    stack[stack.length - 1][0] === TAPROOT_ANNEX_TAG
  ) {
    return { success: false, error: 'SCRIPT_ERR_TAPROOT_ANNEX_NOT_SUPPORTED' }
  }

  // Key path spending: single signature on stack
  if (stack.length === 1) {
    // Key path spending is verified by the transaction's signature verification
    // The interpreter will handle this after we return
    return {
      success: true,
      stack,
      // No script to execute for key path
    }
  }

  // Script path spending: script and control block on stack
  const controlBlock = stack[stack.length - 1]
  const scriptBytes = stack[stack.length - 2]
  const execScript = new Script(scriptBytes)

  // Create new stack without script and control block
  const newStack = stack.slice(0, stack.length - 2)

  // Validate control block size
  const sizeRemainder =
    (controlBlock.length - TAPROOT_CONTROL_BASE_SIZE) %
    TAPROOT_CONTROL_NODE_SIZE

  if (
    controlBlock.length < TAPROOT_CONTROL_BASE_SIZE ||
    controlBlock.length > TAPROOT_CONTROL_MAX_SIZE ||
    sizeRemainder !== 0
  ) {
    return { success: false, error: 'SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE' }
  }

  // Check leaf version
  if ((controlBlock[0] & TAPROOT_LEAF_MASK) !== TAPROOT_LEAF_TAPSCRIPT) {
    return {
      success: false,
      error: 'SCRIPT_ERR_TAPROOT_LEAF_VERSION_NOT_SUPPORTED',
    }
  }

  // Extract internal pubkey and merkle path from control block
  // Control block format: [control_byte][32-byte x-coord][merkle_path...]
  // BASE_SIZE = 33 means bytes 0-32 are base (1 control + 32 pubkey)
  const internalPubkey = controlBlock.slice(1, TAPROOT_CONTROL_BASE_SIZE)
  const merklePath: Buffer[] = []
  for (
    let i = TAPROOT_CONTROL_BASE_SIZE;
    i < controlBlock.length;
    i += TAPROOT_CONTROL_NODE_SIZE
  ) {
    merklePath.push(controlBlock.slice(i, i + TAPROOT_CONTROL_NODE_SIZE))
  }

  // Verify script is in merkle tree
  const leafVersion = controlBlock[0] & TAPROOT_LEAF_MASK
  const parity = controlBlock[0] & 0x01

  const isValid = verifyTaprootScriptPath(
    internalPubkey,
    execScript,
    vchPubkey,
    leafVersion,
    merklePath,
    parity,
  )

  if (!isValid) {
    return {
      success: false,
      error: 'SCRIPT_ERR_TAPROOT_CONTROL_BLOCK_VERIFICATION_FAILED',
    }
  }

  // Push state onto stack if present (matches lotusd behavior)
  // Reference: lotusd/src/script/interpreter.cpp lines 2136-2140
  const scriptPubkeyBuf = scriptPubkey.toBuffer()
  if (scriptPubkeyBuf.length === TAPROOT_SIZE_WITH_STATE) {
    const state = extractTaprootState(scriptPubkey)
    if (state) {
      newStack.push(state)
    }
  }

  // Return script to execute and updated stack
  return {
    success: true,
    stack: newStack,
    scriptToExecute: execScript,
  }
}

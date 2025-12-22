/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */
/**
 * Taproot Implementation for Lotus
 *
 * Implements Pay-To-Taproot (P2TR) support based on lotusd implementation.
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

import { Hash } from './crypto/hash.js'
import { PublicKey } from './publickey.js'
import { PrivateKey } from './privatekey.js'
import { Script } from './script.js'
import { Opcode } from './opcode.js'
import { BN } from './crypto/bn.js'
import { BufferWriter } from './encoding/bufferwriter.js'
import { Signature } from './crypto/signature.js'

/**
 * Taproot Leaf Node
 *
 * Represents a leaf node in the Taproot script tree, holding a script and an optional leaf version.
 *
 * @property script - The script for this leaf node. Can be a Script object or a Buffer.
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
export interface TapLeaf {
  script: Script
  leafVersion: number
  leafHash: Buffer
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
export const TAPROOT_LEAF_MASK = 0xfe
export const TAPROOT_LEAF_TAPSCRIPT = 0xc0
export const TAPROOT_CONTROL_BASE_SIZE = 33
export const TAPROOT_CONTROL_NODE_SIZE = 32
export const TAPROOT_CONTROL_MAX_NODE_COUNT = 128
export const TAPROOT_CONTROL_MAX_SIZE =
  TAPROOT_CONTROL_BASE_SIZE +
  TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT

export const TAPROOT_SCRIPTTYPE = Opcode.OP_1
export const TAPROOT_INTRO_SIZE = 3 // OP_SCRIPTTYPE + OP_1 + push length
export const TAPROOT_SIZE_WITHOUT_STATE = TAPROOT_INTRO_SIZE + 33 // 36 bytes
export const TAPROOT_SIZE_WITH_STATE = TAPROOT_INTRO_SIZE + 33 + 33 // 69 bytes

/** SIGHASH_ALL | SIGHASH_LOTUS */
export const TAPROOT_SIGHASH_TYPE =
  Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS

export const TAPROOT_ANNEX_TAG = 0x50

/**
 * Tagged hash for Taproot
 *
 * Implements BIP340-style tagged hashing:
 * tag_hash = SHA256(tag)
 * tagged_hash = SHA256(tag_hash || tag_hash || data)
 *
 * @param tag - Tag string (e.g., "TapTweak", "TapLeaf", "TapBranch")
 * @param data - Data to hash
 * @returns 32-byte hash
 */
export function taggedHash(tag: string, data: Buffer): Buffer {
  const tagHash = Hash.sha256(Buffer.from(tag, 'utf8'))
  const combined = Buffer.concat([tagHash, tagHash, data])
  return Hash.sha256(combined)
}

/**
 * Calculate TapTweak hash
 *
 * tweak = SHA256_Tag("TapTweak", internal_pubkey || merkle_root)
 *
 * @param internalPubKey - 33-byte internal public key
 * @param merkleRoot - 32-byte merkle root (or empty buffer for key-only)
 * @returns 32-byte tweak hash
 */
export function calculateTapTweak(
  internalPubKey: PublicKey,
  merkleRoot: Buffer = Buffer.alloc(32),
): Buffer {
  const pubKeyBytes = internalPubKey.toBuffer()
  const data = Buffer.concat([pubKeyBytes, merkleRoot])
  return taggedHash('TapTweak', data)
}

/**
 * Calculate TapLeaf hash
 *
 * tapleaf_hash = SHA256_Tag("TapLeaf", leaf_version || compact_size(script) || script)
 *
 * @param script - Tapscript
 * @param leafVersion - Leaf version (default: 0xc0 for tapscript)
 * @returns 32-byte tapleaf hash
 */
export function calculateTapLeaf(
  script: Script | Buffer,
  leafVersion: number = TAPROOT_LEAF_TAPSCRIPT,
): Buffer {
  const scriptBuf = Buffer.isBuffer(script) ? script : script.toBuffer()
  const writer = new BufferWriter()

  writer.writeUInt8(leafVersion)
  writer.writeVarintNum(scriptBuf.length)
  writer.write(scriptBuf)

  return taggedHash('TapLeaf', writer.toBuffer())
}

/**
 * Calculate TapBranch hash
 *
 * tapbranch_hash = SHA256_Tag("TapBranch", left || right)
 * where left and right are ordered lexicographically
 *
 * @param left - Left branch hash
 * @param right - Right branch hash
 * @returns 32-byte tapbranch hash
 */
export function calculateTapBranch(left: Buffer, right: Buffer): Buffer {
  // Order lexicographically
  const ordered =
    Buffer.compare(left, right) < 0
      ? Buffer.concat([left, right])
      : Buffer.concat([right, left])

  return taggedHash('TapBranch', ordered)
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
  merkleRoot: Buffer = Buffer.alloc(32),
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
  merkleRoot: Buffer = Buffer.alloc(32),
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
    const scriptBuf = Buffer.isBuffer(leafNode.script)
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
 * - 32 bytes: internal public key X-coordinate (without 0x02/0x03 prefix)
 * - 32*n bytes: merkle path
 *
 * Total size: 33 + 32*n bytes
 *
 * The parity bit (bit 0 of first byte) indicates if the internal pubkey's
 * Y-coordinate is even (0) or odd (1), allowing reconstruction of the full
 * 33-byte compressed public key during verification.
 *
 * Reference: lotusd/src/script/taproot.cpp lines 43-54
 *
 * @param internalPubKey - Internal public key (33-byte compressed)
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
  // Parity is 1 if y-coordinate is odd (pubkey byte is 0x03), 0 if even (0x02)
  const parity = pubKeyBytes[0] === 0x03 ? 1 : 0
  const controlByte = (leaf.leafVersion & TAPROOT_LEAF_MASK) | parity

  const writer = new BufferWriter()
  writer.writeUInt8(controlByte)

  // Next 32 bytes: x-coordinate only (not the full 33-byte compressed key)
  // Parity is already encoded in the control byte above
  // Control block format: [control_byte][32-byte x-coord][merkle_path...]
  writer.write(pubKeyBytes.slice(1, 33)) // Skip the 0x02/0x03 prefix, write only x-coordinate

  // Merkle path
  for (const node of leaf.merklePath) {
    writer.write(node)
  }

  return writer.toBuffer()
}

/**
 * Verify a Taproot commitment
 *
 * Verifies that the commitment pubkey equals internal_pubkey + tweak*G
 * where tweak = tagged_hash("TapTweak", internal_pubkey || merkle_root)
 *
 * @param commitmentPubKey - The commitment public key (from script)
 * @param internalPubKey - The internal public key (from control block)
 * @param merkleRoot - The merkle root
 * @returns true if commitment is valid
 */
export function verifyTaprootCommitment(
  commitmentPubKey: PublicKey,
  internalPubKey: PublicKey,
  merkleRoot: Buffer,
): boolean {
  const expectedCommitment = tweakPublicKey(internalPubKey, merkleRoot)
  return commitmentPubKey.toString() === expectedCommitment.toString()
}

/**
 * Check if a script is Pay-To-Taproot
 *
 * Valid formats:
 * - OP_SCRIPTTYPE OP_1 0x21 <33-byte commitment>
 * - OP_SCRIPTTYPE OP_1 0x21 <33-byte commitment> 0x20 <32-byte state>
 *
 * @param script - Script to check
 * @returns true if script is P2TR
 */
export function isPayToTaproot(script: Script): boolean {
  const buf = script.toBuffer()

  if (buf.length < TAPROOT_SIZE_WITHOUT_STATE) {
    return false
  }

  // Must start with OP_SCRIPTTYPE OP_1
  if (buf[0] !== Opcode.OP_SCRIPTTYPE || buf[1] !== TAPROOT_SCRIPTTYPE) {
    return false
  }

  // Next byte must be 0x21 (33 bytes push)
  if (buf[2] !== 33) {
    return false
  }

  // If exactly 36 bytes, valid without state
  if (buf.length === TAPROOT_SIZE_WITHOUT_STATE) {
    return true
  }

  // If has state, must be exactly 69 bytes with 0x20 (32 bytes) state push
  return (
    buf.length === TAPROOT_SIZE_WITH_STATE &&
    buf[TAPROOT_SIZE_WITHOUT_STATE] === 32
  )
}

/**
 * Extract the commitment public key from a Taproot script
 *
 * @param script - P2TR script
 * @returns Commitment public key
 * @throws Error if not a valid P2TR script
 */
export function extractTaprootCommitment(script: Script): PublicKey {
  if (!isPayToTaproot(script)) {
    throw new Error('Not a valid Pay-To-Taproot script')
  }

  const buf = script.toBuffer()
  const commitmentBytes = buf.subarray(3, 3 + 33)

  return PublicKey.fromBuffer(commitmentBytes)
}

/**
 * Extract the state from a Taproot script (if present)
 *
 * @param script - P2TR script
 * @returns State buffer (32 bytes) or null if no state
 */
export function extractTaprootState(script: Script): Buffer | null {
  const buf = script.toBuffer()

  if (buf.length !== TAPROOT_SIZE_WITH_STATE) {
    return null
  }

  return buf.subarray(TAPROOT_SIZE_WITHOUT_STATE + 1, TAPROOT_SIZE_WITH_STATE)
}

/**
 * Build a Pay-To-Taproot script
 *
 * @param commitment - Commitment public key (tweaked)
 * @param state - Optional 32-byte state
 * @returns P2TR script
 */
export function buildPayToTaproot(
  commitment: PublicKey,
  state?: Buffer,
): Script {
  if (state && state.length !== 32) {
    throw new Error('Taproot state must be exactly 32 bytes')
  }

  const commitmentBytes = commitment.toBuffer()

  if (commitmentBytes.length !== 33) {
    throw new Error('Commitment must be 33-byte compressed public key')
  }

  if (state) {
    return new Script()
      .add(Opcode.OP_SCRIPTTYPE)
      .add(TAPROOT_SCRIPTTYPE)
      .add(commitmentBytes)
      .add(state)
  } else {
    return new Script()
      .add(Opcode.OP_SCRIPTTYPE)
      .add(TAPROOT_SCRIPTTYPE)
      .add(commitmentBytes)
  }
}

/**
 * Build a simple key-path-only Taproot output
 *
 * @param internalPubKey - Internal public key
 * @param state - Optional 32-byte state
 * @returns P2TR script
 */
export function buildKeyPathTaproot(
  internalPubKey: PublicKey,
  state?: Buffer,
): Script {
  // For key-path only, merkle root is all zeros
  const merkleRoot = Buffer.alloc(32)
  const commitment = tweakPublicKey(internalPubKey, merkleRoot)
  return buildPayToTaproot(commitment, state)
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
  const script = buildPayToTaproot(commitment, state)

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
 * @param internalPubKey - Internal public key X-coordinate (32 bytes, without prefix)
 * @param script - Script being revealed
 * @param commitmentPubKey - Commitment public key from scriptPubKey (33 bytes)
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
    // parity bit tells us the prefix: 0 = 0x02 (even), 1 = 0x03 (odd)
    const pubkeyPrefix = parity === 0 ? 0x02 : 0x03
    const fullPubkey = Buffer.concat([
      Buffer.from([pubkeyPrefix]),
      internalPubKey,
    ])

    // Calculate leaf hash
    let leafHash = calculateTapLeaf(script, leafVersion)

    // Walk up the merkle tree
    for (const pathNode of merklePath) {
      // Sort hashes lexicographically before combining
      if (Buffer.compare(leafHash, pathNode) < 0) {
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
  if (!isPayToTaproot(scriptPubkey)) {
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

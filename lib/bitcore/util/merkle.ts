/**
 * Merkle tree utility functions
 * Migrated from bitcore-lib-xpi with TypeScript enhancements
 *
 * These utilities provide general-purpose merkle tree calculations
 * used across the bitcore block modules.
 */

import { Hash } from '../crypto/hash'
import { BufferUtil } from './buffer'
import type { Buffer } from 'buffer/'

/**
 * Calculate the width of a merkle tree at a given height.
 *
 * This determines how many nodes exist at a specific level in the tree,
 * accounting for the fact that merkle trees may have odd numbers of leaves
 * which get paired with duplicates.
 *
 * @param nLeaves - Total number of leaves (transaction hashes) in the tree
 * @param height - Height at which to calculate tree width (0 = leaves)
 * @returns Number of nodes at the specified height
 *
 * @example
 * ```typescript
 * // Block with 5 transactions
 * const widthAtLeaves = calcTreeWidth(10, 0) // 10 (hash + txid pairs)
 * const widthAtLevel1 = calcTreeWidth(10, 1) // 5
 * const widthAtRoot = calcTreeWidth(10, 3)   // 1
 * ```
 *
 * @remarks
 * This matches the implementation in lotusd (CPartialMerkleTree::CalcTreeWidth)
 * and Bitcoin Core (merkleblock.h).
 */
export function calcTreeWidth(nLeaves: number, height: number): number {
  return (nLeaves + (1 << height) - 1) >> height
}

/**
 * Calculate the height of a merkle tree given the number of leaves.
 *
 * @param nLeaves - Total number of leaves in the tree
 * @returns Height of the tree (0 for single leaf, increases with tree depth)
 *
 * @example
 * ```typescript
 * calcTreeHeight(1)   // 0 (single tx)
 * calcTreeHeight(2)   // 1
 * calcTreeHeight(5)   // 3
 * calcTreeHeight(10)  // 4
 * ```
 */
export function calcTreeHeight(nLeaves: number): number {
  let height = 0
  while (calcTreeWidth(nLeaves, height) > 1) {
    height++
  }
  return height
}

/**
 * Calculate the hash of a node in the merkle tree.
 *
 * At height 0, returns the leaf hash directly. At higher heights,
 * recursively calculates the hash by combining left and right child hashes.
 *
 * @param height - Current height in the tree (0 = leaves)
 * @param pos - Position at this height
 * @param hashes - Array of all leaf hashes
 * @param nullHash - Optional null hash buffer for padding (defaults to 32 zero bytes)
 * @returns The calculated hash as a hex string
 *
 * @example
 * ```typescript
 * const hashes = ['abc...', 'def...', 'ghi...']
 * const rootHash = calcMerkleHash(2, 0, hashes)
 * ```
 */
export function calcMerkleHash(
  height: number,
  pos: number,
  hashes: string[],
  nullHash: Buffer = BufferUtil.alloc(32),
): string {
  if (height === 0) {
    return hashes[pos]
  }

  const left = calcMerkleHash(height - 1, pos * 2, hashes, nullHash)
  let right = left

  if (pos * 2 + 1 < calcTreeWidth(hashes.length, height - 1)) {
    right = calcMerkleHash(height - 1, pos * 2 + 1, hashes, nullHash)
  } else {
    right = nullHash.toString('hex')
  }

  return Hash.sha256sha256(
    BufferUtil.concat([
      BufferUtil.from(left, 'hex'),
      BufferUtil.from(right, 'hex'),
    ]),
  ).toString('hex')
}

/**
 * Traverse and build a partial merkle tree.
 *
 * Recursively traverses the merkle tree, determining which nodes are parents
 * of matched transactions, and builds the arrays of flag bits and hashes
 * needed for a MerkleBlock.
 *
 * @param height - Current height in the tree
 * @param pos - Current position at this height
 * @param nLeaves - Total number of leaves in the tree
 * @param hashes - Array of all leaf hashes
 * @param vfMatch - Boolean array indicating which leaves match
 * @param vBits - Output array for flag bits (mutated)
 * @param vHash - Output array for hashes (mutated)
 * @param nullHash - Optional null hash buffer for padding
 *
 * @example
 * ```typescript
 * const vBits: boolean[] = []
 * const vHash: string[] = []
 * traverseAndBuild(height, 0, nLeaves, hashes, vfMatch, vBits, vHash)
 * ```
 */
export function traverseAndBuild(
  height: number,
  pos: number,
  nLeaves: number,
  hashes: string[],
  vfMatch: boolean[],
  vBits: boolean[],
  vHash: string[],
  nullHash: Buffer = BufferUtil.alloc(32),
): void {
  // Determine if this node is parent of at least one matched txid
  let fParentOfMatch = false
  const startIdx = pos << height
  const endIdx = Math.min((pos + 1) << height, nLeaves)
  for (let p = startIdx; p < endIdx; p++) {
    fParentOfMatch ||= vfMatch[p]
  }

  // Store as flag bit
  vBits.push(fParentOfMatch)

  if (height === 0 || !fParentOfMatch) {
    // Store hash and stop
    vHash.push(calcMerkleHash(height, pos, hashes, nullHash))
  } else {
    // Descend into subtrees
    traverseAndBuild(
      height - 1,
      pos * 2,
      nLeaves,
      hashes,
      vfMatch,
      vBits,
      vHash,
      nullHash,
    )
    if (pos * 2 + 1 < calcTreeWidth(nLeaves, height - 1)) {
      traverseAndBuild(
        height - 1,
        pos * 2 + 1,
        nLeaves,
        hashes,
        vfMatch,
        vBits,
        vHash,
        nullHash,
      )
    }
  }
}

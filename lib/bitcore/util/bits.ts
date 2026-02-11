/**
 * Copyright 2026 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * Bit manipulation utilities
 *
 * These utilities provide functions for converting between boolean bit arrays
 * and packed byte arrays (LSB-first bit ordering), used primarily for
 * MerkleBlock flag serialization per Lotus protocol specification.
 */

/**
 * Converts an array of boolean bits into an array of bytes.
 * Bits are packed LSB-first (least significant bit first) into each byte.
 *
 * This matches the Bitcoin/Lotus protocol specification for MerkleBlock
 * flag serialization as implemented in lotusd (BitsToBytes).
 *
 * @param bits - Array of boolean values representing individual bits
 * @returns Array of bytes with bits packed LSB-first
 *
 * @example
 * ```typescript
 * const bits = [true, false, true, false, true, false, true, false]
 * const bytes = bitsToBytes(bits) // [0b01010101] = [0x55]
 * ```
 */
export function bitsToBytes(bits: boolean[]): number[] {
  const bytes: number[] = new Array(Math.ceil(bits.length / 8)).fill(0)
  for (let p = 0; p < bits.length; p++) {
    bytes[p >> 3] |= (bits[p] ? 1 : 0) << (p & 7)
  }
  return bytes
}

/**
 * Converts an array of bytes into an array of boolean bits.
 * Bits are extracted LSB-first (least significant bit first) from each byte.
 *
 * This matches the Bitcoin/Lotus protocol specification for MerkleBlock
 * flag deserialization as implemented in lotusd (BytesToBits).
 *
 * @param bytes - Array of bytes containing packed bits
 * @returns Array of boolean values representing individual bits
 *
 * @example
 * ```typescript
 * const bytes = [0x55, 0xAA]
 * const bits = bytesToBits(bytes)
 * // [true, false, true, false, true, false, true, false,
 * //  false, true, false, true, false, true, false, true]
 * ```
 */
export function bytesToBits(bytes: number[]): boolean[] {
  const bits: boolean[] = new Array(bytes.length * 8)
  for (let p = 0; p < bits.length; p++) {
    bits[p] = (bytes[p >> 3] & (1 << (p & 7))) !== 0
  }
  return bits
}

/**
 * Extracts a single bit from a byte array at the specified position.
 * Uses LSB-first bit ordering consistent with Bitcoin/Lotus protocol.
 *
 * @param bytes - Array of bytes containing packed bits
 * @param position - Bit position (0-indexed, LSB-first)
 * @returns Boolean value of the bit at the specified position
 *
 * @example
 * ```typescript
 * const bytes = [0b00001111] // 0x0F
 * const bit0 = extractBit(bytes, 0) // true (LSB)
 * const bit4 = extractBit(bytes, 4) // true
 * const bit7 = extractBit(bytes, 7) // false
 * ```
 */
export function extractBit(bytes: number[], position: number): boolean {
  return (bytes[position >> 3] & (1 << (position & 7))) !== 0
}

/**
 * Sets a single bit in a byte array at the specified position.
 * Uses LSB-first bit ordering consistent with Bitcoin/Lotus protocol.
 *
 * @param bytes - Array of bytes to modify
 * @param position - Bit position (0-indexed, LSB-first)
 * @param value - Boolean value to set
 *
 * @example
 * ```typescript
 * const bytes = [0, 0]
 * setBit(bytes, 0, true)  // bytes = [1, 0] (0x01)
 * setBit(bytes, 8, true)  // bytes = [1, 1] (0x01, 0x01)
 * ```
 */
export function setBit(
  bytes: number[],
  position: number,
  value: boolean,
): void {
  const byteIndex = position >> 3
  const bitIndex = position & 7
  if (value) {
    bytes[byteIndex] |= 1 << bitIndex
  } else {
    bytes[byteIndex] &= ~(1 << bitIndex)
  }
}

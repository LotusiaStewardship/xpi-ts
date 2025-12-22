/**
 * Signature type detection utilities for Lotus
 *
 * Lotus automatically determines signature type by length:
 * - 64 bytes = Schnorr signature
 * - Other lengths (typically 70-72 bytes) = ECDSA signature (DER-encoded)
 *
 * Reference: lotusd/src/script/interpreter.cpp lines 1900-1908
 * Reference: lotusd/src/script/sigencoding.cpp lines 156-158
 */

/**
 * Check if a signature is Schnorr format (64 bytes)
 *
 * In Lotus, signatures are automatically interpreted as Schnorr if they are
 * exactly 64 bytes long. This is checked before any other validation.
 *
 * @param sig - The signature buffer (without sighash byte)
 * @returns true if signature is 64 bytes (Schnorr), false otherwise (ECDSA)
 */
export function isSchnorrSignature(sig: Buffer): boolean {
  return sig.length === 64
}

/**
 * Check if a signature is ECDSA format (DER-encoded)
 *
 * ECDSA signatures are DER-encoded and typically 70-72 bytes long.
 * Any signature that is not 64 bytes is assumed to be ECDSA.
 *
 * @param sig - The signature buffer (without sighash byte)
 * @returns true if signature is not 64 bytes (ECDSA), false if 64 bytes (Schnorr)
 */
export function isECDSASignature(sig: Buffer): boolean {
  return sig.length !== 64
}

/**
 * Get signature type as string for debugging
 *
 * @param sig - The signature buffer (without sighash byte)
 * @returns "schnorr" or "ecdsa"
 */
export function getSignatureType(sig: Buffer): 'schnorr' | 'ecdsa' {
  return isSchnorrSignature(sig) ? 'schnorr' : 'ecdsa'
}

/**
 * Validate signature length
 *
 * Checks if a signature has a valid length for either Schnorr or ECDSA.
 *
 * Valid lengths:
 * - Schnorr: Exactly 64 bytes
 * - ECDSA: Typically 70-72 bytes, but can be 9-73 bytes (DER format)
 *
 * @param sig - The signature buffer (without sighash byte)
 * @returns true if valid length, false otherwise
 */
export function isValidSignatureLength(sig: Buffer): boolean {
  // Schnorr is always 64 bytes
  if (sig.length === 64) {
    return true
  }

  // ECDSA DER signatures can be 9-73 bytes
  // Minimum: 0x30 [len] 0x02 0x01 [r] 0x02 0x01 [s] = 8 bytes + at least 1 byte content
  // Maximum: 0x30 0x48 0x02 0x21 [33 bytes r] 0x02 0x21 [33 bytes s] = 73 bytes
  if (sig.length >= 9 && sig.length <= 73) {
    return true
  }

  return false
}

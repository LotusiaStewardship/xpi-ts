/**
 * Digital signature handling for ECDSA and Schnorr signatures in Lotus
 *
 * This module provides a unified Signature class that supports both:
 * - ECDSA signatures (DER-encoded, variable length ~70-72 bytes)
 * - Schnorr signatures (fixed 64 bytes, big-endian)
 *
 * The signature type is automatically detected and handled based on:
 * - The `isSchnorr` flag
 * - The signature length (64 bytes = Schnorr)
 * - The serialization method parameter
 *
 * Key Features:
 * - Unified API for both signature types
 * - Automatic type detection
 * - Multiple serialization formats (DER, compact, transaction format)
 * - Full validation and parsing
 *
 * Reference: lotusd/src/secp256k1/ and lotusd/src/pubkey.cpp
 *
 * Migrated from bitcore-lib-xpi with ESM support and BigInt
 */
import { BN } from './bn.js'

/**
 * Data structure for initializing a Signature object
 *
 * @property r - The r value of the signature (x-coordinate of ephemeral public key)
 * @property s - The s value of the signature (proof component)
 * @property i - Recovery ID for ECDSA signature recovery (0-3)
 * @property compressed - Whether the signature uses compressed public key
 * @property isSchnorr - Flag indicating if this is a Schnorr signature (vs ECDSA)
 * @property nhashtype - Signature hash type (SIGHASH_ALL, etc.)
 */
export interface SignatureData {
  r: BN
  s: BN
  i?: number
  compressed?: boolean
  isSchnorr?: boolean
  nhashtype?: number
}

export type SignatureSigningMethod = 'schnorr' | 'ecdsa'

/**
 * Represents a cryptographic signature (ECDSA or Schnorr)
 *
 * This class handles both ECDSA and Schnorr signatures with a unified interface.
 * The signature type is determined by the `isSchnorr` flag or automatically
 * detected during parsing based on signature length and format.
 *
 * Signature Types:
 * - **ECDSA**: DER-encoded, variable length (typically 70-72 bytes), must use low-S
 * - **Schnorr**: Fixed 64 bytes, big-endian format [r (32) || s (32)]
 *
 * Serialization Formats:
 * - DER: Standard format (toDER)
 * - Transaction: DER + 1-byte sighash type (toTxFormat)
 * - Compact: Recovery format for message signing (toCompact)
 *
 * @example ECDSA Usage
 * ```typescript
 * const sig = ECDSA.sign(hash, privateKey)
 * const der = sig.toDER() // Returns DER-encoded bytes
 * const txFormat = sig.toTxFormat() // Adds sighash byte
 * ```
 *
 * @example Schnorr Usage
 * ```typescript
 * const sig = Schnorr.sign(hash, privateKey)
 * const bytes = sig.toDER('schnorr') // Returns 64 bytes big-endian
 * const txFormat = sig.toTxFormat('schnorr') // 65 bytes with sighash
 * ```
 */
export class Signature {
  /** The r value of the signature (elliptic curve point x-coordinate) */
  r!: BN

  /** The s value of the signature (proof component) */
  s!: BN

  /** Recovery ID for ECDSA public key recovery (0-3), used in message signing */
  i?: number

  /** Whether this signature uses a compressed public key */
  compressed?: boolean

  /** Flag indicating if this is a Schnorr signature (true) or ECDSA (false/undefined) */
  isSchnorr?: boolean

  /** Signature hash type - determines what parts of the transaction are signed */
  nhashtype?: number

  /**
   * SIGHASH_ALL (0x01): Sign all inputs and outputs
   *
   * This is the most common and secure sighash type. It commits to:
   * - All transaction inputs
   * - All transaction outputs
   * - Transaction version and locktime
   *
   * This prevents any modification of the transaction after signing.
   *
   * @constant
   */
  static readonly SIGHASH_ALL = 0x01

  /**
   * SIGHASH_NONE (0x02): Sign all inputs, but no outputs
   *
   * Allows outputs to be modified after signing. Commits to:
   * - All transaction inputs
   * - Transaction version and locktime
   * - NO outputs (can be changed)
   *
   * WARNING: Rarely used, can be dangerous if not understood properly.
   *
   * @constant
   */
  static readonly SIGHASH_NONE = 0x02

  /**
   * SIGHASH_SINGLE (0x03): Sign all inputs and one corresponding output
   *
   * Signs only the output at the same index as the input being signed.
   * Other outputs can be modified. Commits to:
   * - All transaction inputs
   * - The output at the same index as this input
   * - Transaction version and locktime
   *
   * Used for more complex transaction constructions.
   *
   * @constant
   */
  static readonly SIGHASH_SINGLE = 0x03

  /**
   * SIGHASH_FORKID (0x40): Use BIP143 sighash algorithm
   *
   * Indicates the signature uses the BIP143 sighash algorithm (BCH-style).
   * This is the standard for Lotus transactions and provides:
   * - Protection against replay attacks
   * - More efficient validation
   * - Better hardware wallet support
   *
   * This flag is typically combined with base types:
   * - SIGHASH_ALL | SIGHASH_FORKID = 0x41 (most common)
   * - SIGHASH_NONE | SIGHASH_FORKID = 0x42
   * - SIGHASH_SINGLE | SIGHASH_FORKID = 0x43
   *
   * Reference: BIP143 (Bitcoin Cash sighash)
   *
   * @constant
   */
  static readonly SIGHASH_FORKID = 0x40

  /**
   * SIGHASH_LOTUS (0x60): Use Lotus-specific sighash algorithm
   *
   * Indicates the signature uses the Lotus sighash algorithm.
   * This is a more advanced sighash that includes:
   * - Merkle roots for inputs and outputs (instead of simple hashes)
   * - Merkle tree heights for efficient validation
   * - Total input and output amounts
   * - Support for taproot/tapscript execution data
   *
   * Benefits over BIP143 (FORKID):
   * - More efficient batch validation via merkle proofs
   * - Better scaling for large transactions
   * - Enables future optimization strategies
   *
   * Usage Requirements:
   * - Must combine with a base type (SIGHASH_ALL or SIGHASH_SINGLE)
   * - SIGHASH_FORKID is already included (bit 6 is set in 0x60)
   * - Must provide spent outputs for all inputs via transaction.from()
   * - Example: SIGHASH_ALL | SIGHASH_LOTUS = 0x61
   *
   * Note: SIGHASH_LOTUS (0x60 = 0110 0000) already includes SIGHASH_FORKID
   * (0x40 = 0100 0000) because bit 6 is set. Adding FORKID is redundant.
   *
   * Status: ✅ FULLY IMPLEMENTED as of October 28, 2025
   *
   * Reference: lotusd/src/script/interpreter.cpp lines 1782-1846
   * Implementation: sighash.ts sighashForLotus()
   *
   * @constant
   */
  static readonly SIGHASH_LOTUS = 0x60

  /**
   * SIGHASH_ANYONECANPAY (0x80): Sign only this input, others can be added
   *
   * Modifier flag that changes how inputs are signed. When set:
   * - Only the current input is signed
   * - Other inputs can be added or removed
   * - All outputs are still signed (unless combined with NONE/SINGLE)
   *
   * Commonly combined with other flags:
   * - SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_FORKID = 0xC1
   *
   * Use cases:
   * - Crowdfunding transactions (anyone can add inputs)
   * - Partial transaction signing
   *
   * @constant
   */
  static readonly SIGHASH_ANYONECANPAY = 0x80

  /**
   * Create a new Signature instance
   *
   * @param r - Either a BN representing the r value, or a SignatureData object with all properties
   * @param s - The s value as a BN (only used if first param is BN)
   * @param isSchnorr - Whether this is a Schnorr signature (only used if first param is BN)
   *
   * @example Create from r and s values
   * ```typescript
   * const sig = new Signature(rBN, sBN, false) // ECDSA
   * const sig = new Signature(rBN, sBN, true)  // Schnorr
   * ```
   *
   * @example Create from SignatureData object
   * ```typescript
   * const sig = new Signature({
   *   r: rBN,
   *   s: sBN,
   *   isSchnorr: true,
   *   nhashtype: Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
   * })
   * ```
   */
  constructor(r: BN | SignatureData, s?: BN, isSchnorr?: boolean) {
    if (r instanceof BN) {
      this.set({
        r: r,
        s: s!,
        isSchnorr: isSchnorr,
      })
    } else if (r) {
      this.set(r)
    }
  }

  /**
   * Factory function to create a Signature without 'new' keyword
   *
   * @param r - Either a BN or SignatureData object
   * @param s - The s value (if r is a BN)
   * @param isSchnorr - Schnorr flag (if r is a BN)
   * @returns New Signature instance
   */
  static create(
    r?: BN | SignatureData,
    s?: BN,
    isSchnorr?: boolean,
  ): Signature {
    return new Signature(r!, s, isSchnorr)
  }

  /**
   * Set signature properties from a data object
   *
   * Updates the signature's properties with values from the provided object.
   * Only updates properties that are defined in the object.
   *
   * @param obj - Object containing signature properties to set
   * @returns This signature instance for chaining
   */
  set(obj: SignatureData): Signature {
    this.r = obj.r || this.r || undefined!
    this.s = obj.s || this.s || undefined!
    this.i = typeof obj.i !== 'undefined' ? obj.i : this.i
    this.compressed =
      typeof obj.compressed !== 'undefined' ? obj.compressed : this.compressed
    this.isSchnorr = obj.isSchnorr
    this.nhashtype = obj.nhashtype || this.nhashtype || undefined
    return this
  }

  /**
   * Create signature from compact format (used for message signing)
   *
   * Compact format is used for Bitcoin message signing and includes:
   * - 1 byte: recovery ID + compression flag (27-34)
   * - 32 bytes: r value (little-endian)
   * - 32 bytes: s value (little-endian)
   *
   * Total: 65 bytes
   *
   * Note: This format uses little-endian for compatibility with message signing.
   * This is different from Schnorr signatures which use big-endian.
   *
   * @param buf - 65-byte buffer in compact format
   * @returns Signature with recovery ID and compression flag set
   * @throws Error if buffer format is invalid
   */
  static fromCompact(buf: Buffer): Signature {
    if (!Buffer.isBuffer(buf)) {
      throw new Error('Argument is expected to be a Buffer')
    }

    const sig = new Signature(new BN(0), new BN(0))

    let compressed = true
    let i = buf.subarray(0, 1)[0] - 27 - 4
    if (i < 0) {
      compressed = false
      i = i + 4
    }

    const b2 = buf.subarray(1, 33)
    const b3 = buf.subarray(33, 65)

    if (!(i === 0 || i === 1 || i === 2 || i === 3)) {
      throw new Error('i must be 0, 1, 2, or 3')
    }
    if (b2.length !== 32) {
      throw new Error('r must be 32 bytes')
    }
    if (b3.length !== 32) {
      throw new Error('s must be 32 bytes')
    }

    sig.compressed = compressed
    sig.i = i
    sig.r = new BN(b2, 'le')
    sig.s = new BN(b3, 'le')

    return sig
  }

  /**
   * Create signature from DER or Schnorr format (auto-detect)
   *
   * This is the main parsing method that automatically detects signature type:
   * - If 64-65 bytes and doesn't start with 0x30: Parse as Schnorr
   * - Otherwise: Parse as DER-encoded ECDSA
   *
   * Schnorr Detection:
   * - 64 bytes: Schnorr signature without sighash
   * - 65 bytes starting with non-0x30: Schnorr with sighash
   *
   * ECDSA Format:
   * - Starts with 0x30 (DER sequence marker)
   * - Variable length (typically 70-72 bytes)
   * - Strictly validated if strict=true
   *
   * @param buf - Buffer containing the signature
   * @param strict - If true, enforce strict DER validation (default: true)
   * @returns Signature object with isSchnorr flag set appropriately
   * @throws Error if format is invalid
   */
  static fromDER(buf: Buffer, strict: boolean = true): Signature {
    // Schnorr Signatures use 64-65 byte format
    if ((buf.length === 64 || buf.length === 65) && buf[0] !== 0x30) {
      const obj = Signature.parseSchnorrEncodedSig(buf)
      const sig = new Signature(new BN(0), new BN(0))
      sig.r = obj.r
      sig.s = obj.s
      sig.isSchnorr = true
      return sig
    }

    if (buf.length === 64 && buf[0] === 0x30) {
      throw new Error('64 DER (ecdsa) signatures not allowed')
    }

    const obj = Signature.parseDER(buf, strict)
    const sig = new Signature(new BN(0), new BN(0))
    sig.r = obj.r
    sig.s = obj.s
    return sig
  }

  /**
   * Create signature from buffer (alias for fromDER)
   *
   * @param buf - Buffer containing signature data
   * @param strict - Enforce strict DER validation
   * @returns Signature object
   */
  static fromBuffer(buf: Buffer, strict: boolean = true): Signature {
    return Signature.fromDER(buf, strict)
  }

  /**
   * Create signature from transaction format
   *
   * Transaction format includes the signature plus a 1-byte sighash type:
   * - ECDSA: [DER signature (70-72 bytes)] + [sighash byte]
   * - Schnorr: [64-byte signature] + [sighash byte]
   *
   * The sighash byte is extracted and set as the nhashtype property.
   *
   * @param buf - Buffer in transaction format (signature + sighash byte)
   * @returns Signature with nhashtype property set
   */
  static fromTxFormat(buf: Buffer): Signature {
    const nhashtype = buf.readUInt8(buf.length - 1)
    const derbuf = buf.subarray(0, buf.length - 1)
    const sig = Signature.fromDER(derbuf, false)
    sig.nhashtype = nhashtype
    return sig
  }

  /**
   * Create signature from data format (alias for fromDER with non-strict parsing)
   *
   * @param buf - Buffer containing signature
   * @returns Signature object
   */
  static fromDataFormat(buf: Buffer): Signature {
    const derbuf = buf.subarray(0, buf.length)
    return Signature.fromDER(derbuf, false)
  }

  /**
   * Create signature from hexadecimal string
   *
   * @param str - Hex string representing the signature
   * @returns Signature object
   */
  static fromString(str: string): Signature {
    const buf = Buffer.from(str, 'hex')
    return Signature.fromDER(buf)
  }

  /**
   * Create signature from Schnorr format
   *
   * Accepts 64-byte Schnorr signature or 65-byte with sighash type
   *
   * @param buf - Buffer containing Schnorr signature
   * @returns Signature object with isSchnorr flag set
   */
  static fromSchnorr(buf: Buffer): Signature {
    const parsed = Signature.parseSchnorrEncodedSig(buf)
    const sig = new Signature(parsed.r, parsed.s)
    sig.isSchnorr = true
    if (parsed.nhashtype) {
      sig.nhashtype = parsed.nhashtype.readUInt8(0)
    }
    return sig
  }

  /**
   * Parse Schnorr encoded signature
   *
   * Schnorr signatures are 64 bytes (r + s) or 65 bytes (r + s + sighash)
   * Both r and s are 32-byte values in big-endian format
   *
   * CRITICAL: Schnorr signatures use big-endian byte order per Lotus specification
   * Reference: lotusd/src/secp256k1/src/modules/schnorr/schnorr_impl.h
   */
  static parseSchnorrEncodedSig(buf: Buffer): {
    r: BN
    s: BN
    nhashtype?: Buffer
  } {
    // Validate buffer length: must be exactly 64 or 65 bytes
    if (buf.length !== 64 && buf.length !== 65) {
      throw new Error(
        `Invalid Schnorr signature length: ${buf.length} bytes (expected 64 or 65)`,
      )
    }

    // Parse r and s as big-endian (network byte order)
    const r = buf.subarray(0, 32)
    const s = buf.subarray(32, 64)
    let hashtype: Buffer | undefined

    if (buf.length === 65) {
      hashtype = buf.subarray(64, 65)
    }

    return {
      r: new BN(r, 'be'), // Big-endian per Lotus spec
      s: new BN(s, 'be'), // Big-endian per Lotus spec
      nhashtype: hashtype,
    }
  }

  /**
   * Parse DER-encoded ECDSA signature
   *
   * DER (Distinguished Encoding Rules) format structure:
   * ```
   * 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
   * ```
   *
   * Validation checks:
   * - Must start with 0x30 (SEQUENCE marker)
   * - Length bytes must match actual content
   * - R and S must start with 0x02 (INTEGER marker)
   * - No unnecessary padding
   * - High bit padding for positive values
   *
   * @param buf - Buffer containing DER-encoded signature
   * @param strict - If true, enforce strict DER validation
   * @returns Object with r and s as BN values (big-endian)
   * @throws Error if DER format is invalid
   */
  static parseDER(buf: Buffer, strict: boolean = true): { r: BN; s: BN } {
    if (!Buffer.isBuffer(buf)) {
      throw new Error('DER formatted signature should be a buffer')
    }

    const header = buf[0]
    if (header !== 0x30) {
      throw new Error('Header byte should be 0x30')
    }

    let length = buf[1]
    const buflength = buf.subarray(2).length
    if (strict && length !== buflength) {
      throw new Error('Length byte should length of what follows')
    }

    length = length < buflength ? length : buflength

    const rheader = buf[2 + 0]
    if (rheader !== 0x02) {
      throw new Error('Integer byte for r should be 0x02')
    }

    const rlength = buf[2 + 1]
    const rbuf = buf.subarray(2 + 2, 2 + 2 + rlength)
    const r = new BN(rbuf, 'be')

    if (rlength !== rbuf.length) {
      throw new Error('Length of r incorrect')
    }

    const sheader = buf[2 + 2 + rlength + 0]
    if (sheader !== 0x02) {
      throw new Error('Integer byte for s should be 0x02')
    }

    const slength = buf[2 + 2 + rlength + 1]
    const sbuf = buf.subarray(
      2 + 2 + rlength + 2,
      2 + 2 + rlength + 2 + slength,
    )
    const s = new BN(sbuf, 'be')

    if (slength !== sbuf.length) {
      throw new Error('Length of s incorrect')
    }

    const sumlength = 2 + 2 + rlength + 2 + slength
    if (length !== sumlength - 2) {
      throw new Error('Length of signature incorrect')
    }

    return { r, s }
  }

  /**
   * Convert signature to compact format (for message signing)
   *
   * Compact format encodes the signature with recovery information:
   * - Byte 0: recovery ID (0-3) + 27 + (compressed ? 4 : 0)
   * - Bytes 1-32: r value (little-endian)
   * - Bytes 33-64: s value (little-endian)
   *
   * Total: 65 bytes
   *
   * Note: Uses little-endian for compatibility with Bitcoin message signing.
   *
   * @param i - Recovery ID override (0-3), uses this.i if not provided
   * @param compressed - Compression flag override, uses this.compressed if not provided
   * @returns 65-byte buffer in compact format
   * @throws Error if recovery ID is invalid
   */
  toCompact(i?: number, compressed?: boolean): Buffer {
    const recoveryId = typeof i === 'number' ? i : this.i
    const isCompressed =
      typeof compressed === 'boolean' ? compressed : this.compressed

    if (
      !(
        recoveryId === 0 ||
        recoveryId === 1 ||
        recoveryId === 2 ||
        recoveryId === 3
      )
    ) {
      throw new Error('i must be equal to 0, 1, 2, or 3')
    }

    let val = recoveryId + 27 + 4
    if (isCompressed === false) {
      val = val - 4
    }

    const b1 = Buffer.from([val])
    const b2 = this.r.toArrayLike(Buffer, 'le', 32)
    const b3 = this.s.toArrayLike(Buffer, 'le', 32)

    return Buffer.concat([b1, b2, b3])
  }

  /**
   * Convert to DER format
   *
   * For ECDSA: Returns DER-encoded signature (variable length, typically 70-72 bytes)
   * For Schnorr: Returns 64-byte signature in big-endian format [r (32) || s (32)]
   *
   * CRITICAL: Schnorr signatures use big-endian byte order per Lotus specification
   * Reference: lotusd/src/secp256k1/src/modules/schnorr/schnorr_impl.h
   */
  toDER(signingMethod: string = 'ecdsa'): Buffer {
    if (signingMethod === 'schnorr') {
      // Schnorr signatures: 64 bytes, big-endian (network byte order)
      // This matches the Lotus/BCH Schnorr specification
      return Buffer.concat([
        this.r.toArrayLike(Buffer, 'be', 32), // Big-endian for R.x
        this.s.toArrayLike(Buffer, 'be', 32), // Big-endian for s
      ])
    }

    const rnbuf = this.r.toArrayLike(Buffer, 'be')
    const snbuf = this.s.toArrayLike(Buffer, 'be')

    const rneg = (rnbuf[0] & 0x80) !== 0
    const sneg = (snbuf[0] & 0x80) !== 0

    const rbuf = rneg ? Buffer.concat([Buffer.from([0x00]), rnbuf]) : rnbuf
    const sbuf = sneg ? Buffer.concat([Buffer.from([0x00]), snbuf]) : snbuf

    const rlength = rbuf.length
    const slength = sbuf.length
    const length = 2 + rlength + 2 + slength
    const rheader = 0x02
    const sheader = 0x02
    const header = 0x30

    return Buffer.concat([
      Buffer.from([header, length, rheader, rlength]),
      rbuf,
      Buffer.from([sheader, slength]),
      sbuf,
    ])
  }

  /**
   * Convert to buffer format (alias for toDER)
   *
   * @param signingMethod - 'ecdsa' (default) or 'schnorr'
   * @returns Signature as Buffer
   */
  toBuffer(signingMethod?: string): Buffer {
    // Auto-detect signing method from isSchnorr flag if not specified
    const method = signingMethod || (this.isSchnorr ? 'schnorr' : 'ecdsa')
    return this.toDER(method)
  }

  /**
   * Convert to hexadecimal string
   *
   * Automatically detects format based on isSchnorr flag.
   * For Schnorr: Returns 64-byte raw signature as hex
   * For ECDSA: Returns DER-encoded signature as hex
   *
   * @returns Hex string of signature
   */
  toString(): string {
    const method = this.isSchnorr ? 'schnorr' : 'ecdsa'
    const buf = this.toDER(method)
    return buf.toString('hex')
  }

  /**
   * Convert to transaction format (signature + sighash byte)
   *
   * This is the format used in transaction scriptSig:
   * - ECDSA: [DER signature (70-72 bytes)] + [sighash type (1 byte)] = 71-73 bytes
   * - Schnorr: [64-byte signature] + [sighash type (1 byte)] = 65 bytes
   *
   * The sighash byte indicates what parts of the transaction are signed.
   *
   * @param signingMethod - 'ecdsa' (default) or 'schnorr'
   * @returns Buffer with signature + sighash byte appended
   *
   * @example
   * ```typescript
   * const sig = ECDSA.sign(hash, privkey)
   * sig.nhashtype = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
   * const txFormat = sig.toTxFormat() // 71-73 bytes
   * ```
   */
  toTxFormat(signingMethod?: SignatureSigningMethod): Buffer {
    const derbuf = this.toDER(signingMethod)
    const buf = Buffer.alloc(1)
    buf.writeUInt8(this.nhashtype || 0, 0)
    return Buffer.concat([derbuf, buf])
  }

  /**
   * Check if buffer contains a valid DER-encoded signature
   *
   * Validates DER encoding rules without throwing errors:
   * - Length between 8 and 72 bytes
   * - Proper DER structure with sequence and integer markers
   * - Valid length encodings
   * - No unnecessary padding
   *
   * This is a non-throwing validation useful for checking if data
   * is likely a valid ECDSA signature.
   *
   * @param buf - Buffer to validate
   * @returns true if buffer appears to be valid DER signature
   */
  static isDER(buf: Buffer): boolean {
    if (buf.length < 8 || buf.length > 72) {
      return false
    }

    if (buf[0] !== 0x30) {
      return false
    }

    if (buf[1] !== buf.length - 2) {
      return false
    }

    if (buf[2] !== 0x02) {
      return false
    }

    const lenR = buf[3]
    if (lenR === 0) {
      return false
    }

    if (buf[4] & 0x80) {
      return false
    }

    if (lenR > buf.length - 7) {
      return false
    }

    if (lenR > 1 && buf[4] === 0x00 && !(buf[5] & 0x80)) {
      return false
    }

    const startS = lenR + 4
    if (buf[startS] !== 0x02) {
      return false
    }

    const lenS = buf[startS + 1]
    if (lenS === 0) {
      return false
    }

    if (buf[startS + 2] & 0x80) {
      return false
    }

    if (startS + lenS + 2 !== buf.length) {
      return false
    }

    if (lenS > 1 && buf[startS + 2] === 0x00 && !(buf[startS + 3] & 0x80)) {
      return false
    }

    return true
  }

  /**
   * Check if signature has low S value (BIP 62 compliance)
   *
   * To prevent signature malleability, Lotus requires that S <= (n-1)/2
   * where n is the secp256k1 curve order.
   *
   * Threshold: 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
   *
   * This check is important for:
   * - Transaction signature validation
   * - Preventing signature malleability attacks
   * - Network consensus compliance
   *
   * Reference: lotusd enforces low-S via secp256k1_ecdsa_signature_normalize
   *
   * @returns true if S is in the low range [1, (n-1)/2]
   */
  hasLowS(): boolean {
    const lowSThreshold = new BN(
      '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0',
      16,
    )

    if (this.s.lt(new BN(1)) || this.s.gt(lowSThreshold)) {
      return false
    }
    return true
  }

  /**
   * Check if signature has a valid/defined sighash type
   *
   * Validates that the nhashtype is a valid sighash type value.
   * Valid base types are SIGHASH_ALL (1), SIGHASH_NONE (2), or SIGHASH_SINGLE (3).
   * Can be combined with SIGHASH_FORKID (0x40) and SIGHASH_ANYONECANPAY (0x80).
   *
   * @returns true if nhashtype is defined and valid
   */
  hasDefinedHashtype(): boolean {
    if (typeof this.nhashtype !== 'number') {
      return false
    }

    // Check if SIGHASH_LOTUS is set (Taproot signatures)
    if (this.nhashtype & Signature.SIGHASH_LOTUS) {
      // LOTUS is valid, just check the base type
      const baseMask =
        ~(Signature.SIGHASH_LOTUS | Signature.SIGHASH_ANYONECANPAY) >>> 0
      const baseType = this.nhashtype & baseMask
      return (
        baseType >= Signature.SIGHASH_ALL &&
        baseType <= Signature.SIGHASH_SINGLE
      )
    }

    // Original logic for FORKID signatures
    const mask =
      ~(Signature.SIGHASH_FORKID | Signature.SIGHASH_ANYONECANPAY) >>> 0
    const temp = this.nhashtype & mask

    if (temp < Signature.SIGHASH_ALL || temp > Signature.SIGHASH_SINGLE) {
      return false
    }
    return true
  }

  /**
   * Check if buffer is valid transaction DER format
   *
   * Transaction format is: [DER signature] + [1-byte sighash type]
   * This validates only the DER portion (excluding the last sighash byte).
   *
   * @param buf - Buffer to check (including sighash byte)
   * @returns true if the signature portion (excluding last byte) is valid DER
   */
  static isTxDER(buf: Buffer): boolean {
    return Signature.isDER(buf.subarray(0, buf.length - 1))
  }
}

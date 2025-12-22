/**
 * Schnorr signature implementation for Lotus
 *
 * This implements the custom Schnorr signature scheme used by Lotus (BCH-derived),
 * which is different from BIP340 (Bitcoin Taproot).
 *
 * Reference: lotusd/src/secp256k1/src/modules/schnorr/schnorr_impl.h
 *
 * Key Differences from BIP340:
 * - Uses compressed public key (33 bytes) instead of x-only (32 bytes)
 * - Hash construction: e = Hash(R.x || compressed(P) || m) instead of Hash(R.x || P.x || m)
 * - Verification equation: R = s*G - e*P (standard Schnorr)
 * - Checks that R.y is a quadratic residue (Jacobi symbol = 1)
 *
 * Signature Format:
 * - 64 bytes total: [R.x (32 bytes) || s (32 bytes)]
 * - No sighash byte appended to raw signature
 *
 * Signing: s = k + e*x where e = Hash(R.x || compressed(P) || m) mod n
 * Verification: Check that s*G - e*P has x-coordinate equal to r and y is quadratic residue
 */

import { BN } from './bn.js'
import { Point } from './point.js'
import { Signature } from './signature.js'
import { Hash } from './hash.js'
import { PrivateKey } from '../privatekey.js'
import { PublicKey } from '../publickey.js'

export interface SchnorrData {
  hashbuf?: Buffer
  endian?: 'little' | 'big'
  privkey?: PrivateKey
  pubkey?: PublicKey
  sig?: Signature
  verified?: boolean
}

export class Schnorr {
  hashbuf!: Buffer
  endian!: 'little' | 'big'
  privkey!: PrivateKey
  pubkey!: PublicKey
  sig!: Signature
  verified!: boolean

  constructor(obj?: SchnorrData) {
    if (obj) {
      this.set(obj)
    }
  }

  set(obj: SchnorrData): Schnorr {
    this.hashbuf = obj.hashbuf || this.hashbuf
    this.endian = obj.endian || this.endian
    this.privkey = obj.privkey || this.privkey
    this.pubkey =
      obj.pubkey || (this.privkey ? this.privkey.toPublicKey() : this.pubkey)
    this.sig = obj.sig || this.sig
    this.verified = obj.verified || this.verified
    return this
  }

  /**
   * Derive public key from private key
   */
  privkey2pubkey(): Schnorr {
    this.pubkey = this.privkey.toPublicKey()
    return this
  }

  /**
   * Get public key
   */
  toPublicKey(): PublicKey {
    return this.privkey.toPublicKey()
  }

  /**
   * Sign the hash using Schnorr
   */
  sign(): Schnorr {
    const hashbuf = this.hashbuf
    const privkey = this.privkey
    const d = privkey.bn

    if (!hashbuf || !privkey || !d) {
      throw new Error('invalid parameters')
    }
    if (!Buffer.isBuffer(hashbuf) || hashbuf.length !== 32) {
      throw new Error('hashbuf must be a 32 byte buffer')
    }

    // Convert hash to BN with endianness, then pass to _findSignature
    // This matches the original bitcore-lib-xpi implementation
    const e = new BN(hashbuf, 'be')
    const obj = this._findSignature(d, e)
    obj.compressed = this.pubkey.compressed
    obj.isSchnorr = true

    this.sig = new Signature(obj)
    return this
  }

  /**
   * Find signature values using Lotus Schnorr algorithm
   *
   * Process:
   * 1. Generate deterministic nonce k using RFC6979 with "Schnorr+SHA256  " seed
   * 2. Compute R = k*G
   * 3. If R.y is not a quadratic residue, use n-k instead (negate)
   * 4. Compute e = Hash(R.x || compressed(P) || m) mod n
   * 5. Compute s = k + e*d mod n
   * 6. Return signature (r=R.x, s)
   */
  _findSignature(
    d: BN,
    e: BN,
  ): { r: BN; s: BN; compressed?: boolean; isSchnorr?: boolean } {
    const n = Point.getN()
    const G = Point.getG()

    if (d.lte(new BN(0))) {
      throw new Error('privkey out of field of curve')
    }
    if (d.gte(n)) {
      throw new Error('privkey out of field of curve')
    }

    let k = this.nonceFunctionRFC6979(
      d.toArrayLike(Buffer, 'be', 32),
      e.toArrayLike(Buffer, 'be', 32),
    )

    const P = G.mul(d)
    const R = G.mul(k)

    // Negate k if R.y is not a quadratic residue (Jacobi symbol != 1)
    // This ensures R.y is always a quadratic residue in the final signature
    // CRITICAL: Only negate k, NOT R!
    // Point negation: (-k)*G has the SAME x-coordinate as k*G but opposite y
    if (R.hasSquare()) {
      // k is already correct - R.y is a quadratic residue (even)
    } else {
      // Negate k: use n-k instead
      // This makes the signature use -R which has even y-coordinate
      k = n.sub(k)
    }

    const r = R.getX()
    const rBuffer = this.getrBuffer(r)

    // Compute e = Hash(R.x || compressed(P) || m) mod n
    // This is the Lotus/BCH Schnorr hash construction
    // Note: compressed(P) is 33 bytes, not x-only like BIP340
    const e0 = new BN(
      Hash.sha256(
        Buffer.concat([
          rBuffer,
          Point.pointToCompressed(P),
          e.toArrayLike(Buffer, 'be', 32),
        ]),
      ),
      'be',
    )

    const s = e0.mul(d).add(k).mod(n)

    return { r, s, compressed: this.pubkey.compressed, isSchnorr: true }
  }

  /**
   * Ensure r part of signature is at least 32 bytes
   */
  private getrBuffer(r: BN): Buffer {
    const rNaturalLength = r.toArrayLike(Buffer, 'be').length
    if (rNaturalLength < 32) {
      return r.toArrayLike(Buffer, 'be', 32)
    }
    return r.toArrayLike(Buffer, 'be')
  }

  /**
   * Ensure s part of signature is at least 32 bytes
   */
  private getsBuffer(s: BN): Buffer {
    const sNaturalLength = s.toArrayLike(Buffer, 'be').length
    if (sNaturalLength < 32) {
      return s.toArrayLike(Buffer, 'be', 32)
    }
    return s.toArrayLike(Buffer, 'be')
  }

  /**
   * Check for signature errors (verification)
   *
   * Lotus Schnorr Verification:
   * 1. Check signature length is 64 or 65 bytes (65 with sighash byte)
   * 2. Check r < p (field prime) and s < n (curve order)
   * 3. Compute e = Hash(r || compressed(P) || m) mod n
   * 4. Compute R = s*G - e*P
   * 5. Check R is not infinity
   * 6. Check R.y is a quadratic residue
   * 7. Check R.x == r
   *
   * Returns true if verification fails, false if signature is valid
   */
  sigError(): boolean {
    if (!Buffer.isBuffer(this.hashbuf) || this.hashbuf.length !== 32) {
      return true
    }

    const sigLength =
      this.getrBuffer(this.sig.r).length + this.getsBuffer(this.sig.s).length
    if (!(sigLength === 64 || sigLength === 65)) {
      return true
    }

    const hashbuf =
      this.endian === 'little' ? this.reverseBuffer(this.hashbuf) : this.hashbuf
    const P = this.pubkey.point
    const G = Point.getG()

    if (P.isInfinity()) {
      return true
    }

    const r = this.sig.r
    const s = this.sig.s

    const p = new BN(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
      16,
    )
    const n = Point.getN()

    if (r.gte(p) || s.gte(n)) {
      return true
    }

    const Br = this.getrBuffer(this.sig.r)
    const Bp = Point.pointToCompressed(P)

    // Compute challenge: e = Hash(r || compressed(P) || m) mod n
    const hash = Hash.sha256(Buffer.concat([Br, Bp, hashbuf]))
    const e = new BN(hash, 'be').mod(n)

    // Verification equation: R = s*G - e*P
    // We compute this as s*G + (-e)*P = s*G + (n-e)*P
    const sG = G.mul(s)
    const eP = P.mul(n.sub(e)) // -e*P = (n-e)*P in modular arithmetic
    const R = sG.add(eP)

    // Check validity conditions:
    // 1. R must not be point at infinity
    // 2. R.y must be a quadratic residue (Jacobi symbol = 1)
    // 3. R.x must equal r (the signature's r value)
    if (R.isInfinity() || !R.hasSquare() || !R.getX().eq(r)) {
      return true // Verification failed
    }

    return false
  }

  /**
   * Verify signature
   */
  verify(): Schnorr {
    // eslint-disable-next-line no-extra-boolean-cast
    this.verified = !!!this.sigError()
    return this
  }

  /**
   * RFC6979 deterministic nonce generation for Lotus Schnorr
   *
   * Uses HMAC-DRBG with SHA256 and Schnorr-specific domain separator.
   *
   * Key difference from standard RFC6979:
   * - Uses "Schnorr+SHA256  " (with trailing spaces) as the algorithm identifier
   * - This ensures different nonces than ECDSA for the same key and message
   *
   * Reference: lotusd/src/secp256k1/src/modules/schnorr/schnorr_impl.h
   */
  nonceFunctionRFC6979(privkey: Buffer, msgbuf: Buffer): BN {
    let V = Buffer.from(
      '0101010101010101010101010101010101010101010101010101010101010101',
      'hex',
    )
    let K = Buffer.from(
      '0000000000000000000000000000000000000000000000000000000000000000',
      'hex',
    )

    const blob = Buffer.concat([
      privkey,
      msgbuf,
      Buffer.from('', 'ascii'),
      Buffer.from('Schnorr+SHA256  ', 'ascii'),
    ])

    K = Hash.sha256hmac(
      Buffer.concat([V, Buffer.from('00', 'hex'), blob]),
      K,
    ) as Buffer<ArrayBuffer>
    V = Hash.sha256hmac(V, K) as Buffer<ArrayBuffer>

    K = Hash.sha256hmac(
      Buffer.concat([V, Buffer.from('01', 'hex'), blob]),
      K,
    ) as Buffer<ArrayBuffer>
    V = Hash.sha256hmac(V, K) as Buffer<ArrayBuffer>

    let k = new BN(0)
    let T: BN

    while (true) {
      V = Hash.sha256hmac(V, K) as Buffer<ArrayBuffer>
      T = new BN(V, 'be')

      k = T
      if (V.length < 32) {
        throw new Error('V length should be >= 32')
      }
      if (k.gt(new BN(0)) && k.lt(Point.getN())) {
        break
      }
      K = Hash.sha256hmac(
        Buffer.concat([V, Buffer.from('00', 'hex')]),
        K,
      ) as Buffer<ArrayBuffer>
      V = Hash.sha256hmac(V, K) as Buffer<ArrayBuffer>
    }

    return k
  }

  /**
   * Static sign method
   */
  static sign(
    hashbuf: Buffer,
    privkey: PrivateKey,
    endian?: 'little' | 'big',
  ): Signature {
    return new Schnorr()
      .set({
        hashbuf: hashbuf,
        endian: endian,
        privkey: privkey,
      })
      .sign().sig
  }

  /**
   * Static verify method
   */
  static verify(
    hashbuf: Buffer,
    sig: Signature,
    pubkey: PublicKey,
    endian?: 'little' | 'big',
  ): boolean {
    return new Schnorr()
      .set({
        hashbuf: hashbuf,
        endian: endian,
        sig: sig,
        pubkey: pubkey,
      })
      .verify().verified
  }

  /**
   * Reverse buffer byte order
   */
  private reverseBuffer(buf: Buffer): Buffer {
    const buf2 = Buffer.alloc(buf.length)
    for (let i = 0; i < buf.length; i++) {
      buf2[i] = buf[buf.length - 1 - i]
    }
    return buf2
  }
}

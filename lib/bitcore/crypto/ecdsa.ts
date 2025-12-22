/**
 * ECDSA (Elliptic Curve Digital Signature Algorithm) implementation for Lotus
 *
 * This implements standard secp256k1 ECDSA as used by Lotus.
 *
 * Reference: lotusd/src/pubkey.cpp (lines 173-198)
 *
 * Key Requirements:
 * - Signatures must be DER-encoded (typically 70-72 bytes)
 * - Signatures must use low-S form (BIP 62)
 * - Verification automatically normalizes high-S to low-S
 *
 * Low-S Requirement:
 * - S must be <= n/2 where n is the curve order
 * - If S > n/2, replace with S' = n - S
 * - Prevents signature malleability (CVE-2013-2292)
 *
 * Signature Format:
 * - DER-encoded ECDSA signature (variable length, typically 70-72 bytes)
 * - Plus 1-byte sighash type when used in transactions
 *
 * Migrated from bitcore-lib-xpi with ESM support
 */

import { BN } from './bn.js'
import { Point } from './point.js'
import { Signature } from './signature.js'
import { Hash } from './hash.js'
import { Random } from './random.js'
import { PrivateKey } from '../privatekey.js'
import { PublicKey } from '../publickey.js'

export interface ECDSAData {
  hashbuf?: Buffer
  endian?: 'little' | 'big'
  privkey?: PrivateKey
  pubkey?: PublicKey
  sig?: Signature
  k?: BN
  verified?: boolean
}

export class ECDSA {
  hashbuf!: Buffer
  endian?: 'little' | 'big'
  privkey!: PrivateKey
  pubkey!: PublicKey
  sig!: Signature
  k!: BN
  verified!: boolean

  constructor(obj?: ECDSAData) {
    if (obj) {
      this.set(obj)
    }
  }

  // Factory function to allow calling ECDSA() without 'new'
  static create(obj?: ECDSAData): ECDSA {
    return new ECDSA(obj)
  }

  set(obj: ECDSAData): ECDSA {
    this.hashbuf = obj.hashbuf || this.hashbuf
    this.endian = obj.endian || this.endian
    this.privkey = obj.privkey || this.privkey
    this.pubkey =
      obj.pubkey || (this.privkey ? this.privkey.toPublicKey() : this.pubkey)
    this.sig = obj.sig || this.sig
    this.k = obj.k || this.k
    this.verified = obj.verified || this.verified
    return this
  }

  /**
   * Derive public key from private key
   */
  privkey2pubkey(): ECDSA {
    this.pubkey = this.privkey.toPublicKey()
    return this
  }

  /**
   * Calculate recovery factor i
   */
  calci(): ECDSA {
    for (let i = 0; i < 4; i++) {
      this.sig!.i = i
      let Qprime: PublicKey
      try {
        Qprime = this.toPublicKey()
      } catch (e) {
        console.error(e)
        continue
      }

      if (Qprime.point.eq(this.pubkey.point)) {
        this.sig!.compressed = this.pubkey.compressed
        return this
      }
    }

    this.sig!.i = undefined
    throw new Error('Unable to find valid recovery factor')
  }

  /**
   * Create ECDSA from JSON string
   */
  static fromString(str: string): ECDSA {
    const obj = JSON.parse(str)
    return new ECDSA(obj)
  }

  /**
   * Generate random k value
   */
  randomK(): ECDSA {
    const N = Point.getN()
    let k: BN
    do {
      k = new BN(Random.getPseudoRandomBuffer(32), 'be')
    } while (!(k.lt(N) && k.gt(new BN(0))))
    this.k = k
    return this
  }

  /**
   * Generate deterministic k value using RFC 6979
   */
  deterministicK(badrs: number = 0): ECDSA {
    let v = Buffer.alloc(32)
    v.fill(0x01)
    let k = Buffer.alloc(32)
    k.fill(0x00)

    const x = this.privkey!.toBuffer()
    const hashbuf =
      this.endian === 'little'
        ? this.reverseBuffer(this.hashbuf!)
        : this.hashbuf!

    k = Hash.sha256hmac(
      Buffer.concat([v, Buffer.from([0x00]), x, hashbuf]),
      k,
    ) as Buffer<ArrayBuffer>
    v = Hash.sha256hmac(v, k) as Buffer<ArrayBuffer>
    k = Hash.sha256hmac(
      Buffer.concat([v, Buffer.from([0x01]), x, hashbuf]),
      k,
    ) as Buffer<ArrayBuffer>
    v = Hash.sha256hmac(v, k) as Buffer<ArrayBuffer>
    v = Hash.sha256hmac(v, k) as Buffer<ArrayBuffer>

    let T = new BN(v, 'be')
    const N = Point.getN()

    for (let i = 0; i < badrs || !(T.lt(N) && T.gt(new BN(0))); i++) {
      k = Hash.sha256hmac(
        Buffer.concat([v, Buffer.from([0x00])]),
        k,
      ) as Buffer<ArrayBuffer>
      v = Hash.sha256hmac(v, k) as Buffer<ArrayBuffer>
      v = Hash.sha256hmac(v, k) as Buffer<ArrayBuffer>
      T = new BN(v, 'be')
    }

    this.k = T
    return this
  }

  /**
   * Recover public key from signature
   */
  toPublicKey(): PublicKey {
    const i = this.sig!.i
    if (!(i === 0 || i === 1 || i === 2 || i === 3)) {
      throw new Error('i must be equal to 0, 1, 2, or 3')
    }

    const e = new BN(this.hashbuf!, 'be')
    const r = this.sig!.r
    const s = this.sig!.s

    const isYOdd = (i & 1) !== 0
    const isSecondKey = i >> 1 !== 0

    const n = Point.getN()
    const G = Point.getG()

    const x = isSecondKey ? r.add(n) : r
    const R = Point.fromX(isYOdd, x)

    const nR = R.mul(n)
    if (!nR.isInfinity()) {
      throw new Error('nR is not a valid curve point')
    }

    const eNeg = e.neg().mod(n)
    const rInv = r.invm(n)

    const Q = R.mul(s).add(G.mul(eNeg)).mul(rInv)

    const pubkey = PublicKey.fromPoint(Q, this.sig!.compressed)
    return pubkey
  }

  /**
   * Check for signature errors
   */
  sigError(): string | false {
    if (!Buffer.isBuffer(this.hashbuf) || this.hashbuf.length !== 32) {
      return 'hashbuf must be a 32 byte buffer'
    }

    const r = this.sig!.r
    const s = this.sig!.s
    const N = Point.getN()

    if (!(r.gt(new BN(0)) && r.lt(N)) || !(s.gt(new BN(0)) && s.lt(N))) {
      return 'r and s not in range'
    }

    const e = new BN(this.hashbuf, this.endian === 'little' ? 'le' : 'be')
    const n = Point.getN()
    const sinv = s.invm(n)
    const u1 = sinv.mul(e).mod(n)
    const u2 = sinv.mul(r).mod(n)

    const p = Point.getG().mulAdd(u1, this.pubkey.point, u2)
    if (p.isInfinity()) {
      return 'p is infinity'
    }

    if (p.getX().mod(n).cmp(r) !== 0) {
      return 'Invalid signature'
    } else {
      return false
    }
  }

  /**
   * Convert to low S value (BIP 62 - Low S signatures)
   *
   * To prevent signature malleability, enforce that S <= n/2.
   * If S > n/2, replace with S' = n - S.
   *
   * This matches Lotus behavior where signatures are normalized:
   * secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig)
   *
   * Threshold = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
   * This is (n-1)/2 where n is the secp256k1 curve order
   */
  static toLowS(s: BN): BN {
    const lowSThreshold = new BN(
      '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0',
      16,
    )

    if (s.gt(lowSThreshold)) {
      s = Point.getN().sub(s)
    }
    return s
  }

  /**
   * Find signature values
   */
  _findSignature(d: BN, e: BN): { s: BN; r: BN; compressed?: boolean } {
    const N = Point.getN()
    const G = Point.getG()
    let badrs = 0
    let k: BN, Q: Point, r: BN, s: BN

    do {
      if (!this.k || badrs > 0) {
        this.deterministicK(badrs)
      }
      badrs++
      k = this.k!
      Q = G.mul(k)
      r = Q.getX().mod(N)
      s = k
        .invm(N)
        .mul(e.add(d.mul(r)))
        .mod(N)
    } while (r.cmp(new BN(0)) <= 0 || s.cmp(new BN(0)) <= 0)

    s = ECDSA.toLowS(s)
    return { s, r, compressed: this.pubkey.compressed }
  }

  /**
   * Sign the hash
   */
  sign(): ECDSA {
    const hashbuf = this.hashbuf!
    const privkey = this.privkey!
    const d = privkey.bn

    if (!hashbuf || !privkey || !d) {
      throw new Error('invalid parameters')
    }
    if (!Buffer.isBuffer(hashbuf) || hashbuf.length !== 32) {
      throw new Error('hashbuf must be a 32 byte buffer')
    }

    const e = new BN(hashbuf, this.endian === 'little' ? 'le' : 'be')
    const obj = this._findSignature(d, e)
    obj.compressed = this.pubkey.compressed

    this.sig = new Signature(obj)
    return this
  }

  /**
   * Sign with random k
   */
  signRandomK(): ECDSA {
    this.randomK()
    return this.sign()
  }

  /**
   * Convert to JSON string
   */
  toString(): string {
    const obj: Record<string, unknown> = {}
    if (this.hashbuf) {
      obj.hashbuf = this.hashbuf.toString('hex')
    }
    if (this.privkey) {
      obj.privkey = this.privkey.toString()
    }
    if (this.pubkey) {
      obj.pubkey = this.pubkey.toString()
    }
    if (this.sig) {
      obj.sig = this.sig.toString()
    }
    if (this.k) {
      obj.k = this.k.toString()
    }
    return JSON.stringify(obj)
  }

  /**
   * Verify signature
   */
  verify(): ECDSA {
    if (!this.sigError()) {
      this.verified = true
    } else {
      this.verified = false
    }
    return this
  }

  /**
   * Static sign method
   */
  static sign(
    hashbuf: Buffer,
    privkey: PrivateKey,
    endian?: 'little' | 'big',
  ): Signature {
    return ECDSA.create()
      .set({
        hashbuf: hashbuf,
        endian: endian,
        privkey: privkey,
      })
      .sign().sig!
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
    return ECDSA.create()
      .set({
        hashbuf: hashbuf,
        endian: endian,
        sig: sig,
        pubkey: pubkey,
      })
      .verify().verified!
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

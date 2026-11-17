/**
 * Replay protection (First Chronicles) Unit Tests
 *
 * After First Chronicles (tip MTP >= activation time) the node validates the
 * next block with SCRIPT_ENABLE_REPLAY_PROTECTION: every signature is hashed
 * with sighash fork value 0xffdead. Signers must put that fork value in the
 * upper 24 bits of the 32-bit sighash type in the preimage while the
 * signature itself still carries one byte.
 *
 * Covers:
 * - the node's sighash vectors (src/test/data/sighash.json, 1000 random
 *   transactions and 32-bit sighash types, checked by the C++ test
 *   sighash_tests/sighash_from_data): legacy, BIP143 (FORKID), SIGHASH_LOTUS,
 *   with and without SCRIPT_ENABLE_REPLAY_PROTECTION
 * - signer (fork value in the sighash type) == verifier (replay-protection
 *   flag) on every vector
 * - fork value selection: tip MTP vs activation time, network aware
 * - every signing path: P2PKH (ECDSA, Schnorr), P2PK, bare multisig, P2SH
 *   multisig, Taproot key path, MuSig2 sighash
 * - random-transaction property tests (seeded)
 * - boundary window, broadcast refusal detection, time-locked transactions,
 *   LOTUS_REPLAY_PROTECTION_ACTIVATION_TIME
 *
 * Vectors: test/data/sighash.json = the node's src/test/data/sighash.json.
 *
 * Reference: lotusd/src/validation.cpp IsReplayProtectionEnabled,
 *            lotusd/src/script/interpreter.cpp SignatureHash,
 *            lotusd/src/test/sighash_tests.cpp
 */

import { afterEach, beforeEach, describe, it } from 'node:test'
import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Buffer } from 'buffer/'
import {
  BN,
  Hash,
  Interpreter,
  PrivateKey,
  PublicKey,
  Script,
  Signature,
  Transaction,
  sighash,
  Networks,
  buildKeyPathTaproot,
  buildMuSig2TaprootKey,
  SIGHASH_FORK_VALUE_DEFAULT,
  SIGHASH_FORK_VALUE_REPLAY_PROTECTED,
  REPLAY_PROTECTION_ACTIVATION_TIME,
  getNextBlockSighashForkValue,
  getReplayProtectionActivationTime,
  getSighashForkValue,
  isKnownSighashForkValue,
  isReplayProtectionEnabledForNextBlock,
  replayProtectionFlagsForForkValue,
  withSighashForkValue,
  REPLAY_PROTECTION_ACTIVATION_TIME_ENV,
  REPLAY_PROTECTION_DEFAULT_MARGIN_SECONDS,
  getReplayProtectionWindow,
  isReplayProtectionRefusal,
  getSighashForkValueForTransaction,
} from '../../lib/bitcore/index.js'
import { sighashForLotus } from '../../lib/bitcore/transaction/sighash.js'

// ─── Test Helpers ────────────────────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url))
const RP = SIGHASH_FORK_VALUE_REPLAY_PROTECTED
const F_FORKID = Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID
const F_RP = Interpreter.SCRIPT_ENABLE_REPLAY_PROTECTION
// lotusd mandatory/standard flags a wallet transaction is checked with
const F_STD =
  Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID |
  Interpreter.SCRIPT_VERIFY_CLEANSTACK |
  Interpreter.SCRIPT_VERIFY_INPUT_SIGCHECKS

const ALL_FORKID = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
const ALL_LOTUS = Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS

/** Display order of lotusd uint256::GetHex(). */
function rev(buf: Buffer): string {
  return Buffer.from(buf).reverse().toString('hex')
}

/** The fork value lotusd's interpreter uses with the replay flag. */
function verifierForkValue(forkValue: number): number {
  return 0xff0000 | (forkValue ^ 0xdead)
}

/** Small seeded PRNG (mulberry32) so property tests are reproducible. */
function prng(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function randInt(r: () => number, lo: number, hi: number): number {
  return lo + Math.floor(r() * (hi - lo + 1))
}

function randBytes(r: () => number, n: number): Buffer {
  const b = Buffer.alloc(n)
  for (let i = 0; i < n; i++) b[i] = randInt(r, 0, 255)
  return b
}

function randKey(r: () => number): PrivateKey {
  // secp256k1 order is just below 2^256: a random 31-byte scalar is valid
  const bn = new BN(randBytes(r, 31).toString('hex'), 16).add(new BN(1))
  return new PrivateKey(bn, Networks.regtest)
}

function verifyInput(tx: Transaction, i: number, flags: number): boolean {
  const input = tx.inputs[i]
  const interp = new Interpreter()
  return interp.verify(
    input.script!,
    input.output!.script,
    tx,
    i,
    flags,
    BigInt(input.output!.satoshis),
  )
}

function lastSigByte(tx: Transaction, inputIndex: number, chunk = 0): number {
  const buf = tx.inputs[inputIndex].script!.chunks[chunk].buf!
  return buf[buf.length - 1]
}

// ─── node sighash.json vectors ─────────────────────────────────

type Vector = [string, string, number, number, string, string, string]

const VECTORS: Vector[] = (
  JSON.parse(
    readFileSync(join(HERE, '..', 'data', 'sighash.json'), 'utf8'),
  ) as unknown[]
).filter(v => Array.isArray(v) && v.length === 7) as Vector[]

/**
 * xpi-ts cannot build the legacy SIGHASH_SINGLE pre-image when it blanks
 * earlier outputs to the 0xffffffffffffffff sentinel (not a JS number).
 * Legacy (non-FORKID) signatures are invalid on Lotus anyway: lotusd always
 * validates with SCRIPT_ENABLE_SIGHASH_FORKID (MUST_USE_FORKID).
 */
function legacySingleSentinel(v: Vector, tx: Transaction): boolean {
  const nIn = v[2]
  const type = v[3] >>> 0
  return (
    (type & 0x1f) === Signature.SIGHASH_SINGLE &&
    nIn > 0 &&
    nIn < tx.outputs.length
  )
}

/**
 * lotusd sighash for a vector, computed by xpi-ts.
 * flags: FORKID (regular), 0 (no forkid), FORKID|RP (replay protected).
 */
function vectorSighash(v: Vector, type: number, flags: number): string {
  const [txhex, scripthex, nIn] = v
  const tx = new Transaction(txhex)
  const scriptBuf = Buffer.from(scripthex, 'hex')
  const algo = type & Signature.SIGHASH_ALGORITHM_MASK
  if (flags & F_FORKID && algo === Signature.SIGHASH_LOTUS) {
    // The C++ test hashes SIGHASH_LOTUS with execdata (executed script =
    // scriptCode, no OP_CODESEPARATOR) and spent outputs that are default
    // CTxOut (nValue = -1 satoshi) except the scriptPubKey of nIn.
    let t = type >>> 0
    if (flags & F_RP) {
      t = withSighashForkValue(t, verifierForkValue(getSighashForkValue(t)))
    }
    const spent = tx.inputs.map((_, i) => ({
      satoshis: -1,
      scriptBuffer: i === nIn ? scriptBuf : Buffer.alloc(0),
    }))
    return rev(
      sighashForLotus(
        tx,
        t,
        nIn,
        spent as never,
        Hash.sha256sha256(scriptBuf),
        0xffffffff,
      ),
    )
  }
  const h = sighash(
    tx,
    type >>> 0,
    nIn,
    Script.fromBuffer(scriptBuf),
    new BN(0),
    flags,
  )
  // BIP143 returns the raw double-SHA256, legacy returns it reversed
  return flags & F_FORKID && algo === Signature.SIGHASH_FORKID
    ? rev(h)
    : h.toString('hex')
}

describe('Replay protection', () => {
  describe('node sighash.json vectors (C++ SignatureHash)', () => {
    it('has the 1000 vectors', () => {
      assert.strictEqual(VECTORS.length, 1000)
    })

    it('matches every regular, no-forkid and replay-protected sighash', () => {
      const counts = { regular: 0, legacy: 0, replay: 0, skipped: 0 }
      const byAlgo: Record<string, number> = {}
      for (const v of VECTORS) {
        const tx = new Transaction(v[0])
        const type = v[3] >>> 0
        const algo = type & Signature.SIGHASH_ALGORITHM_MASK
        const skipLegacy = legacySingleSentinel(v, tx)
        if (algo === 0 && skipLegacy) {
          counts.skipped++
          continue
        }
        byAlgo[algo.toString(16)] = (byAlgo[algo.toString(16)] || 0) + 1
        assert.strictEqual(
          vectorSighash(v, type, F_FORKID),
          v[4],
          `regular ${JSON.stringify(v)}`,
        )
        counts.regular++
        assert.strictEqual(
          vectorSighash(v, type, F_FORKID | F_RP),
          v[6],
          `replay ${JSON.stringify(v)}`,
        )
        counts.replay++
        if (!skipLegacy) {
          assert.strictEqual(
            vectorSighash(v, type, 0),
            v[5],
            `legacy ${JSON.stringify(v)}`,
          )
          counts.legacy++
        }
      }
      // Every FORKID and SIGHASH_LOTUS vector is checked; only legacy
      // SIGHASH_SINGLE vectors with blanked outputs are left out.
      assert.ok(counts.regular >= 990, JSON.stringify(counts))
      assert.ok(counts.replay >= 990, JSON.stringify(counts))
      assert.ok(counts.legacy >= 930, JSON.stringify(counts))
      assert.ok(
        byAlgo['40'] > 200 && byAlgo['60'] > 400,
        JSON.stringify(byAlgo),
      )
    })

    it('signer with fork value 0xffdead == verifier with the replay flag', () => {
      // What a signer computes after First Chronicles (fork value in the
      // sighash type, no flag) is what lotusd's interpreter computes from
      // the one-byte signature type under SCRIPT_ENABLE_REPLAY_PROTECTION.
      let n = 0
      for (const v of VECTORS) {
        const type = v[3] >>> 0
        const algo = type & Signature.SIGHASH_ALGORITHM_MASK
        if (algo === 0) continue
        const low = type & 0xff
        const signer = vectorSighash(v, withSighashForkValue(low, RP), F_FORKID)
        const verifier = vectorSighash(v, low, F_FORKID | F_RP)
        assert.strictEqual(signer, verifier)
        // and the fork value really changes the hash
        assert.notStrictEqual(signer, vectorSighash(v, low, F_FORKID))
        n++
      }
      assert.ok(n > 600, `checked ${n}`)
    })
  })

  describe('sighash type helpers', () => {
    it('withSighashForkValue keeps the low byte and is unsigned', () => {
      const t = withSighashForkValue(ALL_FORKID, RP)
      assert.strictEqual(t, 0xffdead41)
      assert.ok(t > 0)
      assert.strictEqual(getSighashForkValue(t), RP)
      assert.strictEqual(t & 0xff, ALL_FORKID)
      assert.strictEqual(withSighashForkValue(t, 0), ALL_FORKID)
      assert.throws(() => withSighashForkValue(ALL_FORKID, 0x1000000))
      assert.throws(() => withSighashForkValue(ALL_FORKID, -1))
    })

    it('knows exactly the two fork values lotusd accepts', () => {
      assert.ok(isKnownSighashForkValue(0))
      assert.ok(isKnownSighashForkValue(0xffdead))
      assert.ok(!isKnownSighashForkValue(0xdead))
      assert.ok(!isKnownSighashForkValue(1))
      assert.strictEqual(SIGHASH_FORK_VALUE_DEFAULT, 0)
      assert.strictEqual(RP, verifierForkValue(0))
      assert.strictEqual(replayProtectionFlagsForForkValue(RP), F_RP)
      assert.strictEqual(replayProtectionFlagsForForkValue(0), 0)
    })

    it('Signature.toTxFormat writes only the low byte', () => {
      const sig = Signature.fromString(
        '3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022009c7e3a40bbd03c6b9ae29fd1ba8c33e67ec95e8b17e9ea79e5a3c4cdd9c3b1c',
      )
      sig.nhashtype = withSighashForkValue(ALL_FORKID, RP)
      const buf = sig.toTxFormat()
      assert.strictEqual(buf[buf.length - 1], 0x41)
    })
  })

  describe('fork value selection (next block rule)', () => {
    const A = REPLAY_PROTECTION_ACTIVATION_TIME.livenet

    it('uses lotusd chain parameters', () => {
      assert.strictEqual(A, 1813587000)
      assert.strictEqual(
        REPLAY_PROTECTION_ACTIVATION_TIME.testnet,
        1813587000 - 21 * 24 * 3600,
      )
      assert.strictEqual(REPLAY_PROTECTION_ACTIVATION_TIME.regtest, 1813587000)
    })

    it('flips exactly when tip MTP reaches the activation time', () => {
      const expected = [0, 0, RP, RP, RP]
      ;[-2, -1, 0, 1, 2].forEach((d, i) => {
        assert.strictEqual(
          getNextBlockSighashForkValue({
            network: 'livenet',
            tipMedianTimePast: A + d,
          }),
          expected[i],
          `MTP A${d >= 0 ? '+' : ''}${d}`,
        )
      })
    })

    it('no tip -> fork value 0', () => {
      assert.strictEqual(
        getNextBlockSighashForkValue({ tipMedianTimePast: undefined }),
        0,
      )
      assert.strictEqual(
        getNextBlockSighashForkValue({ tipMedianTimePast: null }),
        0,
      )
      assert.ok(!isReplayProtectionEnabledForNextBlock(NaN, 0))
    })

    it('is network aware (lotusd and xpi-ts names)', () => {
      const T = REPLAY_PROTECTION_ACTIVATION_TIME.testnet
      for (const n of ['test', 'testnet', Networks.testnet]) {
        assert.strictEqual(getReplayProtectionActivationTime(n), T)
        assert.strictEqual(
          getNextBlockSighashForkValue({ network: n, tipMedianTimePast: T }),
          RP,
        )
        assert.strictEqual(
          getNextBlockSighashForkValue({
            network: n,
            tipMedianTimePast: T - 1,
          }),
          0,
        )
      }
      for (const n of ['main', 'mainnet', 'livenet', Networks.livenet]) {
        assert.strictEqual(getReplayProtectionActivationTime(n), A)
      }
      assert.strictEqual(getReplayProtectionActivationTime('regtest'), A)
      assert.strictEqual(getReplayProtectionActivationTime(), A)
      assert.throws(() => getReplayProtectionActivationTime('nonsense'))
    })

    it('prefers the activation time the node reports (override)', () => {
      assert.strictEqual(
        getNextBlockSighashForkValue({
          network: 'regtest',
          tipMedianTimePast: 1000,
          activationTime: 1000,
        }),
        RP,
      )
      assert.strictEqual(
        getNextBlockSighashForkValue({
          network: 'regtest',
          tipMedianTimePast: 999,
          activationTime: 1000,
        }),
        0,
      )
      // null/undefined override -> chain parameter
      assert.strictEqual(getReplayProtectionActivationTime('regtest', null), A)
    })
  })

  describe('signing paths', () => {
    const r = prng(0x5eed)
    const prev = (): string => randBytes(r, 32).toString('hex')

    function checkTx(tx: Transaction, forkValue: number, label: string): void {
      const flags = F_STD | replayProtectionFlagsForForkValue(forkValue)
      const other =
        F_STD | replayProtectionFlagsForForkValue(forkValue === RP ? 0 : RP)
      for (let i = 0; i < tx.inputs.length; i++) {
        assert.ok(
          verifyInput(tx, i, flags),
          `${label} input ${i} fork ${forkValue}`,
        )
        assert.ok(
          !verifyInput(tx, i, other),
          `${label} input ${i} other fork value`,
        )
      }
      assert.strictEqual(tx.verify(), true, label)
      assert.ok(tx.isFullySigned(), label)
      // round trip: the serialized transaction carries one-byte types
      const back = new Transaction(
        tx.serialize({ disableDustOutputs: true } as never),
      )
      assert.strictEqual(back.id, tx.id)
    }

    for (const forkValue of [0, RP]) {
      it(`P2PKH ECDSA and Schnorr, fork value ${forkValue.toString(16)}`, () => {
        for (const method of ['ecdsa', 'schnorr'] as const) {
          const key = randKey(r)
          const tx = new Transaction()
            .from(
              [0, 1].map(i => ({
                txId: prev(),
                outputIndex: i,
                satoshis: 100000 + i,
                script: Script.buildPublicKeyHashOut(key.toAddress()),
              })),
            )
            .to(randKey(r).toAddress(), 150000)
            .change(key.toAddress())
          tx.setSighashForkValue(forkValue).sign(key, null, method)
          for (let i = 0; i < tx.inputs.length; i++) {
            assert.strictEqual(lastSigByte(tx, i), ALL_FORKID)
          }
          checkTx(tx, forkValue, `p2pkh-${method}`)
        }
      })

      it(`P2PK, bare multisig and P2SH multisig, fork value ${forkValue.toString(16)}`, () => {
        const k = [randKey(r), randKey(r), randKey(r)]
        const pubs = k.map(x => x.publicKey)

        const p2pk = new Transaction()
          .from({
            txId: prev(),
            outputIndex: 0,
            satoshis: 50000,
            script: Script.buildPublicKeyOut(pubs[0]),
          })
          .to(k[1].toAddress(), 40000)
        p2pk.setSighashForkValue(forkValue).sign(k[0])
        checkTx(p2pk, forkValue, 'p2pk')

        const bare = new Transaction()
          .from(
            {
              txId: prev(),
              outputIndex: 0,
              satoshis: 50000,
              script: Script.buildMultisigOut(pubs, 2),
            },
            pubs,
            2,
          )
          .to(k[1].toAddress(), 40000)
        bare.setSighashForkValue(forkValue).sign([k[0], k[2]])
        checkTx(bare, forkValue, 'bare-multisig')

        const redeem = Script.buildMultisigOut(pubs, 2)
        const p2sh = new Transaction()
          .from(
            {
              txId: prev(),
              outputIndex: 0,
              satoshis: 50000,
              script: Script.buildScriptHashOut(redeem),
            },
            pubs,
            2,
          )
          .to(k[1].toAddress(), 40000)
        p2sh.setSighashForkValue(forkValue).sign([k[1], k[2]])
        checkTx(p2sh, forkValue, 'p2sh-multisig')
        // multisig signatures are serialized with one byte as well
        for (const c of p2sh.inputs[0].script!.chunks.slice(1, 3)) {
          assert.strictEqual(c.buf![c.buf!.length - 1], ALL_FORKID)
        }
      })

      it(`Taproot key path (SIGHASH_LOTUS), fork value ${forkValue.toString(16)}`, () => {
        const key = randKey(r)
        const out = buildKeyPathTaproot(key.publicKey)
        const tx = new Transaction()
          .from(
            [0, 1].map(i => ({
              txId: prev(),
              outputIndex: i,
              satoshis: 70000,
              script: out,
              internalPubKey: key.publicKey,
            })),
          )
          .to(randKey(r).toAddress(), 100000)
        tx.setSighashForkValue(forkValue).sign(key, null, 'schnorr')
        for (let i = 0; i < tx.inputs.length; i++) {
          assert.strictEqual(lastSigByte(tx, i), ALL_LOTUS)
        }
        checkTx(tx, forkValue, 'taproot-keypath')
      })
    }

    it('MuSig2 sighash uses the transaction fork value', () => {
      const signers = [randKey(r), randKey(r)]
      const tap = buildMuSig2TaprootKey(signers.map(k => k.publicKey))
      const make = (): Transaction =>
        new Transaction()
          .from({
            txId: '11'.repeat(32),
            outputIndex: 0,
            satoshis: 100000,
            script: tap.script,
            keyAggContext: tap.keyAggContext,
            mySignerIndex: 0,
            internalPubKey: tap.keyAggContext.aggregatedPubKey,
            merkleRoot: tap.merkleRoot,
          } as never)
          .to(signers[1].toAddress(), 90000)
      const script = tap.script
      const h0 = make().getMuSig2Sighash(0)
      const hRp = make().setSighashForkValue(RP).getMuSig2Sighash(0)
      const tx = make()
      assert.ok(h0.equals(sighash(tx, ALL_LOTUS, 0, script, new BN(100000))))
      assert.ok(!h0.equals(hRp))
      // == what lotusd's verifier hashes for a 0x61 signature with the flag
      assert.ok(
        hRp.equals(
          sighash(tx, ALL_LOTUS, 0, script, new BN(100000), F_FORKID | F_RP),
        ),
      )
    })

    it('an explicit sigtype carrying a fork value wins', () => {
      const key = randKey(r)
      const tx = new Transaction()
        .from({
          txId: prev(),
          outputIndex: 0,
          satoshis: 100000,
          script: Script.buildPublicKeyHashOut(key.toAddress()),
        })
        .to(randKey(r).toAddress(), 90000)
      tx.sign(key, withSighashForkValue(ALL_FORKID, RP))
      assert.ok(verifyInput(tx, 0, F_STD | F_RP))
      assert.ok(!verifyInput(tx, 0, F_STD))
    })

    it('refuses unknown fork values', () => {
      assert.throws(() => new Transaction().setSighashForkValue(0xdead))
      assert.throws(() => new Transaction().setSighashForkValue(1))
    })

    it('default stays fork value 0 (pre-activation behaviour unchanged)', () => {
      const key = randKey(r)
      const tx = new Transaction()
        .from({
          txId: prev(),
          outputIndex: 0,
          satoshis: 100000,
          script: Script.buildPublicKeyHashOut(key.toAddress()),
        })
        .to(randKey(r).toAddress(), 90000)
        .sign(key)
      assert.strictEqual(tx.sighashForkValue, 0)
      assert.ok(verifyInput(tx, 0, F_STD))
      assert.ok(!verifyInput(tx, 0, F_STD | F_RP))
    })
  })

  describe('random transactions (property tests)', () => {
    const seed = Number(process.env.XPI_RP_SEED || 0x1c4a0)
    const iterations = Number(process.env.XPI_RP_ITERATIONS || 150)

    it(`sign/verify agree with lotusd's rule on ${iterations} random transactions (seed ${seed})`, () => {
      const r = prng(seed)
      const bases = [
        Signature.SIGHASH_ALL,
        Signature.SIGHASH_NONE,
        Signature.SIGHASH_SINGLE,
      ]
      let checked = 0
      for (let it = 0; it < iterations; it++) {
        const forkValue = r() < 0.5 ? 0 : RP
        const nIn = randInt(r, 1, 4)
        const keys = Array.from({ length: nIn }, () => randKey(r))
        const kinds = keys.map(() => randInt(r, 0, 2)) // p2pkh ecdsa / p2pkh schnorr / taproot
        const tx = new Transaction()
        keys.forEach((k, i) => {
          tx.from({
            txId: randBytes(r, 32).toString('hex'),
            outputIndex: randInt(r, 0, 5),
            satoshis: randInt(r, 10000, 5000000),
            script:
              kinds[i] === 2
                ? buildKeyPathTaproot(k.publicKey)
                : Script.buildPublicKeyHashOut(k.toAddress()),
            ...(kinds[i] === 2 ? { internalPubKey: k.publicKey } : {}),
          })
        })
        const nOut = randInt(r, nIn, nIn + 3) // >= nIn so SIGHASH_SINGLE has an output
        for (let o = 0; o < nOut; o++) {
          tx.to(randKey(r).toAddress(), randInt(r, 1000, 9000))
        }
        if (r() < 0.5) tx.nLockTime = randInt(r, 0, 0x7fffffff)
        for (const inp of tx.inputs) {
          if (r() < 0.3) inp.sequenceNumber = randInt(r, 0, 0xfffffffe)
        }
        tx.setSighashForkValue(forkValue)
        keys.forEach((k, i) => {
          const base = bases[randInt(r, 0, 2)]
          const acp = r() < 0.3 ? Signature.SIGHASH_ANYONECANPAY : 0
          const algo =
            kinds[i] === 2 ? Signature.SIGHASH_LOTUS : Signature.SIGHASH_FORKID
          const sigtype = base | acp | algo
          const method = kinds[i] === 0 ? 'ecdsa' : 'schnorr'
          // sign only input i with its own type (keys are distinct), with
          // the transaction's fork value like Transaction.getSignatures()
          const sigs = tx.inputs[i].getSignatures(
            tx,
            k,
            i,
            withSighashForkValue(sigtype, tx.sighashForkValue),
            undefined,
            method,
          )
          assert.strictEqual(sigs.length, 1)
          for (const s of sigs) {
            assert.strictEqual(getSighashForkValue(s.sigtype), forkValue)
            tx.applySignature(s, method)
          }
          assert.strictEqual(lastSigByte(tx, i), sigtype)
        })
        const flags = F_STD | replayProtectionFlagsForForkValue(forkValue)
        const wrong =
          F_STD | replayProtectionFlagsForForkValue(forkValue === RP ? 0 : RP)
        for (let i = 0; i < nIn; i++) {
          assert.ok(verifyInput(tx, i, flags), `iteration ${it} input ${i}`)
          assert.ok(
            !verifyInput(tx, i, wrong),
            `iteration ${it} input ${i} wrong fork`,
          )
          // byte-level: the signature verifies against the sighash computed
          // the lotusd verifier way (one-byte type + replay flag)
          checked++
        }
      }
      assert.ok(checked >= iterations, `checked ${checked}`)
    })

    it('random sighash types: signer and verifier pre-images agree', () => {
      const r = prng(seed ^ 0xabcdef)
      for (let i = 0; i < 300; i++) {
        const key = randKey(r)
        const tx = new Transaction()
          .from({
            txId: randBytes(r, 32).toString('hex'),
            outputIndex: 0,
            satoshis: 100000,
            script: Script.buildPublicKeyHashOut(key.toAddress()),
          })
          .to(randKey(r).toAddress(), 50000)
          .to(randKey(r).toAddress(), 40000)
        const low = (randInt(r, 1, 3) | (r() < 0.5 ? 0x80 : 0) | 0x40) & 0xff
        const forkValue = randInt(r, 0, 0xffffff)
        const s = tx.inputs[0].output!.script
        const signer = sighash(
          tx,
          withSighashForkValue(low, verifierForkValue(forkValue)),
          0,
          s,
          new BN(100000),
        )
        const verifier = sighash(
          tx,
          withSighashForkValue(low, forkValue),
          0,
          s,
          new BN(100000),
          F_FORKID | F_RP,
        )
        assert.ok(signer.equals(verifier))
      }
    })
  })
})

describe('Replay protection helpers', () => {
  const A = REPLAY_PROTECTION_ACTIVATION_TIME.livenet
  const T = REPLAY_PROTECTION_ACTIVATION_TIME.testnet
  const ENV = REPLAY_PROTECTION_ACTIVATION_TIME_ENV
  const DELTAS = [-2, -1, 0, 1, 2]
  const EXPECTED = [0, 0, RP, RP, RP]
  const r = prng(0xc4a1)

  // No test in this block may see a stray LOTUS_REPLAY_PROTECTION_ACTIVATION_TIME.
  let savedEnv: string | undefined
  beforeEach(() => {
    savedEnv = process.env[ENV]
    delete process.env[ENV]
  })
  afterEach(() => {
    if (savedEnv === undefined) delete process.env[ENV]
    else process.env[ENV] = savedEnv
  })

  function p2pkhTx(nInputs = 1): { tx: Transaction; key: PrivateKey } {
    const key = randKey(r)
    const tx = new Transaction()
      .from(
        Array.from({ length: nInputs }, (_, i) => ({
          txId: randBytes(r, 32).toString('hex'),
          outputIndex: i,
          satoshis: 100000,
          script: Script.buildPublicKeyHashOut(key.toAddress()),
        })),
      )
      .to(randKey(r).toAddress(), 90000 * nInputs)
    return { tx, key }
  }

  /** The signature verifies with exactly the expected rule set. */
  function assertSignedWith(tx: Transaction, forkValue: number, label: string) {
    const ok = F_STD | replayProtectionFlagsForForkValue(forkValue)
    const ko =
      F_STD | replayProtectionFlagsForForkValue(forkValue === RP ? 0 : RP)
    for (let i = 0; i < tx.inputs.length; i++) {
      assert.ok(
        verifyInput(tx, i, ok),
        `${label}: input ${i} fork ${forkValue}`,
      )
      assert.ok(
        !verifyInput(tx, i, ko),
        `${label}: input ${i} wrong fork value`,
      )
    }
  }

  describe('boundary window', () => {
    const M = REPLAY_PROTECTION_DEFAULT_MARGIN_SECONDS

    it('default margin is one hour', () => {
      assert.strictEqual(M, 3600)
    })

    it('nearBoundary exactly at +-margin, not just outside', () => {
      const cases: Array<[number, boolean, boolean]> = [
        // [MTP - A, nearBoundary, active]
        [-M - 1, false, false],
        [-M, true, false],
        [-1, true, false],
        [0, true, true],
        [M, true, true],
        [M + 1, false, true],
      ]
      for (const [d, near, active] of cases) {
        const w = getReplayProtectionWindow({
          network: 'main',
          tipMedianTimePast: A + d,
        })
        assert.strictEqual(
          w.nearBoundary,
          near,
          `MTP A${d >= 0 ? '+' : ''}${d}`,
        )
        assert.strictEqual(w.active, active)
        assert.strictEqual(w.forkValue, active ? RP : 0)
        assert.strictEqual(w.activationTime, A)
        assert.strictEqual(w.secondsToActivation, A - (A + d))
      }
    })

    it('custom margin, explicit activation time and network', () => {
      const w0 = getReplayProtectionWindow({
        tipMedianTimePast: 1000,
        activationTime: 1000,
        marginSeconds: 0,
      })
      assert.deepStrictEqual(w0, {
        forkValue: RP,
        active: true,
        activationTime: 1000,
        secondsToActivation: 0,
        nearBoundary: true,
      })
      assert.strictEqual(
        getReplayProtectionWindow({
          tipMedianTimePast: 999,
          activationTime: 1000,
          marginSeconds: 0,
        }).nearBoundary,
        false,
      )
      const wt = getReplayProtectionWindow({
        network: 'testnet',
        tipMedianTimePast: T - 600,
        marginSeconds: 600,
      })
      assert.strictEqual(wt.activationTime, T)
      assert.strictEqual(wt.nearBoundary, true)
      assert.strictEqual(wt.active, false)
      assert.throws(() =>
        getReplayProtectionWindow({ tipMedianTimePast: A, marginSeconds: -1 }),
      )
      assert.throws(() =>
        getReplayProtectionWindow({ tipMedianTimePast: A, marginSeconds: NaN }),
      )
      assert.throws(() =>
        getReplayProtectionWindow({
          tipMedianTimePast: undefined as unknown as number,
        }),
      )
    })

    it('secondsToActivation is positive before, negative after', () => {
      const before = getReplayProtectionWindow({
        network: 'main',
        tipMedianTimePast: A - 86400,
      })
      assert.strictEqual(before.secondsToActivation, 86400)
      assert.strictEqual(before.active, false)
      assert.strictEqual(before.nearBoundary, false)
      const after = getReplayProtectionWindow({
        network: 'main',
        tipMedianTimePast: A + 86400,
      })
      assert.strictEqual(after.secondsToActivation, -86400)
      assert.strictEqual(after.active, true)
      assert.strictEqual(after.forkValue, RP)
    })
  })

  describe('isReplayProtectionRefusal', () => {
    it('detects script verification refusals', () => {
      const positives: unknown[] = [
        'mandatory-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)',
        'non-mandatory-script-verify-flag (Signature hash type missing or not understood)',
        '16: mandatory-script-verify-flag-failed',
        'script-verify-flag-failed',
        'MANDATORY-SCRIPT-VERIFY-FLAG-FAILED',
        new Error(
          'mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)',
        ),
        { message: 'non-mandatory-script-verify-flag (x)' },
        {
          error: { code: -26, message: 'mandatory-script-verify-flag-failed' },
        },
        { error: 'script-verify-flag-failed' },
      ]
      for (const e of positives) {
        assert.strictEqual(isReplayProtectionRefusal(e), true, String(e))
      }
    })

    it('ignores other errors', () => {
      const negatives: unknown[] = [
        'insufficient fee',
        'txn-mempool-conflict',
        'bad-txns-inputs-missingorspent',
        'non-final',
        new Error('dust'),
        { message: 'min relay fee not met' },
        { message: 42 },
        { error: { code: -25 } },
        {},
        [],
        42,
        null,
        undefined,
        '',
      ]
      for (const e of negatives) {
        assert.strictEqual(isReplayProtectionRefusal(e), false, String(e))
      }
    })
  })

  describe('time-locked transactions', () => {
    function locked(lockTime: number, sequences: number[]) {
      return {
        nLockTime: lockTime,
        inputs: sequences.map(sequenceNumber => ({ sequenceNumber })),
      }
    }
    const NONFINAL = [0xffffffff, 0xfffffffe]

    it('timestamp lock: A-2 -> next block, A-1 and later -> 0xffdead', () => {
      const cases: Array<[number, number]> = [
        [A - 2, 0],
        [A - 1, RP],
        [A, RP],
        [A + 1, RP],
        [A + 10 * 365 * 86400, RP],
        [0xffffffff, RP],
      ]
      for (const [lock, expected] of cases) {
        assert.strictEqual(
          getSighashForkValueForTransaction(locked(lock, NONFINAL), 0, A),
          expected,
          `nLockTime A${lock - A >= 0 ? '+' : ''}${lock - A}`,
        )
      }
    })

    it('all inputs final -> next block value (nLockTime is ignored)', () => {
      const tx = locked(A + 1000, [0xffffffff, 0xffffffff])
      assert.strictEqual(getSighashForkValueForTransaction(tx, 0, A), 0)
      assert.strictEqual(
        getSighashForkValueForTransaction(locked(A, []), 0, A),
        0,
      )
    })

    it('height lock -> next block value', () => {
      for (const height of [1, 1000000, 499999999]) {
        assert.strictEqual(
          getSighashForkValueForTransaction(locked(height, [0]), 0, A),
          0,
        )
      }
      // the threshold itself is a timestamp
      assert.strictEqual(
        getSighashForkValueForTransaction(locked(500000000, [0]), 0, 500000001),
        RP,
      )
      assert.strictEqual(
        getSighashForkValueForTransaction(locked(0, [0]), 0, A),
        0,
      )
    })

    it('already active -> 0xffdead whatever the lock', () => {
      for (const tx of [
        locked(0, [0xffffffff]),
        locked(1000, [0]),
        locked(A - 1000000, [0]),
        locked(A + 1000, [0xffffffff]),
      ]) {
        assert.strictEqual(getSighashForkValueForTransaction(tx, RP, A), RP)
      }
    })

    it('refuses unknown fork values and a missing activation time', () => {
      assert.throws(() =>
        getSighashForkValueForTransaction(locked(A, [0]), 0xdead, A),
      )
      assert.throws(() =>
        getSighashForkValueForTransaction(
          locked(A, [0]),
          0,
          undefined as unknown as number,
        ),
      )
    })

    it('time lock read from a Transaction object', () => {
      const { tx } = p2pkhTx()
      tx.lockUntilDate(A - 1)
      assert.strictEqual(tx.inputs[0].sequenceNumber, 0xfffffffe)
      assert.strictEqual(getSighashForkValueForTransaction(tx, 0, A), RP)
      tx.nLockTime = A - 2
      assert.strictEqual(getSighashForkValueForTransaction(tx, 0, A), 0)
      // the lock is compared with the activation time given
      assert.strictEqual(getSighashForkValueForTransaction(tx, 0, A - 1), RP)
    })
  })

  describe('Transaction.setSighashForkValueForTip', () => {
    it('before activation: signs with 0, verifies without the replay flag only', () => {
      const { tx, key } = p2pkhTx(2)
      const ret = tx.setSighashForkValueForTip({
        network: 'main',
        tipMedianTimePast: A - 1,
      })
      assert.strictEqual(ret, tx)
      assert.strictEqual(tx.sighashForkValue, 0)
      tx.sign(key)
      assertSignedWith(tx, 0, 'pre-activation')
    })

    it('after activation: signs with 0xffdead, verifies with the replay flag only', () => {
      for (const method of ['ecdsa', 'schnorr'] as const) {
        const { tx, key } = p2pkhTx(2)
        tx.setSighashForkValueForTip({
          network: 'main',
          tipMedianTimePast: A,
        }).sign(key, null, method)
        assert.strictEqual(tx.sighashForkValue, RP)
        assertSignedWith(tx, RP, `post-activation ${method}`)
      }
    })

    it('Taproot key path follows the tip too', () => {
      const key = randKey(r)
      const tx = new Transaction()
        .from({
          txId: randBytes(r, 32).toString('hex'),
          outputIndex: 0,
          satoshis: 70000,
          script: buildKeyPathTaproot(key.publicKey),
          internalPubKey: key.publicKey,
        })
        .to(randKey(r).toAddress(), 60000)
      tx.setSighashForkValueForTip({
        network: 'test',
        tipMedianTimePast: T,
      }).sign(key, null, 'schnorr')
      assertSignedWith(tx, RP, 'taproot testnet')
    })

    it('time-locked transaction signed before activation with 0xffdead', () => {
      const { tx, key } = p2pkhTx()
      tx.lockUntilDate(A)
      tx.setSighashForkValueForTip({
        network: 'main',
        tipMedianTimePast: A - 30 * 86400,
      })
      tx.sign(key)
      assert.strictEqual(tx.sighashForkValue, RP)
      assertSignedWith(tx, RP, 'locked until A')

      const h = p2pkhTx()
      h.tx.lockUntilBlockHeight(10_000_000)
      h.tx.setSighashForkValueForTip({
        network: 'main',
        tipMedianTimePast: A - 30 * 86400,
      })
      h.tx.sign(h.key)
      assertSignedWith(h.tx, 0, 'height lock')
    })

    it('re-signing after a refusal replaces the signatures (README pattern)', () => {
      for (const method of ['ecdsa', 'schnorr'] as const) {
        const { tx, key } = p2pkhTx(2)
        tx.setSighashForkValueForTip({
          network: 'main',
          tipMedianTimePast: A - 1,
        })
        tx.sign(key, null, method)
        assertSignedWith(tx, 0, `first signature ${method}`)
        // broadcast refused: the tip crossed the activation meanwhile
        assert.ok(
          isReplayProtectionRefusal(
            new Error(
              'mandatory-script-verify-flag-failed (Signature must be zero)',
            ),
          ),
        )
        tx.setSighashForkValueForTip({ network: 'main', tipMedianTimePast: A })
        tx.sign(key, null, method)
        assertSignedWith(tx, RP, `re-signed ${method}`)
      }
    })

    it('an untouched transaction still signs with fork value 0', () => {
      process.env[ENV] = '1' // even with an activation time in the past
      const { tx, key } = p2pkhTx()
      tx.sign(key)
      assert.strictEqual(tx.sighashForkValue, 0)
      assertSignedWith(tx, 0, 'default')
    })
  })

  describe(`${REPLAY_PROTECTION_ACTIVATION_TIME_ENV} environment variable`, () => {
    it('overrides the built-in activation time on every network', () => {
      process.env[ENV] = '1000'
      for (const n of ['main', 'test', 'regtest', Networks.livenet]) {
        assert.strictEqual(getReplayProtectionActivationTime(n), 1000)
      }
      assert.strictEqual(getReplayProtectionActivationTime(), 1000)
      assert.strictEqual(
        getNextBlockSighashForkValue({
          network: 'regtest',
          tipMedianTimePast: 1000,
        }),
        RP,
      )
      assert.strictEqual(
        getNextBlockSighashForkValue({
          network: 'regtest',
          tipMedianTimePast: 999,
        }),
        0,
      )
      // unknown network names still throw
      assert.throws(() => getReplayProtectionActivationTime('nonsense'))
    })

    it('precedence: explicit > env > built-in', () => {
      process.env[ENV] = '1000'
      // explicit argument beats env
      assert.strictEqual(
        getReplayProtectionActivationTime('regtest', 2000),
        2000,
      )
      assert.strictEqual(
        getNextBlockSighashForkValue({
          network: 'regtest',
          tipMedianTimePast: 1500,
          activationTime: 2000,
        }),
        0,
      )
      // env beats built-in
      assert.strictEqual(
        getNextBlockSighashForkValue({
          network: 'main',
          tipMedianTimePast: 1500,
        }),
        RP,
      )
      // built-in once unset
      delete process.env[ENV]
      assert.strictEqual(
        getNextBlockSighashForkValue({
          network: 'main',
          tipMedianTimePast: 1500,
        }),
        0,
      )
      assert.strictEqual(getReplayProtectionActivationTime('main'), A)
    })

    it('empty is ignored, garbage throws', () => {
      process.env[ENV] = ''
      assert.strictEqual(getReplayProtectionActivationTime('main'), A)
      process.env[ENV] = '  '
      assert.strictEqual(getReplayProtectionActivationTime('main'), A)
      for (const bad of [
        'abc',
        '1.5',
        '-1',
        '1e9',
        '0x10',
        '99999999999999999999',
      ]) {
        process.env[ENV] = bad
        assert.throws(
          () => getReplayProtectionActivationTime('main'),
          new RegExp(ENV),
        )
        // an explicit value does not read the environment at all
        assert.strictEqual(getReplayProtectionActivationTime('main', 7), 7)
      }
    })
  })
})

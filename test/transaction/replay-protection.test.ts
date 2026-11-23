/**
 * Replay protection and the Lotus chain fork id
 *
 * Covers:
 * - the fork-id policy (auto at the 2nd Kings activation, explicit override)
 * - the fork value committed by every sighash algorithm
 * - signing and verification separation across the activation boundary
 * - golden signatures produced by lotusd on regtest
 * - taproot key-path and script-path signing
 *
 * Reference: lotusd/src/script/sighashtype.h (CHAIN_FORK_ID)
 * Reference: lotusd/src/script/interpreter.cpp (SignatureHash)
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'buffer/'
import {
  Address,
  BN,
  CHAIN_FORK_ID,
  Input,
  MuSig2TaprootInput,
  Networks,
  Opcode,
  Output,
  PrivateKey,
  REPLAY_PROTECTION_ACTIVATION_MARGIN,
  REPLAY_PROTECTION_ACTIVATION_TIME,
  Signature,
  Script,
  TESTNET_REPLAY_PROTECTION_ACTIVATION_TIME,
  TaprootInput,
  Transaction,
  buildKeyPathTaproot,
  buildScriptPathTaproot,
  calculateTapLeaf,
  chainForkIdAt,
  createControlBlock,
  resolveForkId,
} from '../../lib/bitcore/index.js'
import {
  DEFAULT_SIGN_FLAGS,
  sighash,
  signFlagsForForkId,
} from '../../lib/bitcore/transaction/sighash.js'
import { ScriptFlags } from '../../lib/bitcore/script/interpreter/types.js'

const REPLAY_FLAGS = DEFAULT_SIGN_FLAGS | ScriptFlags.ENABLE_REPLAY_PROTECTION

// ─── Fixtures ────────────────────────────────────────────────────

const KEY = new PrivateKey(Buffer.from('11'.repeat(32), 'hex'), 'regtest')
const PREV_SCRIPT = Script.fromAddress(
  Address.fromPublicKey(KEY.publicKey, Networks.regtest),
)
const PREV_SATOSHIS = 260_000_000

/**
 * A transaction spending a P2PKH output, used for sighash and signing tests.
 */
function buildTx(): Transaction {
  const tx = new Transaction()
  tx.addInput(
    new Input({
      prevTxId: Buffer.alloc(32, 1),
      outputIndex: 0,
      sequenceNumber: 0xffffffff,
      script: new Script(),
      output: new Output({
        script: PREV_SCRIPT,
        satoshis: PREV_SATOSHIS,
      }),
    }),
  )
  tx.addOutput(
    new Output({
      script: Script.buildPublicKeyHashOut(KEY.toAddress()),
      satoshis: PREV_SATOSHIS - 1000,
    }),
  )
  return tx
}

/**
 * Golden transaction signed by lotusd v12.0.2 (branch
 * maff1989/dev-328-add-the-lotus-chain-fork-id-to-the-sighash, commit
 * 144af58e1) on regtest, spending a 260 XPI P2PKH coinbase output.
 *
 * The signatures were produced with `signrawtransactionwithkey` on a node
 * with replay protection inactive (fork id 0) and active (fork id 0x4c4f54).
 * Both post-activation forms were accepted by `testmempoolaccept`; the
 * fork-id-0 forms are rejected once activation is live.
 */
const GOLDEN = {
  unsignedTx:
    '02000000013c5f18e34beec55ccb9777ae2949035b6b1bea7aa4d9deaad185814d91ff44810100000000ffffffff0118457f0f000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000',
  prevScript: '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac',
  satoshis: 260_000_000,
  wif: 'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA',
  signatures: {
    fork0: {
      bip143:
        '3044022036a407d4d970b541f28947f5809c479341e67a667efb8ba809aa7a885794c0a002205d41de1464cbf4f45639af02a19e39cff69fc4d0f1c8aee2a3c545139c0fb59c41',
      lotus:
        '304402207ad77c13c4e27dd69ff35eae65a1f48a21437f1ee707cde755e76004b42b02570220552a5c5fe656064a36945443361c0ebe5101dd21b9ff9f6400d2a1b9d41628ee61',
    },
    chain: {
      bip143:
        '30440220069b5aecd1dd495aa2773beff6a3570960839235e223d54b2454b718f4ffc25f0220750e31df391dc72da322392b6a3c65b8e1b3d9b2ec59c5520c8c9fdd12156ac141',
      lotus:
        '3044022010d5af5506238b1050f954c468cd53e3ed56a35816ba7131fb4c02d14e3b626a02201c7ab5087021e0acd40cfc5081b6f22e7dc27476661f99581c0788ab02627eb461',
    },
  },
} as const

function goldenTx(forkId: 0 | typeof CHAIN_FORK_ID): Transaction {
  const tx = Transaction.fromString(GOLDEN.unsignedTx)
  tx.inputs[0].output = new Output({
    script: Script.fromString(GOLDEN.prevScript),
    satoshis: GOLDEN.satoshis,
  })
  tx.forkId = forkId
  return tx
}

// ─── Tests ───────────────────────────────────────────────────────

describe('chain fork id', () => {
  it('should expose the Lotus chain id and activation point', () => {
    assert.strictEqual(CHAIN_FORK_ID, 0x4c4f54)
    assert.strictEqual(REPLAY_PROTECTION_ACTIVATION_TIME, 1797886200)
    assert.strictEqual(
      TESTNET_REPLAY_PROTECTION_ACTIVATION_TIME,
      REPLAY_PROTECTION_ACTIVATION_TIME - 21 * 24 * 60 * 60,
    )
    assert.strictEqual(REPLAY_PROTECTION_ACTIVATION_MARGIN, 30 * 60)
  })

  it('should switch to the chain id only after the safety margin', () => {
    const cutoff =
      REPLAY_PROTECTION_ACTIVATION_TIME + REPLAY_PROTECTION_ACTIVATION_MARGIN

    assert.strictEqual(chainForkIdAt(cutoff - 1), 0)
    assert.strictEqual(chainForkIdAt(REPLAY_PROTECTION_ACTIVATION_TIME), 0)
    assert.strictEqual(chainForkIdAt(cutoff), CHAIN_FORK_ID)
  })

  it('should honour a network-specific activation time', () => {
    const cutoff =
      TESTNET_REPLAY_PROTECTION_ACTIVATION_TIME +
      REPLAY_PROTECTION_ACTIVATION_MARGIN

    assert.strictEqual(
      chainForkIdAt(cutoff - 1, TESTNET_REPLAY_PROTECTION_ACTIVATION_TIME),
      0,
    )
    assert.strictEqual(
      chainForkIdAt(cutoff, TESTNET_REPLAY_PROTECTION_ACTIVATION_TIME),
      CHAIN_FORK_ID,
    )
  })

  it('should resolve the auto policy from the clock', () => {
    const cutoff =
      REPLAY_PROTECTION_ACTIVATION_TIME + REPLAY_PROTECTION_ACTIVATION_MARGIN

    assert.strictEqual(resolveForkId(undefined, cutoff - 1), 0)
    assert.strictEqual(resolveForkId('auto', cutoff), CHAIN_FORK_ID)
  })

  it('should accept only the fork ids this chain verifies', () => {
    assert.strictEqual(resolveForkId(0), 0)
    assert.strictEqual(resolveForkId(CHAIN_FORK_ID), CHAIN_FORK_ID)

    // 0xffdead is the stock ABC transform, not a chain identity.
    assert.throws(
      () => resolveForkId(0xffdead as unknown as 0),
      /Invalid Lotus fork id/,
    )
  })

  it('should map a fork id to script flags', () => {
    assert.strictEqual(signFlagsForForkId(0), DEFAULT_SIGN_FLAGS)
    assert.strictEqual(signFlagsForForkId(CHAIN_FORK_ID), REPLAY_FLAGS)
    assert.throws(
      () => signFlagsForForkId(0xffdead as unknown as 0),
      /Invalid Lotus fork id/,
    )
  })
})

describe('sighash fork value', () => {
  const algorithms: Array<[string, number]> = [
    ['legacy', Signature.SIGHASH_ALL],
    ['bip143', Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID],
    ['lotus', Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS],
  ]

  for (const [label, sigtype] of algorithms) {
    it(`should commit exactly CHAIN_FORK_ID for ${label} signatures`, () => {
      const tx = buildTx()
      const committed = sighash(
        tx,
        sigtype,
        0,
        PREV_SCRIPT,
        new BN(PREV_SATOSHIS),
        REPLAY_FLAGS,
      )

      // Setting the fork value directly must produce the same preimage.
      const explicit = sighash(
        tx,
        (CHAIN_FORK_ID << 8) | sigtype,
        0,
        PREV_SCRIPT,
        new BN(PREV_SATOSHIS),
        DEFAULT_SIGN_FLAGS,
      )
      assert.ok(committed.equals(explicit))

      // The pre-activation value commits a different message.
      const preActivation = sighash(
        tx,
        sigtype,
        0,
        PREV_SCRIPT,
        new BN(PREV_SATOSHIS),
        DEFAULT_SIGN_FLAGS,
      )
      assert.ok(!committed.equals(preActivation))

      // The stock 0xffdead transform is gone.
      const oldTransform = sighash(
        tx,
        (0xffdead << 8) | sigtype,
        0,
        PREV_SCRIPT,
        new BN(PREV_SATOSHIS),
        DEFAULT_SIGN_FLAGS,
      )
      assert.ok(!committed.equals(oldTransform))
    })
  }
})

describe('golden lotusd signatures', () => {
  const publicKey = new PrivateKey(GOLDEN.wif, 'regtest').publicKey
  const prevScript = Script.fromString(GOLDEN.prevScript)

  const policyFor = (forkId: number): 'fork0' | 'chain' =>
    forkId === 0 ? 'fork0' : 'chain'

  for (const forkId of [0, CHAIN_FORK_ID] as const) {
    it(`should verify lotusd signatures under fork id ${forkId}`, () => {
      const tx = goldenTx(forkId)
      const sigs = GOLDEN.signatures[policyFor(forkId)]

      for (const [label, hex] of Object.entries(sigs)) {
        const sig = Signature.fromTxFormat(Buffer.from(hex, 'hex'))
        assert.strictEqual(
          tx.verifySignature(
            sig,
            publicKey,
            0,
            prevScript,
            new BN(GOLDEN.satoshis),
            undefined,
            'ecdsa',
          ),
          true,
          `${label} signature should verify under fork id ${forkId}`,
        )
      }
    })
  }

  it('should reject a signature made for the other side of the split', () => {
    const tx = goldenTx(CHAIN_FORK_ID)
    const fork0Sig = Signature.fromTxFormat(
      Buffer.from(GOLDEN.signatures.fork0.bip143, 'hex'),
    )

    assert.strictEqual(
      tx.verifySignature(
        fork0Sig,
        publicKey,
        0,
        prevScript,
        new BN(GOLDEN.satoshis),
        undefined,
        'ecdsa',
      ),
      false,
    )
  })
})

describe('transaction signing policy', () => {
  it('should select the fork id from the transaction policy', () => {
    const tx = buildTx()
    const cutoff =
      REPLAY_PROTECTION_ACTIVATION_TIME + REPLAY_PROTECTION_ACTIVATION_MARGIN

    tx.forkId = 'auto'
    assert.strictEqual(tx.getForkId(cutoff - 1), 0)
    assert.strictEqual(tx.getForkId(cutoff), CHAIN_FORK_ID)

    tx.forkId = 0
    assert.strictEqual(tx.getForkId(cutoff), 0)

    tx.forkId = CHAIN_FORK_ID
    assert.strictEqual(tx.getForkId(0), CHAIN_FORK_ID)
  })

  it('should reject a fork id the chain cannot verify', () => {
    const tx = buildTx()
    tx.forkId = 0xffdead as unknown as 0
    assert.throws(() => tx.getForkId(), /Invalid Lotus fork id/)
  })

  it('should produce signatures separable by fork id', () => {
    const pre = buildTx()
    pre.forkId = 0
    pre.sign(KEY, Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

    const post = buildTx()
    post.forkId = CHAIN_FORK_ID
    post.sign(KEY, Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

    const preSig = pre.inputs[0].script!.chunks[0].buf!.toString('hex')
    const postSig = post.inputs[0].script!.chunks[0].buf!.toString('hex')
    assert.notStrictEqual(preSig, postSig)

    assert.strictEqual(pre.verify(), true)
    assert.strictEqual(post.verify(), true)

    // A post-activation signature is invalid in a pre-activation context.
    const cross = buildTx()
    cross.forkId = 0
    cross.inputs[0].setScript(post.inputs[0].script!)
    assert.notStrictEqual(cross.verify(), true)
  })

  it('should sign LOTUS inputs with the executed-script context', () => {
    const tx = buildTx()
    tx.forkId = CHAIN_FORK_ID
    tx.sign(KEY, Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS, 'ecdsa')

    assert.strictEqual(tx.verify(), true)

    // Without the executed-script context (taproot key-path form) the
    // signature must not verify.
    const noExecdata = sighash(
      tx,
      Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      0,
      PREV_SCRIPT,
      new BN(PREV_SATOSHIS),
      REPLAY_FLAGS,
      null,
    )
    const withExecdata = sighash(
      tx,
      Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      0,
      PREV_SCRIPT,
      new BN(PREV_SATOSHIS),
      REPLAY_FLAGS,
    )
    assert.ok(!noExecdata.equals(withExecdata))
  })
})

describe('taproot fork id', () => {
  const owner = new PrivateKey(Buffer.from('22'.repeat(32), 'hex'), 'regtest')

  function taprootTx(script: Script, input: TaprootInput): Transaction {
    const tx = new Transaction()
    tx.addInput(input)
    tx.addOutput(
      new Output({
        script: Script.buildPublicKeyHashOut(owner.toAddress()),
        satoshis: 99_000,
      }),
    )
    return tx
  }

  function keyPathInput(script: Script): TaprootInput {
    return new TaprootInput({
      prevTxId: Buffer.alloc(32, 9),
      outputIndex: 0,
      script: new Script(),
      output: new Output({ script, satoshis: 100_000 }),
      internalPubKey: owner.publicKey,
    })
  }

  it('should sign key-path spends under both fork ids', () => {
    const script = buildKeyPathTaproot(owner.publicKey)

    const pre = taprootTx(script, keyPathInput(script))
    pre.forkId = 0
    pre.sign(owner, Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS, 'schnorr')

    const post = taprootTx(script, keyPathInput(script))
    post.forkId = CHAIN_FORK_ID
    post.sign(owner, Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS, 'schnorr')

    assert.strictEqual(pre.verify(), true)
    assert.strictEqual(post.verify(), true)

    const preSig = pre.inputs[0].script!.chunks[0].buf!.toString('hex')
    const postSig = post.inputs[0].script!.chunks[0].buf!.toString('hex')
    assert.notStrictEqual(preSig, postSig)
  })

  it('should commit the tapleaf hash for script-path spends', () => {
    const leaf = new Script()
      .add(owner.publicKey.toBuffer())
      .add(Opcode.OP_CHECKSIG)
    const tree = { script: leaf }
    const built = buildScriptPathTaproot(owner.publicKey, tree)
    const controlBlock = createControlBlock(owner.publicKey, 0, tree)

    const tx = taprootTx(
      built.script,
      new TaprootInput({
        prevTxId: Buffer.alloc(32, 10),
        outputIndex: 0,
        script: new Script(),
        output: new Output({ script: built.script, satoshis: 100_000 }),
        internalPubKey: owner.publicKey,
        merkleRoot: built.merkleRoot,
        controlBlock,
        tapScript: leaf,
      }),
    )
    tx.forkId = CHAIN_FORK_ID
    tx.sign(owner, Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS, 'schnorr')

    assert.strictEqual(tx.verify(), true)

    const tapleafHash = calculateTapLeaf(leaf)
    const withTapleaf = sighash(
      tx,
      Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      0,
      leaf,
      new BN(100_000),
      REPLAY_FLAGS,
      { executedScriptHash: tapleafHash },
    )
    const withScriptPubKey = sighash(
      tx,
      Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      0,
      leaf,
      new BN(100_000),
      REPLAY_FLAGS,
    )
    assert.ok(!withTapleaf.equals(withScriptPubKey))
  })

  it('should apply the fork id to the MuSig2 key-path sighash', () => {
    const script = buildKeyPathTaproot(owner.publicKey)
    const tx = taprootTx(
      script,
      new MuSig2TaprootInput({
        prevTxId: Buffer.alloc(32, 11),
        outputIndex: 0,
        script: new Script(),
        output: new Output({ script, satoshis: 100_000 }),
        internalPubKey: owner.publicKey,
      }),
    )

    tx.forkId = 0
    const pre = tx.getMuSig2Sighash(0)
    tx.forkId = CHAIN_FORK_ID
    const post = tx.getMuSig2Sighash(0)

    assert.ok(!pre.equals(post))
  })
})

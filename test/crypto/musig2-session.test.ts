/**
 * MuSig2 Session Manager Tests
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { PrivateKey } from '../../lib/bitcore/privatekey.js'
import {
  MuSigSessionManager,
  MuSigSessionPhase,
} from '../../lib/bitcore/musig2/session.js'
import { Schnorr } from '../../lib/bitcore/crypto/schnorr.js'
import { BN } from '../../lib/bitcore/crypto/bn.js'

describe('MuSig2 Session Manager', () => {
  describe('Session Creation', () => {
    it('should create a new session', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test message', 'utf8')

      const manager = new MuSigSessionManager()
      const session = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )

      assert.ok(session.sessionId)
      assert.strictEqual(session.signers.length, 2)
      assert.strictEqual(session.myIndex, 0)
      assert.strictEqual(session.phase, MuSigSessionPhase.INIT)
      assert.ok(session.keyAggContext)
      assert.ok(session.keyAggContext.aggregatedPubKey)
    })

    it('should find correct signer index', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const carol = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey, carol.publicKey],
        bob,
        message,
      )

      assert.strictEqual(bobSession.myIndex, 1)
    })

    it('should reject empty signers array', () => {
      const alice = new PrivateKey()
      const message = Buffer.from('test', 'utf8')
      const manager = new MuSigSessionManager()

      assert.throws(() => {
        manager.createSession([], alice, message)
      }, /Cannot create MuSig2 session with zero signers/)
    })

    it('should reject if private key not in signers', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const charlie = new PrivateKey()
      const message = Buffer.from('test', 'utf8')
      const manager = new MuSigSessionManager()

      assert.throws(() => {
        manager.createSession(
          [alice.publicKey, bob.publicKey],
          charlie,
          message,
        )
      }, /Private key does not correspond to any signer/)
    })

    it('should include optional metadata', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')
      const metadata = { txid: 'abc123', inputIndex: 0 }

      const manager = new MuSigSessionManager()
      const session = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
        metadata,
      )

      assert.deepStrictEqual(session.metadata, metadata)
    })
  })

  describe('Nonce Generation', () => {
    it('should generate nonces', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const session = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )

      const nonces = manager.generateNonces(session, alice)

      assert.ok(nonces)
      assert.strictEqual(nonces.length, 2)
      assert.ok(session.mySecretNonce)
      assert.ok(session.myPublicNonce)
      assert.strictEqual(session.phase, MuSigSessionPhase.NONCE_EXCHANGE)
    })

    it('should reject nonce generation if not in INIT phase', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const session = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )

      manager.generateNonces(session, alice)

      assert.throws(() => {
        manager.generateNonces(session, alice)
      }, /Cannot generate nonces in phase/)
    })

    it('should prevent nonce reuse', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const session = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )

      manager.generateNonces(session, alice)
      session.phase = MuSigSessionPhase.INIT // Try to trick it

      assert.throws(() => {
        manager.generateNonces(session, alice)
      }, /Nonces already generated/)
    })
  })

  describe('Nonce Exchange', () => {
    it('should receive nonces from other signers', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )

      const aliceNonces = manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)

      // Alice receives Bob's nonces
      manager.receiveNonces(aliceSession, 1, bobNonces)

      assert.ok(aliceSession.receivedPublicNonces.has(1))
      assert.strictEqual(aliceSession.receivedPublicNonces.size, 1)
    })

    it('should auto-aggregate when all nonces received', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )

      const aliceNonces = manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)

      manager.receiveNonces(aliceSession, 1, bobNonces)

      assert.ok(aliceSession.aggregatedNonce)
      assert.ok(aliceSession.aggregatedNonce.R1)
      assert.ok(aliceSession.aggregatedNonce.R2)
    })

    it('should reject nonce from self', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )

      const aliceNonces = manager.generateNonces(aliceSession, alice)

      assert.throws(() => {
        manager.receiveNonces(aliceSession, 0, aliceNonces)
      }, /Cannot receive nonce from self/)
    })

    it('should reject duplicate nonces', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )

      manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)

      manager.receiveNonces(aliceSession, 1, bobNonces)

      assert.throws(() => {
        manager.receiveNonces(aliceSession, 1, bobNonces)
      }, /Already received nonce/)
    })

    it('should check hasAllNonces correctly', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const carol = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey, carol.publicKey],
        alice,
        message,
      )

      assert.ok(!manager.hasAllNonces(aliceSession))

      manager.generateNonces(aliceSession, alice)
      assert.ok(!manager.hasAllNonces(aliceSession))

      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey, carol.publicKey],
        bob,
        message,
      )
      const bobNonces = manager.generateNonces(bobSession, bob)
      manager.receiveNonces(aliceSession, 1, bobNonces)

      assert.ok(!manager.hasAllNonces(aliceSession))

      const carolSession = manager.createSession(
        [alice.publicKey, bob.publicKey, carol.publicKey],
        carol,
        message,
      )
      const carolNonces = manager.generateNonces(carolSession, carol)
      manager.receiveNonces(aliceSession, 2, carolNonces)

      assert.ok(manager.hasAllNonces(aliceSession))
    })
  })

  describe('Partial Signature Creation', () => {
    it('should create partial signature', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )

      const aliceNonces = manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)

      manager.receiveNonces(aliceSession, 1, bobNonces)

      const alicePartialSig = manager.createPartialSignature(
        aliceSession,
        alice,
      )

      assert.ok(alicePartialSig)
      assert.ok(!alicePartialSig.isZero())
      assert.strictEqual(
        aliceSession.phase,
        MuSigSessionPhase.PARTIAL_SIG_EXCHANGE,
      )
    })

    it('should clear secret nonce after signing', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )

      manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)
      manager.receiveNonces(aliceSession, 1, bobNonces)

      assert.ok(aliceSession.mySecretNonce)
      manager.createPartialSignature(aliceSession, alice)
      assert.ok(!aliceSession.mySecretNonce)
    })

    it('should reject if nonces not aggregated', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )

      manager.generateNonces(aliceSession, alice)

      assert.throws(() => {
        manager.createPartialSignature(aliceSession, alice)
      }, /nonces not yet aggregated/)
    })
  })

  describe('Partial Signature Exchange', () => {
    it('should receive and verify partial signatures', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )

      const aliceNonces = manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)

      manager.receiveNonces(aliceSession, 1, bobNonces)
      manager.receiveNonces(bobSession, 0, aliceNonces)

      manager.createPartialSignature(aliceSession, alice)
      const bobPartialSig = manager.createPartialSignature(bobSession, bob)

      manager.receivePartialSignature(aliceSession, 1, bobPartialSig)

      assert.ok(aliceSession.receivedPartialSigs.has(1))
    })

    it('should reject invalid partial signature', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )

      const aliceNonces = manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)

      manager.receiveNonces(aliceSession, 1, bobNonces)
      manager.receiveNonces(bobSession, 0, aliceNonces)

      manager.createPartialSignature(aliceSession, alice)
      const bobPartialSig = manager.createPartialSignature(bobSession, bob)

      // Tamper with signature
      const tamperedSig = bobPartialSig.add(new BN(1))

      assert.throws(() => {
        manager.receivePartialSignature(aliceSession, 1, tamperedSig)
      }, /Invalid partial signature/)

      // Session should be aborted
      assert.strictEqual(aliceSession.phase, MuSigSessionPhase.ABORTED)
    })

    it('should auto-finalize when all partial sigs received', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )

      const aliceNonces = manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)

      manager.receiveNonces(aliceSession, 1, bobNonces)
      manager.receiveNonces(bobSession, 0, aliceNonces)

      manager.createPartialSignature(aliceSession, alice)
      const bobPartialSig = manager.createPartialSignature(bobSession, bob)

      manager.receivePartialSignature(aliceSession, 1, bobPartialSig)

      assert.strictEqual(aliceSession.phase, MuSigSessionPhase.COMPLETE)
      assert.ok(aliceSession.finalSignature)
    })
  })

  describe('Complete Flow', () => {
    it('should complete 2-of-2 signing session', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.alloc(32).fill(0x42)

      const manager = new MuSigSessionManager()

      // Create sessions
      const aliceSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )
      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )

      // Round 1: Nonce exchange
      const aliceNonces = manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)

      manager.receiveNonces(aliceSession, 1, bobNonces)
      manager.receiveNonces(bobSession, 0, aliceNonces)

      // Round 2: Partial signatures
      const alicePartialSig = manager.createPartialSignature(
        aliceSession,
        alice,
      )
      const bobPartialSig = manager.createPartialSignature(bobSession, bob)

      manager.receivePartialSignature(aliceSession, 1, bobPartialSig)
      manager.receivePartialSignature(bobSession, 0, alicePartialSig)

      // Get final signatures
      const aliceFinalSig = manager.getFinalSignature(aliceSession)
      const bobFinalSig = manager.getFinalSignature(bobSession)

      // Signatures should be identical
      assert.strictEqual(aliceFinalSig.toString(), bobFinalSig.toString())

      // Verify against aggregated key
      const verified = Schnorr.verify(
        message,
        aliceFinalSig,
        aliceSession.keyAggContext.aggregatedPubKey,
        'big',
      )

      assert.ok(verified, 'Final signature should verify')
    })

    it('should complete 3-of-3 signing session', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const carol = new PrivateKey()
      const message = Buffer.alloc(32).fill(0x43)

      const manager = new MuSigSessionManager()

      // Create sessions
      const signers = [alice.publicKey, bob.publicKey, carol.publicKey]
      const aliceSession = manager.createSession(signers, alice, message)
      const bobSession = manager.createSession(signers, bob, message)
      const carolSession = manager.createSession(signers, carol, message)

      // Round 1: Nonce exchange
      const aliceNonces = manager.generateNonces(aliceSession, alice)
      const bobNonces = manager.generateNonces(bobSession, bob)
      const carolNonces = manager.generateNonces(carolSession, carol)

      // Everyone exchanges nonces
      manager.receiveNonces(aliceSession, 1, bobNonces)
      manager.receiveNonces(aliceSession, 2, carolNonces)
      manager.receiveNonces(bobSession, 0, aliceNonces)
      manager.receiveNonces(bobSession, 2, carolNonces)
      manager.receiveNonces(carolSession, 0, aliceNonces)
      manager.receiveNonces(carolSession, 1, bobNonces)

      // Round 2: Partial signatures
      const alicePartialSig = manager.createPartialSignature(
        aliceSession,
        alice,
      )
      const bobPartialSig = manager.createPartialSignature(bobSession, bob)
      const carolPartialSig = manager.createPartialSignature(
        carolSession,
        carol,
      )

      // Everyone exchanges partial sigs
      manager.receivePartialSignature(aliceSession, 1, bobPartialSig)
      manager.receivePartialSignature(aliceSession, 2, carolPartialSig)
      manager.receivePartialSignature(bobSession, 0, alicePartialSig)
      manager.receivePartialSignature(bobSession, 2, carolPartialSig)
      manager.receivePartialSignature(carolSession, 0, alicePartialSig)
      manager.receivePartialSignature(carolSession, 1, bobPartialSig)

      // All should have same final signature
      const aliceFinalSig = manager.getFinalSignature(aliceSession)
      const bobFinalSig = manager.getFinalSignature(bobSession)
      const carolFinalSig = manager.getFinalSignature(carolSession)

      assert.strictEqual(aliceFinalSig.toString(), bobFinalSig.toString())
      assert.strictEqual(bobFinalSig.toString(), carolFinalSig.toString())

      // Verify
      const verified = Schnorr.verify(
        message,
        aliceFinalSig,
        aliceSession.keyAggContext.aggregatedPubKey,
        'big',
      )

      assert.ok(verified, '3-of-3 signature should verify')
    })
  })

  describe('Session Status', () => {
    it('should report correct session status', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const session = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )

      let status = manager.getSessionStatus(session)
      assert.strictEqual(status.phase, MuSigSessionPhase.INIT)
      assert.strictEqual(status.noncesCollected, 0)
      assert.strictEqual(status.noncesTotal, 2)

      manager.generateNonces(session, alice)
      status = manager.getSessionStatus(session)
      assert.strictEqual(status.noncesCollected, 1)
      assert.strictEqual(status.phase, MuSigSessionPhase.NONCE_EXCHANGE)

      const bobSession = manager.createSession(
        [alice.publicKey, bob.publicKey],
        bob,
        message,
      )
      const bobNonces = manager.generateNonces(bobSession, bob)
      manager.receiveNonces(session, 1, bobNonces)

      status = manager.getSessionStatus(session)
      assert.strictEqual(status.noncesCollected, 2)

      manager.createPartialSignature(session, alice)
      status = manager.getSessionStatus(session)
      assert.strictEqual(status.partialSigsCollected, 1)
      assert.strictEqual(status.partialSigsTotal, 2)
    })
  })

  describe('Error Handling', () => {
    it('should handle abort correctly', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const session = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )

      manager.abortSession(session, 'Test abort')

      assert.strictEqual(session.phase, MuSigSessionPhase.ABORTED)
      assert.strictEqual(session.abortReason, 'Test abort')

      const status = manager.getSessionStatus(session)
      assert.ok(status.isAborted)
      assert.strictEqual(status.abortReason, 'Test abort')
    })

    it('should prevent operations on aborted session', () => {
      const alice = new PrivateKey()
      const bob = new PrivateKey()
      const message = Buffer.from('test', 'utf8')

      const manager = new MuSigSessionManager()
      const session = manager.createSession(
        [alice.publicKey, bob.publicKey],
        alice,
        message,
      )

      manager.abortSession(session, 'Test abort')

      assert.throws(() => {
        manager.generateNonces(session, alice)
      }, /Cannot generate nonces in phase/)
    })
  })
})

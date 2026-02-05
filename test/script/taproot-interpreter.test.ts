/**
 * Taproot Interpreter Tests
 *
 * Tests for OP_SCRIPTTYPE dispatch, verifyTaprootSpend key-path and
 * script-path verification within the interpreter.
 *
 * These tests exercise the structural validation logic (control block
 * sizes, leaf versions, annex rejection, encoding checks, P2TR format)
 * and script-path execution via evalScript.
 *
 * Reference: lotusd/src/script/interpreter.cpp VerifyScriptType/VerifyTaprootSpend
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'buffer/'
import {
  verifyScript,
  ScriptError,
  ScriptFlags,
  NULL_SIGNATURE_CHECKER,
  type SignatureChecker,
  type ScriptExecutionData,
} from '../../lib/bitcore/script/interpreter/index'
import { Opcode } from '../../lib/bitcore/opcode'
import {
  TAPROOT_INTRO_SIZE,
  TAPROOT_SIZE_WITHOUT_STATE,
  TAPROOT_SIZE_WITH_STATE,
  TAPROOT_LEAF_TAPSCRIPT,
  TAPROOT_CONTROL_BASE_SIZE,
  TAPROOT_CONTROL_NODE_SIZE,
  TAPROOT_ANNEX_TAG,
  calculateTapLeaf,
  calculateTapTweak,
  taggedHash,
  tweakPublicKey,
  buildTapTree,
  createControlBlock,
} from '../../lib/bitcore/script/taproot'
import { PrivateKey } from '../../lib/bitcore/privatekey'
import { PublicKey } from '../../lib/bitcore/publickey'
import { Script } from '../../lib/bitcore/script'
import { Schnorr } from '../../lib/bitcore/crypto/schnorr'
import { Hash } from '../../lib/bitcore/crypto/hash'

// ─── Test Helpers ────────────────────────────────────────────────

const DEFAULT_FLAGS =
  ScriptFlags.ENABLE_SIGHASH_FORKID | ScriptFlags.VERIFY_CLEANSTACK

/**
 * Build a valid P2TR scriptPubKey (without state).
 * Format: OP_SCRIPTTYPE OP_1 <33-byte commitment>
 */
function buildP2TRScriptPubKey(commitment: PublicKey): Buffer {
  const commitBuf = commitment.toBuffer()
  const spk = Buffer.alloc(TAPROOT_SIZE_WITHOUT_STATE)
  spk[0] = Opcode.OP_SCRIPTTYPE
  spk[1] = Opcode.OP_1
  spk[2] = 33 // push 33 bytes
  commitBuf.copy(spk, 3)
  return spk
}

/**
 * Build a valid P2TR scriptPubKey with 32-byte state.
 */
function buildP2TRScriptPubKeyWithState(
  commitment: PublicKey,
  state: Buffer,
): Buffer {
  const commitBuf = commitment.toBuffer()
  const spk = Buffer.alloc(TAPROOT_SIZE_WITH_STATE)
  spk[0] = Opcode.OP_SCRIPTTYPE
  spk[1] = Opcode.OP_1
  spk[2] = 33
  commitBuf.copy(spk, 3)
  spk[TAPROOT_SIZE_WITHOUT_STATE] = 32 // push 32 bytes
  state.copy(spk, TAPROOT_SIZE_WITHOUT_STATE + 1)
  return spk
}

/**
 * Build a scriptSig that pushes items onto the stack.
 * Each item is pushed with its length prefix.
 */
function buildPushOnlyScriptSig(items: Buffer[]): Buffer {
  const parts: Buffer[] = []
  for (const item of items) {
    if (item.length === 0) {
      parts.push(Buffer.from([Opcode.OP_0]))
    } else if (item.length === 1 && item[0] >= 1 && item[0] <= 16) {
      // Minimal push: use OP_1 through OP_16
      parts.push(Buffer.from([Opcode.OP_1 + item[0] - 1]))
    } else if (item.length === 1 && item[0] === 0x81) {
      // Minimal push: use OP_1NEGATE
      parts.push(Buffer.from([Opcode.OP_1NEGATE]))
    } else if (item.length <= 75) {
      parts.push(Buffer.from([item.length]))
      parts.push(item)
    } else if (item.length <= 255) {
      parts.push(Buffer.from([Opcode.OP_PUSHDATA1, item.length]))
      parts.push(item)
    } else {
      parts.push(
        Buffer.from([
          Opcode.OP_PUSHDATA2,
          item.length & 0xff,
          (item.length >> 8) & 0xff,
        ]),
      )
      parts.push(item)
    }
  }
  return Buffer.concat(parts)
}

// ─── Tests ───────────────────────────────────────────────────────

describe('Taproot/OP_SCRIPTTYPE verification', () => {
  describe('verifyScriptType dispatch', () => {
    it('should reject OP_SCRIPTTYPE with only 1 byte', () => {
      const scriptSig = Buffer.alloc(0)
      const scriptPubKey = Buffer.from([Opcode.OP_SCRIPTTYPE])
      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.SCRIPTTYPE_MALFORMED_SCRIPT)
    })

    it('should reject unknown script type (OP_2)', () => {
      const scriptPubKey = Buffer.from([
        Opcode.OP_SCRIPTTYPE,
        Opcode.OP_2,
        33,
        ...Buffer.alloc(33),
      ])
      const scriptSig = Buffer.alloc(0)
      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.SCRIPTTYPE_INVALID_TYPE)
    })

    it('should reject Taproot when DISABLE_TAPROOT flag is set', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)
      // Push a dummy signature onto the stack
      const dummySig = Buffer.alloc(65, 0x01)
      dummySig[64] = 0x61 // SIGHASH_ALL | SIGHASH_LOTUS
      const scriptSig = buildPushOnlyScriptSig([dummySig])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS | ScriptFlags.DISABLE_TAPROOT_SIGHASH_LOTUS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.TAPROOT_PHASEOUT)
    })
  })

  describe('isPayToTaproot validation', () => {
    it('should reject P2TR with wrong push size', () => {
      // OP_SCRIPTTYPE OP_1 <32 instead of 33>
      const scriptPubKey = Buffer.alloc(35)
      scriptPubKey[0] = Opcode.OP_SCRIPTTYPE
      scriptPubKey[1] = Opcode.OP_1
      scriptPubKey[2] = 32 // wrong: should be 33
      const scriptSig = buildPushOnlyScriptSig([Buffer.alloc(65, 0x01)])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.SCRIPTTYPE_MALFORMED_SCRIPT)
    })

    it('should reject P2TR that is too short', () => {
      const scriptPubKey = Buffer.alloc(10)
      scriptPubKey[0] = Opcode.OP_SCRIPTTYPE
      scriptPubKey[1] = Opcode.OP_1
      scriptPubKey[2] = 33
      const scriptSig = buildPushOnlyScriptSig([Buffer.alloc(65, 0x01)])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.SCRIPTTYPE_MALFORMED_SCRIPT)
    })
  })

  describe('key-path spending', () => {
    it('should reject empty stack', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)
      const scriptSig = Buffer.alloc(0) // empty stack

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.INVALID_STACK_OPERATION)
    })

    it('should reject non-Schnorr signature (wrong length)', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)
      // Push a 72-byte DER sig (wrong for Taproot key-path)
      const derSig = Buffer.alloc(72, 0x30)
      derSig[71] = 0x61
      const scriptSig = buildPushOnlyScriptSig([derSig])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.SIG_BADLENGTH)
    })

    it('should reject signature without SIGHASH_LOTUS', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)
      // 65-byte sig but with SIGHASH_FORKID (0x41) instead of SIGHASH_LOTUS
      const sig = Buffer.alloc(65, 0x01)
      sig[64] = 0x41 // SIGHASH_ALL | SIGHASH_FORKID (not LOTUS)
      const scriptSig = buildPushOnlyScriptSig([sig])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(
        result.error,
        ScriptError.TAPROOT_KEY_SPEND_MUST_USE_LOTUS_SIGHASH,
      )
    })

    it('should reject invalid signature (NULL checker)', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)
      // Valid format but NULL checker always returns false
      const sig = Buffer.alloc(65, 0x01)
      sig[64] = 0x61 // SIGHASH_ALL | SIGHASH_LOTUS
      const scriptSig = buildPushOnlyScriptSig([sig])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(
        result.error,
        ScriptError.TAPROOT_VERIFY_SIGNATURE_FAILED,
      )
    })

    it('should accept valid key-path spend with mock checker', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)

      const sig = Buffer.alloc(65, 0x01)
      sig[64] = 0x61 // SIGHASH_ALL | SIGHASH_LOTUS
      const scriptSig = buildPushOnlyScriptSig([sig])

      // Mock checker that always succeeds
      const mockChecker: SignatureChecker = {
        verifySignature: () => true,
        checkSignature: () => true,
        checkLockTime: () => true,
        checkSequence: () => true,
      }

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        ScriptFlags.ENABLE_SIGHASH_FORKID,
        mockChecker,
      )
      assert.strictEqual(result.success, true)
    })
  })

  describe('annex rejection', () => {
    it('should reject stack with annex tag', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)

      // Stack: [something, annex_tagged_element]
      const annexElement = Buffer.from([TAPROOT_ANNEX_TAG, 0x01, 0x02])
      const otherElement = Buffer.alloc(20, 0xab) // non-minimal-encodable data
      const scriptSig = buildPushOnlyScriptSig([otherElement, annexElement])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.TAPROOT_ANNEX_NOT_SUPPORTED)
    })
  })

  describe('script-path spending', () => {
    it('should reject control block that is too small', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)

      const tinyControlBlock = Buffer.alloc(10, 0xc0) // too small
      const execScript = Buffer.from([Opcode.OP_1])
      const scriptSig = buildPushOnlyScriptSig([execScript, tinyControlBlock])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.TAPROOT_WRONG_CONTROL_SIZE)
    })

    it('should reject control block with wrong size remainder', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)

      // TAPROOT_CONTROL_BASE_SIZE + 15 bytes (not a multiple of 32)
      const badControlBlock = Buffer.alloc(TAPROOT_CONTROL_BASE_SIZE + 15, 0xc0)
      const execScript = Buffer.from([Opcode.OP_1])
      const scriptSig = buildPushOnlyScriptSig([execScript, badControlBlock])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.TAPROOT_WRONG_CONTROL_SIZE)
    })

    it('should reject unsupported leaf version', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)

      // Control block with leaf version 0xe0 (not 0xc0)
      const controlBlock = Buffer.alloc(TAPROOT_CONTROL_BASE_SIZE, 0x00)
      controlBlock[0] = 0xe0 // unsupported leaf version
      const execScript = Buffer.from([Opcode.OP_1])
      const scriptSig = buildPushOnlyScriptSig([execScript, controlBlock])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(
        result.error,
        ScriptError.TAPROOT_LEAF_VERSION_NOT_SUPPORTED,
      )
    })

    it('should reject invalid commitment (bad merkle proof)', () => {
      const privKey = new PrivateKey()
      const commitment = tweakPublicKey(privKey.publicKey)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)

      // Valid-sized control block but with garbage data
      const controlBlock = Buffer.alloc(TAPROOT_CONTROL_BASE_SIZE, 0x00)
      controlBlock[0] = TAPROOT_LEAF_TAPSCRIPT // correct leaf version
      // Fill with random pubkey x-coord
      Buffer.alloc(32, 0xab).copy(controlBlock, 1)

      const execScript = Buffer.from([Opcode.OP_1])
      const scriptSig = buildPushOnlyScriptSig([execScript, controlBlock])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        DEFAULT_FLAGS,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(
        result.error,
        ScriptError.TAPROOT_VERIFY_COMMITMENT_FAILED,
      )
    })

    it('should execute script-path with valid commitment (OP_1 script)', () => {
      // Build a real Taproot tree with a single leaf: OP_1 (always true)
      const internalPrivKey = new PrivateKey()
      const internalPubKey = internalPrivKey.publicKey

      const leafScript = Script.fromBuffer(Buffer.from([Opcode.OP_1]))
      const tree = { script: leafScript }
      const treeResult = buildTapTree(tree)
      const commitment = tweakPublicKey(internalPubKey, treeResult.merkleRoot)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)

      // Build control block
      const controlBlock = createControlBlock(internalPubKey, 0, tree)

      // scriptSig pushes: [exec_script, control_block]
      const execScriptBuf = leafScript.toBuffer()
      const scriptSig = buildPushOnlyScriptSig([execScriptBuf, controlBlock])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        ScriptFlags.ENABLE_SIGHASH_FORKID | ScriptFlags.VERIFY_CLEANSTACK,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(
        result.success,
        true,
        `Expected success but got: ${result.error}`,
      )
    })

    it('should execute script-path with OP_ADD script', () => {
      const internalPrivKey = new PrivateKey()
      const internalPubKey = internalPrivKey.publicKey

      // Script: OP_ADD OP_3 OP_EQUAL (requires two numbers summing to 3)
      const leafScript = Script.fromBuffer(
        Buffer.from([Opcode.OP_ADD, Opcode.OP_3, Opcode.OP_EQUAL]),
      )
      const tree = { script: leafScript }
      const treeResult = buildTapTree(tree)
      const commitment = tweakPublicKey(internalPubKey, treeResult.merkleRoot)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)

      const controlBlock = createControlBlock(internalPubKey, 0, tree)

      // Stack needs: [1, 2, exec_script, control_block]
      // After popping script+control, stack is [1, 2], then OP_ADD OP_3 OP_EQUAL
      const scriptSig = buildPushOnlyScriptSig([
        Buffer.from([0x01]), // 1
        Buffer.from([0x02]), // 2
        leafScript.toBuffer(),
        controlBlock,
      ])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        ScriptFlags.ENABLE_SIGHASH_FORKID | ScriptFlags.VERIFY_CLEANSTACK,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(
        result.success,
        true,
        `Expected success but got: ${result.error}`,
      )
    })

    it('should push state onto stack for script-path with state', () => {
      const internalPrivKey = new PrivateKey()
      const internalPubKey = internalPrivKey.publicKey

      // Script: OP_SIZE <32> OP_EQUAL (checks that top element is 32 bytes)
      // The state (32 bytes) will be pushed onto the stack before execution
      const leafScript = Script.fromBuffer(
        Buffer.from([Opcode.OP_SIZE, 0x01, 32, Opcode.OP_EQUAL]),
      )
      const tree = { script: leafScript }
      const treeResult = buildTapTree(tree)
      const commitment = tweakPublicKey(internalPubKey, treeResult.merkleRoot)

      const state = Buffer.alloc(32, 0xaa)
      const scriptPubKey = buildP2TRScriptPubKeyWithState(commitment, state)

      const controlBlock = createControlBlock(internalPubKey, 0, tree)

      // Stack: [exec_script, control_block]
      // After popping, stack is empty, then state (32 bytes) is pushed
      // Then OP_SIZE pushes 32, then OP_EQUAL checks 32 == 32
      const scriptSig = buildPushOnlyScriptSig([
        leafScript.toBuffer(),
        controlBlock,
      ])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        ScriptFlags.ENABLE_SIGHASH_FORKID,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(
        result.success,
        true,
        `Expected success but got: ${result.error}`,
      )
    })

    it('should fail script-path when script evaluates to false', () => {
      const internalPrivKey = new PrivateKey()
      const internalPubKey = internalPrivKey.publicKey

      // Script: OP_0 (always false)
      const leafScript = Script.fromBuffer(Buffer.from([Opcode.OP_0]))
      const tree = { script: leafScript }
      const treeResult = buildTapTree(tree)
      const commitment = tweakPublicKey(internalPubKey, treeResult.merkleRoot)
      const scriptPubKey = buildP2TRScriptPubKey(commitment)

      const controlBlock = createControlBlock(internalPubKey, 0, tree)
      const scriptSig = buildPushOnlyScriptSig([
        leafScript.toBuffer(),
        controlBlock,
      ])

      const result = verifyScript(
        scriptSig,
        scriptPubKey,
        ScriptFlags.ENABLE_SIGHASH_FORKID,
        NULL_SIGNATURE_CHECKER,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.EVAL_FALSE)
    })
  })
})

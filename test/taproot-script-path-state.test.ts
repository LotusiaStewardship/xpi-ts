/**
 * Taproot Script Path Spending with State Parameter Tests
 *
 * Tests that verify the state parameter is correctly pushed onto the stack
 * before executing the revealed script in script path spending.
 *
 * Reference: lotusd/src/script/interpreter.cpp lines 2136-2140
 */

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert'
import {
  PrivateKey,
  PublicKey,
  Script,
  Opcode,
  buildScriptPathTaproot,
  Hash,
  Networks,
  createControlBlock,
  TapNode,
  verifyTaprootSpend,
  TAPROOT_SIZE_WITH_STATE,
  TAPROOT_SIZE_WITHOUT_STATE,
  Interpreter,
} from '../lib/bitcore/index.js'

describe('Taproot Script Path Spending with State', () => {
  let privateKey: PrivateKey
  let publicKey: PublicKey

  beforeEach(() => {
    privateKey = new PrivateKey(undefined, Networks.regtest)
    publicKey = privateKey.publicKey
  })

  it('should push state onto stack for 69-byte scripts', () => {
    // Create a state parameter
    const state = Hash.sha256(Buffer.from('Test NFT Metadata', 'utf8'))
    assert.strictEqual(state.length, 32, 'State must be 32 bytes')

    // Create a simple tapscript that just returns true
    const tapscript = new Script().add(Opcode.OP_1)

    // Build script path Taproot with state
    const tree: TapNode = { script: tapscript }
    const result = buildScriptPathTaproot(publicKey, tree, state)

    // Verify script is 69 bytes (with state)
    assert.strictEqual(
      result.script.toBuffer().length,
      TAPROOT_SIZE_WITH_STATE,
      'Script should be 69 bytes with state',
    )

    // Create control block
    const controlBlock = createControlBlock(publicKey, 0, tree)

    // Create stack for script path spending
    // Stack: [script] [control_block]
    const stack = [tapscript.toBuffer(), controlBlock]

    // Call verifyTaprootSpend
    const verifyResult = verifyTaprootSpend(
      result.script,
      stack,
      Interpreter.SCRIPT_VERIFY_NONE,
    )

    // Verification should succeed
    assert.strictEqual(
      verifyResult.success,
      true,
      `Verification should succeed, error: ${verifyResult.error}`,
    )
    assert.ok(verifyResult.stack, 'Stack should be returned')
    assert.ok(
      verifyResult.scriptToExecute,
      'Script to execute should be returned',
    )

    // The critical assertion: state should be on the stack
    // After verifyTaprootSpend, the state should have been pushed onto the stack
    assert.strictEqual(
      verifyResult.stack!.length,
      1,
      'Stack should have 1 element (the state)',
    )
    assert.ok(
      verifyResult.stack![0].equals(state),
      'State should be on top of stack',
    )
  })

  it('should not push state for 36-byte scripts', () => {
    // Create script path Taproot WITHOUT state
    const tapscript = new Script().add(Opcode.OP_1)

    const tree: TapNode = { script: tapscript }
    const result = buildScriptPathTaproot(publicKey, tree) // No state parameter

    // Verify script is 36 bytes (no state)
    assert.strictEqual(
      result.script.toBuffer().length,
      TAPROOT_SIZE_WITHOUT_STATE,
      'Script should be 36 bytes without state',
    )

    // Create control block
    const controlBlock = createControlBlock(publicKey, 0, tree)

    // Create stack for script path spending
    const stack = [tapscript.toBuffer(), controlBlock]

    // Call verifyTaprootSpend
    const verifyResult = verifyTaprootSpend(
      result.script,
      stack,
      Interpreter.SCRIPT_VERIFY_NONE,
    )

    // Verification should succeed
    assert.strictEqual(
      verifyResult.success,
      true,
      'Verification should succeed',
    )
    assert.ok(verifyResult.stack, 'Stack should be returned')

    // Stack should be empty (no state pushed)
    assert.strictEqual(
      verifyResult.stack!.length,
      0,
      'Stack should be empty (no state)',
    )
  })

  it('should make state accessible in tapscripts', () => {
    // Create a state
    const state = Hash.sha256(Buffer.from('Contract State Data', 'utf8'))

    // Create a simple tapscript that uses the state
    // Script: OP_1 (just returns true, but state is on stack during execution)
    const tapscript = new Script().add(Opcode.OP_1)

    const tree: TapNode = { script: tapscript }
    const result = buildScriptPathTaproot(publicKey, tree, state)

    // Create control block
    const controlBlock = createControlBlock(publicKey, 0, tree)

    // Create stack for script path spending
    const stack = [tapscript.toBuffer(), controlBlock]

    // Call verifyTaprootSpend
    const verifyResult = verifyTaprootSpend(
      result.script,
      stack,
      Interpreter.SCRIPT_VERIFY_NONE,
    )

    // Verification should succeed
    assert.strictEqual(
      verifyResult.success,
      true,
      'Verification should succeed',
    )

    // State should be on the stack ready for script execution
    assert.strictEqual(
      verifyResult.stack!.length,
      1,
      'State should be on stack',
    )
    assert.ok(verifyResult.stack![0].equals(state), 'State value should match')

    // Now execute the script with the state on the stack
    const interpreter = new Interpreter({
      script: verifyResult.scriptToExecute!,
      stack: verifyResult.stack!,
      flags: Interpreter.SCRIPT_VERIFY_NONE,
    })

    const evalResult = interpreter.evaluate()
    assert.strictEqual(
      evalResult,
      true,
      `Script should execute successfully with state, error: ${interpreter.errstr}`,
    )

    // After execution: OP_1 pushes 1 onto stack
    // Stack should have: [state, 1]
    assert.strictEqual(
      interpreter.stack.length,
      2,
      `Stack should have 2 elements, but has ${interpreter.stack.length}`,
    )
    assert.ok(
      interpreter.stack[0].equals(state),
      'State should still be on stack',
    )
    assert.ok(
      Interpreter.castToBool(interpreter.stack[1]),
      'Top of stack should be true',
    )
  })

  it('should push correct state for multiple leaves', () => {
    const state = Hash.sha256(Buffer.from('Multi-leaf State', 'utf8'))

    // Create a tree with multiple leaves
    const script1 = new Script().add(Opcode.OP_1)
    const script2 = new Script().add(Opcode.OP_1)

    const tree: TapNode = {
      left: { script: script1 },
      right: { script: script2 },
    }

    const result = buildScriptPathTaproot(publicKey, tree, state)

    // Test spending with leaf 0
    const controlBlock0 = createControlBlock(publicKey, 0, tree)
    const stack0 = [script1.toBuffer(), controlBlock0]
    const verify0 = verifyTaprootSpend(
      result.script,
      stack0,
      Interpreter.SCRIPT_VERIFY_NONE,
    )

    assert.strictEqual(verify0.success, true)
    assert.strictEqual(verify0.stack!.length, 1)
    assert.ok(
      verify0.stack![0].equals(state),
      'State should be pushed for leaf 0',
    )

    // Test spending with leaf 1
    const controlBlock1 = createControlBlock(publicKey, 1, tree)
    const stack1 = [script2.toBuffer(), controlBlock1]
    const verify1 = verifyTaprootSpend(
      result.script,
      stack1,
      Interpreter.SCRIPT_VERIFY_NONE,
    )

    assert.strictEqual(verify1.success, true)
    assert.strictEqual(verify1.stack!.length, 1)
    assert.ok(
      verify1.stack![0].equals(state),
      'State should be pushed for leaf 1',
    )
  })
})

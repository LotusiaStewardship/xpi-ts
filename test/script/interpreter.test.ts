/**
 * Script Interpreter Unit Tests
 *
 * Tests for evalScript and verifyScript functions, covering:
 * - Basic opcode execution (stack ops, arithmetic, crypto)
 * - Control flow (IF/ELSE/ENDIF)
 * - Error conditions (stack underflow, disabled opcodes, size limits)
 * - P2PKH and P2SH script verification patterns
 * - Interpreter class backward compatibility
 *
 * Reference: lotusd/src/test/script_tests.cpp
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'buffer/'
import {
  evalScript,
  verifyScript,
  Interpreter,
  ScriptError,
  ScriptFlags,
  STANDARD_SCRIPT_VERIFY_FLAGS,
  NULL_SIGNATURE_CHECKER,
  type ScriptExecutionMetrics,
  type ScriptExecutionData,
} from '../../lib/bitcore/script/interpreter/index'
import { Opcode } from '../../lib/bitcore/opcode'
import { Hash } from '../../lib/bitcore/crypto/hash'

// ─── Test Helpers ────────────────────────────────────────────────

function makeMetrics(): ScriptExecutionMetrics {
  return { sigChecks: 0 }
}

function makeExecdata(): ScriptExecutionData {
  return {
    codeseparatorPos: 0xffffffff,
    executedScriptHash: Hash.sha256sha256(Buffer.alloc(0)),
  }
}

type StackElement = Buffer

/**
 * Run evalScript on a raw script buffer and return the result + final stack.
 */
function runScript(
  scriptBytes: number[],
  initialStack: StackElement[] = [],
  flags: number = ScriptFlags.VERIFY_NONE,
): { result: ReturnType<typeof evalScript>; stack: StackElement[] } {
  const stack = initialStack.map(el => Buffer.from(el))
  const scriptBuf = Buffer.from(scriptBytes)
  const metrics = makeMetrics()
  const execdata = makeExecdata()
  const result = evalScript(
    stack,
    scriptBuf,
    flags,
    NULL_SIGNATURE_CHECKER,
    metrics,
    execdata,
  )
  return { result, stack }
}

// ─── Tests ───────────────────────────────────────────────────────

describe('evalScript', () => {
  describe('push value opcodes', () => {
    it('should push OP_0 as empty buffer', () => {
      const { result, stack } = runScript([Opcode.OP_0])
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 1)
      assert.strictEqual(stack[0].length, 0)
    })

    it('should push OP_1 through OP_16', () => {
      for (let i = 1; i <= 16; i++) {
        const opcode = Opcode.OP_1 + (i - 1)
        const { result, stack } = runScript([opcode])
        assert.strictEqual(result.success, true)
        assert.strictEqual(stack.length, 1)
        // OP_N pushes the ScriptNum encoding of N
        // For 1-16, this is a single byte [N]
        assert.strictEqual(stack[0].length > 0, true, `OP_${i} should push non-empty`)
      }
    })

    it('should push OP_1NEGATE as -1', () => {
      const { result, stack } = runScript([Opcode.OP_1NEGATE])
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 1)
      // -1 in script number encoding is [0x81]
      assert.deepStrictEqual(stack[0], Buffer.from([0x81]))
    })

    it('should push direct data (minimal)', () => {
      // Push 3 bytes: [0x03, 0xaa, 0xbb, 0xcc]
      const { result, stack } = runScript([0x03, 0xaa, 0xbb, 0xcc])
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 1)
      assert.deepStrictEqual(stack[0], Buffer.from([0xaa, 0xbb, 0xcc]))
    })
  })

  describe('stack operations', () => {
    it('OP_DUP should duplicate top element', () => {
      const { result, stack } = runScript(
        [Opcode.OP_DUP],
        [Buffer.from([0x42])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 2)
      assert.deepStrictEqual(stack[0], stack[1])
    })

    it('OP_DROP should remove top element', () => {
      const { result, stack } = runScript(
        [Opcode.OP_DROP],
        [Buffer.from([0x01]), Buffer.from([0x02])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 1)
      assert.deepStrictEqual(stack[0], Buffer.from([0x01]))
    })

    it('OP_SWAP should swap top two elements', () => {
      const { result, stack } = runScript(
        [Opcode.OP_SWAP],
        [Buffer.from([0x01]), Buffer.from([0x02])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x02]))
      assert.deepStrictEqual(stack[1], Buffer.from([0x01]))
    })

    it('OP_OVER should copy second-to-top', () => {
      const { result, stack } = runScript(
        [Opcode.OP_OVER],
        [Buffer.from([0x01]), Buffer.from([0x02])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 3)
      assert.deepStrictEqual(stack[2], Buffer.from([0x01]))
    })

    it('OP_DEPTH should push stack depth', () => {
      const { result, stack } = runScript(
        [Opcode.OP_DEPTH],
        [Buffer.from([0x01]), Buffer.from([0x02])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 3)
      // Depth was 2 before OP_DEPTH
      assert.deepStrictEqual(stack[2], Buffer.from([0x02]))
    })

    it('OP_SIZE should push size of top element', () => {
      const { result, stack } = runScript(
        [Opcode.OP_SIZE],
        [Buffer.from([0xaa, 0xbb, 0xcc])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 2)
      // Size is 3
      assert.deepStrictEqual(stack[1], Buffer.from([0x03]))
    })

    it('OP_NIP should remove second-to-top', () => {
      const { result, stack } = runScript(
        [Opcode.OP_NIP],
        [Buffer.from([0x01]), Buffer.from([0x02])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 1)
      assert.deepStrictEqual(stack[0], Buffer.from([0x02]))
    })

    it('OP_TUCK should copy top before second-to-top', () => {
      const { result, stack } = runScript(
        [Opcode.OP_TUCK],
        [Buffer.from([0x01]), Buffer.from([0x02])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 3)
      assert.deepStrictEqual(stack[0], Buffer.from([0x02]))
      assert.deepStrictEqual(stack[1], Buffer.from([0x01]))
      assert.deepStrictEqual(stack[2], Buffer.from([0x02]))
    })

    it('should fail on stack underflow', () => {
      const { result } = runScript([Opcode.OP_DUP])
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.INVALID_STACK_OPERATION)
    })
  })

  describe('arithmetic operations', () => {
    it('OP_ADD should add two numbers', () => {
      const { result, stack } = runScript(
        [Opcode.OP_ADD],
        [Buffer.from([0x03]), Buffer.from([0x04])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x07]))
    })

    it('OP_SUB should subtract', () => {
      const { result, stack } = runScript(
        [Opcode.OP_SUB],
        [Buffer.from([0x0a]), Buffer.from([0x03])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x07]))
    })

    it('OP_1ADD should increment', () => {
      const { result, stack } = runScript(
        [Opcode.OP_1ADD],
        [Buffer.from([0x05])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x06]))
    })

    it('OP_1SUB should decrement', () => {
      const { result, stack } = runScript(
        [Opcode.OP_1SUB],
        [Buffer.from([0x05])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x04]))
    })

    it('OP_NEGATE should negate', () => {
      const { result, stack } = runScript(
        [Opcode.OP_NEGATE],
        [Buffer.from([0x05])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x85]))
    })

    it('OP_ABS should absolute value', () => {
      const { result, stack } = runScript(
        [Opcode.OP_ABS],
        [Buffer.from([0x85])], // -5
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x05]))
    })

    it('OP_NOT should boolean negate', () => {
      // NOT(0) = 1
      const { result: r1, stack: s1 } = runScript(
        [Opcode.OP_NOT],
        [Buffer.alloc(0)],
      )
      assert.strictEqual(r1.success, true)
      assert.deepStrictEqual(s1[0], Buffer.from([0x01]))

      // NOT(5) = 0
      const { result: r2, stack: s2 } = runScript(
        [Opcode.OP_NOT],
        [Buffer.from([0x05])],
      )
      assert.strictEqual(r2.success, true)
      assert.strictEqual(s2[0].length, 0) // 0 is empty buffer
    })

    it('OP_BOOLAND should boolean AND', () => {
      const { result, stack } = runScript(
        [Opcode.OP_BOOLAND],
        [Buffer.from([0x01]), Buffer.from([0x01])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x01]))
    })

    it('OP_BOOLOR should boolean OR', () => {
      const { result, stack } = runScript(
        [Opcode.OP_BOOLOR],
        [Buffer.from([0x01]), Buffer.alloc(0)],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x01]))
    })

    it('OP_LESSTHAN should compare', () => {
      const { result, stack } = runScript(
        [Opcode.OP_LESSTHAN],
        [Buffer.from([0x03]), Buffer.from([0x05])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x01]))
    })

    it('OP_GREATERTHAN should compare', () => {
      const { result, stack } = runScript(
        [Opcode.OP_GREATERTHAN],
        [Buffer.from([0x05]), Buffer.from([0x03])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x01]))
    })

    it('OP_MIN should return minimum', () => {
      const { result, stack } = runScript(
        [Opcode.OP_MIN],
        [Buffer.from([0x05]), Buffer.from([0x03])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x03]))
    })

    it('OP_MAX should return maximum', () => {
      const { result, stack } = runScript(
        [Opcode.OP_MAX],
        [Buffer.from([0x05]), Buffer.from([0x03])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x05]))
    })

    it('OP_WITHIN should check range', () => {
      // 5 WITHIN [3, 10) = true
      const { result, stack } = runScript(
        [Opcode.OP_WITHIN],
        [Buffer.from([0x05]), Buffer.from([0x03]), Buffer.from([0x0a])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x01]))
    })

    it('OP_DIV should divide', () => {
      const { result, stack } = runScript(
        [Opcode.OP_DIV],
        [Buffer.from([0x0a]), Buffer.from([0x03])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x03]))
    })

    it('OP_DIV should fail on divide by zero', () => {
      const { result } = runScript(
        [Opcode.OP_DIV],
        [Buffer.from([0x0a]), Buffer.alloc(0)],
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.DIV_BY_ZERO)
    })

    it('OP_MOD should modulo', () => {
      const { result, stack } = runScript(
        [Opcode.OP_MOD],
        [Buffer.from([0x0a]), Buffer.from([0x03])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x01]))
    })

    it('OP_MOD should fail on mod by zero', () => {
      const { result } = runScript(
        [Opcode.OP_MOD],
        [Buffer.from([0x0a]), Buffer.alloc(0)],
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.MOD_BY_ZERO)
    })
  })

  describe('equality and comparison', () => {
    it('OP_EQUAL should compare equal byte strings', () => {
      const { result, stack } = runScript(
        [Opcode.OP_EQUAL],
        [Buffer.from([0xaa, 0xbb]), Buffer.from([0xaa, 0xbb])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x01]))
    })

    it('OP_EQUAL should compare unequal byte strings', () => {
      const { result, stack } = runScript(
        [Opcode.OP_EQUAL],
        [Buffer.from([0xaa]), Buffer.from([0xbb])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack[0].length, 0) // false = empty
    })

    it('OP_EQUALVERIFY should pass on equal', () => {
      const { result, stack } = runScript(
        [Opcode.OP_EQUALVERIFY],
        [Buffer.from([0xaa]), Buffer.from([0xaa])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 0)
    })

    it('OP_EQUALVERIFY should fail on unequal', () => {
      const { result } = runScript(
        [Opcode.OP_EQUALVERIFY],
        [Buffer.from([0xaa]), Buffer.from([0xbb])],
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.EQUALVERIFY)
    })
  })

  describe('crypto operations', () => {
    it('OP_SHA256 should hash', () => {
      const data = Buffer.from('hello')
      const expected = Hash.sha256(data)
      const { result, stack } = runScript([Opcode.OP_SHA256], [data])
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], expected)
    })

    it('OP_HASH160 should sha256+ripemd160', () => {
      const data = Buffer.from('hello')
      const expected = Hash.sha256ripemd160(data)
      const { result, stack } = runScript([Opcode.OP_HASH160], [data])
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], expected)
    })

    it('OP_HASH256 should double sha256', () => {
      const data = Buffer.from('hello')
      const expected = Hash.sha256sha256(data)
      const { result, stack } = runScript([Opcode.OP_HASH256], [data])
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], expected)
    })

    it('OP_RIPEMD160 should hash', () => {
      const data = Buffer.from('hello')
      const expected = Hash.ripemd160(data)
      const { result, stack } = runScript([Opcode.OP_RIPEMD160], [data])
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], expected)
    })
  })

  describe('control flow', () => {
    it('OP_IF true branch should execute', () => {
      // OP_1 OP_IF OP_2 OP_ENDIF
      const { result, stack } = runScript([
        Opcode.OP_1,
        Opcode.OP_IF,
        Opcode.OP_2,
        Opcode.OP_ENDIF,
      ])
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 1)
      // OP_2 pushes ScriptNum(2) = [0x02]
      assert.deepStrictEqual(stack[0], Buffer.from([0x02]))
    })

    it('OP_IF false branch should skip', () => {
      // OP_0 OP_IF OP_2 OP_ENDIF
      const { result, stack } = runScript([
        Opcode.OP_0,
        Opcode.OP_IF,
        Opcode.OP_2,
        Opcode.OP_ENDIF,
      ])
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 0)
    })

    it('OP_IF/ELSE should execute else branch on false', () => {
      // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
      const { result, stack } = runScript([
        Opcode.OP_0,
        Opcode.OP_IF,
        Opcode.OP_2,
        Opcode.OP_ELSE,
        Opcode.OP_3,
        Opcode.OP_ENDIF,
      ])
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 1)
      assert.deepStrictEqual(stack[0], Buffer.from([0x03]))
    })

    it('OP_NOTIF should invert condition', () => {
      // OP_0 OP_NOTIF OP_2 OP_ENDIF (0 -> NOTIF executes)
      const { result, stack } = runScript([
        Opcode.OP_0,
        Opcode.OP_NOTIF,
        Opcode.OP_2,
        Opcode.OP_ENDIF,
      ])
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 1)
    })

    it('should fail on unbalanced IF', () => {
      const { result } = runScript([Opcode.OP_1, Opcode.OP_IF, Opcode.OP_2])
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.UNBALANCED_CONDITIONAL)
    })

    it('should fail on ELSE without IF', () => {
      const { result } = runScript([Opcode.OP_ELSE])
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.UNBALANCED_CONDITIONAL)
    })

    it('should fail on ENDIF without IF', () => {
      const { result } = runScript([Opcode.OP_ENDIF])
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.UNBALANCED_CONDITIONAL)
    })
  })

  describe('OP_VERIFY', () => {
    it('should pass on true', () => {
      const { result, stack } = runScript(
        [Opcode.OP_VERIFY],
        [Buffer.from([0x01])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 0)
    })

    it('should fail on false', () => {
      const { result } = runScript(
        [Opcode.OP_VERIFY],
        [Buffer.alloc(0)],
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.VERIFY)
    })
  })

  describe('OP_RETURN', () => {
    it('should always fail', () => {
      const { result } = runScript([Opcode.OP_RETURN])
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.OP_RETURN)
    })
  })

  describe('disabled opcodes', () => {
    it('should fail on OP_MUL', () => {
      const { result } = runScript([Opcode.OP_MUL])
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.DISABLED_OPCODE)
    })

    it('should fail on OP_2MUL', () => {
      const { result } = runScript([Opcode.OP_2MUL])
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.DISABLED_OPCODE)
    })

    it('should fail on OP_2DIV', () => {
      const { result } = runScript([Opcode.OP_2DIV])
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.DISABLED_OPCODE)
    })
  })

  describe('byte string operations', () => {
    it('OP_CAT should concatenate', () => {
      const { result, stack } = runScript(
        [Opcode.OP_CAT],
        [Buffer.from([0xaa, 0xbb]), Buffer.from([0xcc, 0xdd])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]))
    })

    it('OP_SPLIT should split at position', () => {
      const { result, stack } = runScript(
        [Opcode.OP_SPLIT],
        [Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]), Buffer.from([0x02])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 2)
      assert.deepStrictEqual(stack[0], Buffer.from([0xaa, 0xbb]))
      assert.deepStrictEqual(stack[1], Buffer.from([0xcc, 0xdd]))
    })

    it('OP_REVERSEBYTES should reverse', () => {
      const { result, stack } = runScript(
        [Opcode.OP_REVERSEBYTES],
        [Buffer.from([0x01, 0x02, 0x03])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x03, 0x02, 0x01]))
    })
  })

  describe('bitwise operations', () => {
    it('OP_AND should bitwise AND', () => {
      const { result, stack } = runScript(
        [Opcode.OP_AND],
        [Buffer.from([0xff, 0x0f]), Buffer.from([0x0f, 0xff])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0x0f, 0x0f]))
    })

    it('OP_OR should bitwise OR', () => {
      const { result, stack } = runScript(
        [Opcode.OP_OR],
        [Buffer.from([0xf0, 0x00]), Buffer.from([0x0f, 0x00])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0xff, 0x00]))
    })

    it('OP_XOR should bitwise XOR', () => {
      const { result, stack } = runScript(
        [Opcode.OP_XOR],
        [Buffer.from([0xff, 0x00]), Buffer.from([0x0f, 0xf0])],
      )
      assert.strictEqual(result.success, true)
      assert.deepStrictEqual(stack[0], Buffer.from([0xf0, 0xf0]))
    })
  })

  describe('altstack operations', () => {
    it('OP_TOALTSTACK and OP_FROMALTSTACK round-trip', () => {
      const { result, stack } = runScript(
        [Opcode.OP_TOALTSTACK, Opcode.OP_FROMALTSTACK],
        [Buffer.from([0x42])],
      )
      assert.strictEqual(result.success, true)
      assert.strictEqual(stack.length, 1)
      assert.deepStrictEqual(stack[0], Buffer.from([0x42]))
    })

    it('OP_FROMALTSTACK should fail on empty altstack', () => {
      const { result } = runScript([Opcode.OP_FROMALTSTACK])
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.INVALID_ALTSTACK_OPERATION)
    })
  })

  describe('size limits', () => {
    it('should reject script exceeding MAX_SCRIPT_SIZE', () => {
      const bigScript = Buffer.alloc(10001, Opcode.OP_NOP)
      const stack: StackElement[] = []
      const result = evalScript(
        stack,
        bigScript,
        ScriptFlags.VERIFY_NONE,
        NULL_SIGNATURE_CHECKER,
        makeMetrics(),
        makeExecdata(),
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.SCRIPT_SIZE)
    })

    it('should reject push exceeding MAX_SCRIPT_ELEMENT_SIZE', () => {
      // OP_PUSHDATA2 with 521 bytes
      const len = 521
      const script = Buffer.alloc(3 + len)
      script[0] = Opcode.OP_PUSHDATA2
      script[1] = len & 0xff
      script[2] = (len >> 8) & 0xff
      script.fill(0xaa, 3)
      const stack: StackElement[] = []
      const result = evalScript(
        stack,
        script,
        ScriptFlags.VERIFY_NONE,
        NULL_SIGNATURE_CHECKER,
        makeMetrics(),
        makeExecdata(),
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.PUSH_SIZE)
    })
  })

  describe('OP_NOP with DISCOURAGE_UPGRADABLE_NOPS', () => {
    it('OP_NOP should succeed without flag', () => {
      const { result } = runScript([Opcode.OP_NOP], [], ScriptFlags.VERIFY_NONE)
      assert.strictEqual(result.success, true)
    })

    it('OP_NOP1 should fail with DISCOURAGE flag', () => {
      const { result } = runScript(
        [Opcode.OP_NOP1],
        [],
        ScriptFlags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.DISCOURAGE_UPGRADABLE_NOPS)
    })

    it('OP_NOP4 should fail with DISCOURAGE flag', () => {
      const { result } = runScript(
        [Opcode.OP_NOP4],
        [],
        ScriptFlags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.DISCOURAGE_UPGRADABLE_NOPS)
    })
  })

  describe('MINIMALIF flag', () => {
    it('should reject non-minimal IF argument with flag', () => {
      // OP_IF with [0x02] on stack (non-minimal true)
      const { result } = runScript(
        [Opcode.OP_IF, Opcode.OP_1, Opcode.OP_ENDIF],
        [Buffer.from([0x02])],
        ScriptFlags.VERIFY_MINIMALIF,
      )
      assert.strictEqual(result.success, false)
      assert.strictEqual(result.error, ScriptError.MINIMALIF)
    })

    it('should accept [0x01] as IF argument with flag', () => {
      const { result } = runScript(
        [Opcode.OP_IF, Opcode.OP_1, Opcode.OP_ENDIF],
        [Buffer.from([0x01])],
        ScriptFlags.VERIFY_MINIMALIF,
      )
      assert.strictEqual(result.success, true)
    })

    it('should accept empty as IF argument with flag', () => {
      const { result } = runScript(
        [Opcode.OP_IF, Opcode.OP_1, Opcode.OP_ENDIF],
        [Buffer.alloc(0)],
        ScriptFlags.VERIFY_MINIMALIF,
      )
      assert.strictEqual(result.success, true)
    })
  })
})

describe('verifyScript', () => {
  it('should verify simple OP_TRUE scriptPubKey', () => {
    // scriptSig: (empty), scriptPubKey: OP_1
    const result = verifyScript(
      Buffer.alloc(0),
      Buffer.from([Opcode.OP_1]),
      ScriptFlags.VERIFY_NONE,
      NULL_SIGNATURE_CHECKER,
    )
    assert.strictEqual(result.success, true)
  })

  it('should fail on OP_0 scriptPubKey', () => {
    const result = verifyScript(
      Buffer.alloc(0),
      Buffer.from([Opcode.OP_0]),
      ScriptFlags.VERIFY_NONE,
      NULL_SIGNATURE_CHECKER,
    )
    assert.strictEqual(result.success, false)
    assert.strictEqual(result.error, ScriptError.EVAL_FALSE)
  })

  it('should verify scriptSig pushing data matched by scriptPubKey', () => {
    // scriptSig: push [0xaa, 0xbb]
    // scriptPubKey: push [0xaa, 0xbb] OP_EQUAL
    const scriptSig = Buffer.from([0x02, 0xaa, 0xbb])
    const scriptPubKey = Buffer.from([0x02, 0xaa, 0xbb, Opcode.OP_EQUAL])
    const result = verifyScript(
      scriptSig,
      scriptPubKey,
      ScriptFlags.VERIFY_NONE,
      NULL_SIGNATURE_CHECKER,
    )
    assert.strictEqual(result.success, true)
  })

  it('should fail CLEANSTACK with extra stack elements', () => {
    // scriptSig: push two values
    // scriptPubKey: OP_1 (leaves 3 elements on stack)
    const scriptSig = Buffer.from([0x01, 0xaa, 0x01, 0xbb])
    const scriptPubKey = Buffer.from([Opcode.OP_1])
    const result = verifyScript(
      scriptSig,
      scriptPubKey,
      ScriptFlags.VERIFY_CLEANSTACK,
      NULL_SIGNATURE_CHECKER,
    )
    assert.strictEqual(result.success, false)
    assert.strictEqual(result.error, ScriptError.CLEANSTACK)
  })

  it('should reject non-push-only scriptSig', () => {
    // scriptSig with OP_DUP (non-push opcode)
    const scriptSig = Buffer.from([Opcode.OP_DUP])
    const scriptPubKey = Buffer.from([Opcode.OP_1])
    const result = verifyScript(
      scriptSig,
      scriptPubKey,
      ScriptFlags.VERIFY_NONE,
      NULL_SIGNATURE_CHECKER,
    )
    assert.strictEqual(result.success, false)
    assert.strictEqual(result.error, ScriptError.SIG_PUSHONLY)
  })

  it('should verify P2SH script', () => {
    // Redeem script: OP_1 (always true)
    const redeemScript = Buffer.from([Opcode.OP_1])
    const redeemHash = Hash.sha256ripemd160(redeemScript)

    // scriptPubKey: OP_HASH160 <20-byte hash> OP_EQUAL
    const scriptPubKey = Buffer.alloc(23)
    scriptPubKey[0] = Opcode.OP_HASH160
    scriptPubKey[1] = 0x14 // push 20 bytes
    redeemHash.copy(scriptPubKey, 2)
    scriptPubKey[22] = Opcode.OP_EQUAL

    // scriptSig: push the redeem script
    const scriptSig = Buffer.alloc(1 + redeemScript.length)
    scriptSig[0] = redeemScript.length
    redeemScript.copy(scriptSig, 1)

    const result = verifyScript(
      scriptSig,
      scriptPubKey,
      ScriptFlags.VERIFY_NONE,
      NULL_SIGNATURE_CHECKER,
    )
    assert.strictEqual(result.success, true)
  })
})

describe('Interpreter class', () => {
  describe('static flag constants', () => {
    it('should expose SCRIPT_ENABLE_SIGHASH_FORKID', () => {
      assert.strictEqual(
        Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID,
        ScriptFlags.ENABLE_SIGHASH_FORKID,
      )
    })

    it('should expose SCRIPT_VERIFY_CLEANSTACK', () => {
      assert.strictEqual(
        Interpreter.SCRIPT_VERIFY_CLEANSTACK,
        ScriptFlags.VERIFY_CLEANSTACK,
      )
    })

    it('should expose SCRIPT_ENABLE_REPLAY_PROTECTION', () => {
      assert.strictEqual(
        Interpreter.SCRIPT_ENABLE_REPLAY_PROTECTION,
        ScriptFlags.ENABLE_REPLAY_PROTECTION,
      )
    })

    it('should expose SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS', () => {
      assert.strictEqual(
        Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
        ScriptFlags.VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
      )
    })

    it('should expose SCRIPT_VERIFY_INPUT_SIGCHECKS', () => {
      assert.strictEqual(
        Interpreter.SCRIPT_VERIFY_INPUT_SIGCHECKS,
        ScriptFlags.VERIFY_INPUT_SIGCHECKS,
      )
    })
  })

  describe('errstr', () => {
    it('should start with empty errstr', () => {
      const interp = new Interpreter()
      assert.strictEqual(interp.errstr, '')
    })
  })
})

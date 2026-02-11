/**
 * ScriptNum Unit Tests
 *
 * Tests for the CScriptNum-equivalent class used in Lotus script evaluation.
 * Covers encoding/decoding, arithmetic, overflow, and minimal encoding rules.
 *
 * Reference: lotusd/src/test/scriptnum_tests.cpp
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'buffer/'
import {
  ScriptNum,
  ScriptNumError,
} from '../../lib/bitcore/script/interpreter/script-num'

describe('ScriptNum', () => {
  describe('constructor and value', () => {
    it('should store bigint value', () => {
      const sn = new ScriptNum(42n)
      assert.strictEqual(sn.value, 42n)
    })

    it('should store zero', () => {
      const sn = new ScriptNum(0n)
      assert.strictEqual(sn.value, 0n)
    })

    it('should store negative values', () => {
      const sn = new ScriptNum(-100n)
      assert.strictEqual(sn.value, -100n)
    })

    it('should store large int64 values', () => {
      const max = (1n << 63n) - 1n
      const sn = new ScriptNum(max)
      assert.strictEqual(sn.value, max)
    })
  })

  describe('fromBuffer', () => {
    it('should decode empty buffer as 0', () => {
      const sn = ScriptNum.fromBuffer(Buffer.alloc(0))
      assert.strictEqual(sn.value, 0n)
    })

    it('should decode single byte positive', () => {
      const sn = ScriptNum.fromBuffer(Buffer.from([0x05]))
      assert.strictEqual(sn.value, 5n)
    })

    it('should decode single byte negative', () => {
      // 0x85 = 0x80 (sign) | 0x05 (value) = -5
      const sn = ScriptNum.fromBuffer(Buffer.from([0x85]))
      assert.strictEqual(sn.value, -5n)
    })

    it('should decode two-byte positive', () => {
      // 0x0100 little-endian = 256
      const sn = ScriptNum.fromBuffer(Buffer.from([0x00, 0x01]))
      assert.strictEqual(sn.value, 256n)
    })

    it('should decode two-byte negative', () => {
      // 0x0081 little-endian = -256 (0x80 sign bit on second byte, value 0x0100)
      const sn = ScriptNum.fromBuffer(Buffer.from([0x00, 0x81]))
      assert.strictEqual(sn.value, -256n)
    })

    it('should decode value 128 (needs extra byte for sign)', () => {
      // 128 = 0x80, but 0x80 alone means -0, so we need [0x80, 0x00]
      const sn = ScriptNum.fromBuffer(Buffer.from([0x80, 0x00]))
      assert.strictEqual(sn.value, 128n)
    })

    it('should decode value -128', () => {
      // -128 = [0x80, 0x80]
      const sn = ScriptNum.fromBuffer(Buffer.from([0x80, 0x80]))
      assert.strictEqual(sn.value, -128n)
    })

    it('should reject buffer exceeding maxSize', () => {
      const buf = Buffer.alloc(9, 0x01) // 9 bytes > default max of 8
      assert.throws(
        () => ScriptNum.fromBuffer(buf),
        (err: Error) => err instanceof ScriptNumError,
      )
    })

    it('should allow 5-byte numbers with maxSize=5', () => {
      const buf = Buffer.from([0xff, 0xff, 0xff, 0xff, 0x00])
      const sn = ScriptNum.fromBuffer(buf, true, 5)
      assert.strictEqual(sn.value, 0xffffffffn)
    })

    it('should reject non-minimal encoding when requireMinimal=true', () => {
      // [0x00, 0x00] is non-minimal (should be empty for 0)
      assert.throws(
        () => ScriptNum.fromBuffer(Buffer.from([0x00, 0x00]), true),
        (err: Error) => err instanceof ScriptNumError,
      )
    })

    it('should accept non-minimal encoding when requireMinimal=false', () => {
      const sn = ScriptNum.fromBuffer(Buffer.from([0x00, 0x00]), false)
      assert.strictEqual(sn.value, 0n)
    })
  })

  describe('toBuffer (serialize)', () => {
    it('should serialize 0 as empty buffer', () => {
      const sn = new ScriptNum(0n)
      assert.strictEqual(sn.toBuffer().length, 0)
    })

    it('should serialize 1 as [0x01]', () => {
      const sn = new ScriptNum(1n)
      assert.deepStrictEqual(sn.toBuffer(), Buffer.from([0x01]))
    })

    it('should serialize -1 as [0x81]', () => {
      const sn = new ScriptNum(-1n)
      assert.deepStrictEqual(sn.toBuffer(), Buffer.from([0x81]))
    })

    it('should serialize 127 as [0x7f]', () => {
      const sn = new ScriptNum(127n)
      assert.deepStrictEqual(sn.toBuffer(), Buffer.from([0x7f]))
    })

    it('should serialize 128 as [0x80, 0x00]', () => {
      const sn = new ScriptNum(128n)
      assert.deepStrictEqual(sn.toBuffer(), Buffer.from([0x80, 0x00]))
    })

    it('should serialize -128 as [0x80, 0x80]', () => {
      const sn = new ScriptNum(-128n)
      assert.deepStrictEqual(sn.toBuffer(), Buffer.from([0x80, 0x80]))
    })

    it('should serialize 256 as [0x00, 0x01]', () => {
      const sn = new ScriptNum(256n)
      assert.deepStrictEqual(sn.toBuffer(), Buffer.from([0x00, 0x01]))
    })

    it('should round-trip through fromBuffer', () => {
      const values = [0n, 1n, -1n, 127n, 128n, -128n, 255n, 256n, -256n, 65535n, -65535n]
      for (const v of values) {
        const sn = new ScriptNum(v)
        const decoded = ScriptNum.fromBuffer(sn.toBuffer())
        assert.strictEqual(decoded.value, v, `round-trip failed for ${v}`)
      }
    })
  })

  describe('isMinimallyEncoded', () => {
    it('should accept empty buffer', () => {
      assert.strictEqual(ScriptNum.isMinimallyEncoded(Buffer.alloc(0)), true)
    })

    it('should accept [0x01]', () => {
      assert.strictEqual(
        ScriptNum.isMinimallyEncoded(Buffer.from([0x01])),
        true,
      )
    })

    it('should reject [0x00] (non-minimal zero)', () => {
      assert.strictEqual(
        ScriptNum.isMinimallyEncoded(Buffer.from([0x00])),
        false,
      )
    })

    it('should reject [0x80] (negative zero)', () => {
      assert.strictEqual(
        ScriptNum.isMinimallyEncoded(Buffer.from([0x80])),
        false,
      )
    })

    it('should accept [0x80, 0x00] (128)', () => {
      assert.strictEqual(
        ScriptNum.isMinimallyEncoded(Buffer.from([0x80, 0x00])),
        true,
      )
    })

    it('should reject [0x01, 0x00] (non-minimal 1)', () => {
      assert.strictEqual(
        ScriptNum.isMinimallyEncoded(Buffer.from([0x01, 0x00])),
        false,
      )
    })
  })

  describe('minimallyEncode', () => {
    it('should not change empty buffer', () => {
      const result = ScriptNum.minimallyEncode(Buffer.alloc(0))
      assert.strictEqual(result.length, 0)
    })

    it('should not change already minimal buffer', () => {
      const buf = Buffer.from([0x05])
      const result = ScriptNum.minimallyEncode(buf)
      assert.deepStrictEqual(result, Buffer.from([0x05]))
    })

    it('should minimize [0x00] to empty', () => {
      const result = ScriptNum.minimallyEncode(Buffer.from([0x00]))
      assert.strictEqual(result.length, 0)
    })
  })

  describe('toNumber', () => {
    it('should return number for small values', () => {
      assert.strictEqual(new ScriptNum(42n).toNumber(), 42)
      assert.strictEqual(new ScriptNum(-42n).toNumber(), -42)
    })

    it('should clamp to MAX_INT for large positive', () => {
      const sn = new ScriptNum(BigInt(2 ** 32))
      assert.strictEqual(sn.toNumber(), 2_147_483_647)
    })

    it('should clamp to MIN_INT for large negative', () => {
      const sn = new ScriptNum(BigInt(-(2 ** 32)))
      assert.strictEqual(sn.toNumber(), -2_147_483_648)
    })
  })

  describe('arithmetic', () => {
    it('should add', () => {
      const a = new ScriptNum(10n)
      const b = new ScriptNum(20n)
      assert.strictEqual(a.add(b).value, 30n)
    })

    it('should subtract', () => {
      const a = new ScriptNum(30n)
      const b = new ScriptNum(20n)
      assert.strictEqual(a.sub(b).value, 10n)
    })

    it('should negate', () => {
      assert.strictEqual(new ScriptNum(5n).negate().value, -5n)
      assert.strictEqual(new ScriptNum(-5n).negate().value, 5n)
      assert.strictEqual(new ScriptNum(0n).negate().value, 0n)
    })

    it('should abs', () => {
      assert.strictEqual(new ScriptNum(-5n).abs().value, 5n)
      assert.strictEqual(new ScriptNum(5n).abs().value, 5n)
    })

    it('should divide', () => {
      assert.strictEqual(new ScriptNum(10n).div(new ScriptNum(3n)).value, 3n)
      assert.strictEqual(
        new ScriptNum(-10n).div(new ScriptNum(3n)).value,
        -3n,
      )
    })

    it('should modulo', () => {
      assert.strictEqual(new ScriptNum(10n).mod(new ScriptNum(3n)).value, 1n)
    })

    it('should detect overflow on add', () => {
      const max = new ScriptNum((1n << 63n) - 1n)
      assert.throws(
        () => max.add(new ScriptNum(1n)),
        (err: Error) => err instanceof ScriptNumError,
      )
    })

    it('should detect overflow on sub', () => {
      const min = new ScriptNum(-(1n << 63n) + 1n)
      assert.throws(
        () => min.sub(new ScriptNum(1n)),
        (err: Error) => err instanceof ScriptNumError,
      )
    })
  })

  describe('mulpow2', () => {
    it('should left shift by 1', () => {
      assert.strictEqual(
        new ScriptNum(5n).mulpow2(new ScriptNum(1n)).value,
        10n,
      )
    })

    it('should right shift by 1', () => {
      assert.strictEqual(
        new ScriptNum(10n).mulpow2(new ScriptNum(-1n)).value,
        5n,
      )
    })

    it('should return 0 for 0 input', () => {
      assert.strictEqual(
        new ScriptNum(0n).mulpow2(new ScriptNum(10n)).value,
        0n,
      )
    })

    it('should return 0 for large right shift', () => {
      assert.strictEqual(
        new ScriptNum(100n).mulpow2(new ScriptNum(-63n)).value,
        0n,
      )
    })

    it('should throw on shift >= 63 for non-zero', () => {
      assert.throws(
        () => new ScriptNum(1n).mulpow2(new ScriptNum(63n)),
        (err: Error) => err instanceof ScriptNumError,
      )
    })

    it('should throw on overflow', () => {
      assert.throws(
        () => new ScriptNum((1n << 62n)).mulpow2(new ScriptNum(2n)),
        (err: Error) => err instanceof ScriptNumError,
      )
    })
  })

  describe('comparisons', () => {
    const a = new ScriptNum(5n)
    const b = new ScriptNum(10n)
    const c = new ScriptNum(5n)

    it('lt', () => {
      assert.strictEqual(a.lt(b), true)
      assert.strictEqual(b.lt(a), false)
      assert.strictEqual(a.lt(c), false)
    })

    it('gt', () => {
      assert.strictEqual(b.gt(a), true)
      assert.strictEqual(a.gt(b), false)
    })

    it('lte', () => {
      assert.strictEqual(a.lte(b), true)
      assert.strictEqual(a.lte(c), true)
      assert.strictEqual(b.lte(a), false)
    })

    it('gte', () => {
      assert.strictEqual(b.gte(a), true)
      assert.strictEqual(a.gte(c), true)
    })

    it('eq', () => {
      assert.strictEqual(a.eq(c), true)
      assert.strictEqual(a.eq(b), false)
    })

    it('neq', () => {
      assert.strictEqual(a.neq(b), true)
      assert.strictEqual(a.neq(c), false)
    })

    it('isZero', () => {
      assert.strictEqual(new ScriptNum(0n).isZero(), true)
      assert.strictEqual(new ScriptNum(1n).isZero(), false)
    })

    it('isNegative', () => {
      assert.strictEqual(new ScriptNum(-1n).isNegative(), true)
      assert.strictEqual(new ScriptNum(0n).isNegative(), false)
      assert.strictEqual(new ScriptNum(1n).isNegative(), false)
    })

    it('should compare with bigint directly', () => {
      assert.strictEqual(a.lt(10n), true)
      assert.strictEqual(a.eq(5n), true)
      assert.strictEqual(a.gt(0n), true)
    })
  })
})

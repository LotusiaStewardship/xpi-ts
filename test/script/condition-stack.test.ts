/**
 * ConditionStack Unit Tests
 *
 * Tests for the optimized IF/ELSE/ENDIF tracking data structure.
 *
 * Reference: lotusd/src/script/interpreter.cpp (ConditionStack)
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { ConditionStack } from '../../lib/bitcore/script/interpreter/condition-stack'

describe('ConditionStack', () => {
  describe('initial state', () => {
    it('should start empty', () => {
      const cs = new ConditionStack()
      assert.strictEqual(cs.isEmpty(), true)
    })

    it('should start with allTrue', () => {
      const cs = new ConditionStack()
      assert.strictEqual(cs.allTrue(), true)
    })
  })

  describe('pushBack', () => {
    it('should not be empty after push', () => {
      const cs = new ConditionStack()
      cs.pushBack(true)
      assert.strictEqual(cs.isEmpty(), false)
    })

    it('should remain allTrue when pushing true', () => {
      const cs = new ConditionStack()
      cs.pushBack(true)
      assert.strictEqual(cs.allTrue(), true)
    })

    it('should not be allTrue when pushing false', () => {
      const cs = new ConditionStack()
      cs.pushBack(false)
      assert.strictEqual(cs.allTrue(), false)
    })

    it('should not be allTrue when false is below true', () => {
      const cs = new ConditionStack()
      cs.pushBack(false)
      cs.pushBack(true)
      assert.strictEqual(cs.allTrue(), false)
    })

    it('should not be allTrue when true is above false', () => {
      const cs = new ConditionStack()
      cs.pushBack(true)
      cs.pushBack(false)
      assert.strictEqual(cs.allTrue(), false)
    })
  })

  describe('popBack', () => {
    it('should be empty after push then pop', () => {
      const cs = new ConditionStack()
      cs.pushBack(true)
      cs.popBack()
      assert.strictEqual(cs.isEmpty(), true)
    })

    it('should restore allTrue after popping false', () => {
      const cs = new ConditionStack()
      cs.pushBack(true)
      cs.pushBack(false)
      assert.strictEqual(cs.allTrue(), false)
      cs.popBack()
      assert.strictEqual(cs.allTrue(), true)
    })

    it('should remain not allTrue if false is still below', () => {
      const cs = new ConditionStack()
      cs.pushBack(false)
      cs.pushBack(true)
      cs.popBack()
      assert.strictEqual(cs.allTrue(), false)
    })

    it('should throw on empty stack', () => {
      const cs = new ConditionStack()
      assert.throws(() => cs.popBack())
    })
  })

  describe('toggleTop', () => {
    it('should toggle true to false', () => {
      const cs = new ConditionStack()
      cs.pushBack(true)
      assert.strictEqual(cs.allTrue(), true)
      cs.toggleTop()
      assert.strictEqual(cs.allTrue(), false)
    })

    it('should toggle false to true', () => {
      const cs = new ConditionStack()
      cs.pushBack(false)
      assert.strictEqual(cs.allTrue(), false)
      cs.toggleTop()
      assert.strictEqual(cs.allTrue(), true)
    })

    it('should handle toggle with false below', () => {
      const cs = new ConditionStack()
      cs.pushBack(false)
      cs.pushBack(true)
      // false below, true on top -> not allTrue
      assert.strictEqual(cs.allTrue(), false)
      cs.toggleTop()
      // false below, false on top -> still not allTrue
      assert.strictEqual(cs.allTrue(), false)
    })

    it('should throw on empty stack', () => {
      const cs = new ConditionStack()
      assert.throws(() => cs.toggleTop())
    })
  })

  describe('nested IF/ELSE/ENDIF simulation', () => {
    it('should handle simple IF true ENDIF', () => {
      const cs = new ConditionStack()
      cs.pushBack(true) // IF true
      assert.strictEqual(cs.allTrue(), true)
      cs.popBack() // ENDIF
      assert.strictEqual(cs.isEmpty(), true)
    })

    it('should handle IF true ELSE ENDIF', () => {
      const cs = new ConditionStack()
      cs.pushBack(true) // IF true
      assert.strictEqual(cs.allTrue(), true)
      cs.toggleTop() // ELSE
      assert.strictEqual(cs.allTrue(), false)
      cs.popBack() // ENDIF
      assert.strictEqual(cs.isEmpty(), true)
    })

    it('should handle IF false ELSE ENDIF', () => {
      const cs = new ConditionStack()
      cs.pushBack(false) // IF false
      assert.strictEqual(cs.allTrue(), false)
      cs.toggleTop() // ELSE
      assert.strictEqual(cs.allTrue(), true)
      cs.popBack() // ENDIF
      assert.strictEqual(cs.isEmpty(), true)
    })

    it('should handle nested IF true IF true ENDIF ENDIF', () => {
      const cs = new ConditionStack()
      cs.pushBack(true) // outer IF
      cs.pushBack(true) // inner IF
      assert.strictEqual(cs.allTrue(), true)
      cs.popBack() // inner ENDIF
      assert.strictEqual(cs.allTrue(), true)
      cs.popBack() // outer ENDIF
      assert.strictEqual(cs.isEmpty(), true)
    })

    it('should handle nested IF true IF false ELSE ENDIF ENDIF', () => {
      const cs = new ConditionStack()
      cs.pushBack(true) // outer IF
      cs.pushBack(false) // inner IF
      assert.strictEqual(cs.allTrue(), false)
      cs.toggleTop() // inner ELSE
      assert.strictEqual(cs.allTrue(), true)
      cs.popBack() // inner ENDIF
      assert.strictEqual(cs.allTrue(), true)
      cs.popBack() // outer ENDIF
      assert.strictEqual(cs.isEmpty(), true)
    })

    it('should handle deeply nested conditions', () => {
      const cs = new ConditionStack()
      // Push 10 true values
      for (let i = 0; i < 10; i++) {
        cs.pushBack(true)
        assert.strictEqual(cs.allTrue(), true)
      }
      // Push one false
      cs.pushBack(false)
      assert.strictEqual(cs.allTrue(), false)
      // Pop the false
      cs.popBack()
      assert.strictEqual(cs.allTrue(), true)
      // Pop all true values
      for (let i = 0; i < 10; i++) {
        cs.popBack()
      }
      assert.strictEqual(cs.isEmpty(), true)
    })
  })
})

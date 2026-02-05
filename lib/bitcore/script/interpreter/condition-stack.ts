/**
 * Copyright 2025-2026 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * Condition Stack for Script IF/ELSE/ENDIF Tracking
 *
 * An optimized data structure that tracks nested conditional execution
 * during script evaluation. Instead of materializing a boolean stack,
 * it tracks only the stack size and the position of the first false
 * value, which is sufficient for all required operations.
 *
 * Reference: lotusd/src/script/interpreter.cpp (ConditionStack)
 *
 * @module ConditionStack
 */

/**
 * Tracks nested IF/ELSE/ENDIF conditional execution state.
 *
 * Conceptually acts like a stack of booleans, one per nesting level.
 * The interpreter only needs to know:
 * 1. Whether the stack is empty (no active conditionals)
 * 2. Whether all values are true (we're in an active branch)
 * 3. Push/pop/toggle operations for IF/ELSE/ENDIF
 *
 * This implementation avoids allocating an actual boolean array by
 * tracking only the size and the position of the first false value.
 */
export class ConditionStack {
  /** Sentinel value indicating no false values exist */
  private static readonly NO_FALSE = 0xffffffff

  /** The size of the implied boolean stack */
  private _size: number = 0

  /** Position of the first false value, or NO_FALSE if all true */
  private _firstFalsePos: number = ConditionStack.NO_FALSE

  /**
   * Check if the condition stack is empty (no active conditionals).
   *
   * @returns true if no IF/ELSE/ENDIF blocks are active
   */
  isEmpty(): boolean {
    return this._size === 0
  }

  /**
   * Check if all conditions on the stack are true.
   *
   * When all conditions are true, the interpreter should execute
   * opcodes normally. When any condition is false, only
   * IF/ELSE/ENDIF opcodes are processed.
   *
   * @returns true if every condition on the stack is true
   */
  allTrue(): boolean {
    return this._firstFalsePos === ConditionStack.NO_FALSE
  }

  /**
   * Push a new condition value (entering an IF/NOTIF block).
   *
   * @param value - The evaluated condition (true = execute this branch)
   */
  pushBack(value: boolean): void {
    if (this._firstFalsePos === ConditionStack.NO_FALSE && !value) {
      // Stack was all-true; this is the first false
      this._firstFalsePos = this._size
    }
    this._size++
  }

  /**
   * Pop the top condition (leaving an ENDIF block).
   *
   * @throws {Error} If the stack is empty
   */
  popBack(): void {
    if (this._size === 0) {
      throw new Error('ConditionStack: pop from empty stack')
    }
    this._size--
    if (this._firstFalsePos === this._size) {
      // Popped the first false value; everything is now true
      this._firstFalsePos = ConditionStack.NO_FALSE
    }
  }

  /**
   * Toggle the top condition value (processing an ELSE block).
   *
   * @throws {Error} If the stack is empty
   */
  toggleTop(): void {
    if (this._size === 0) {
      throw new Error('ConditionStack: toggle on empty stack')
    }
    if (this._firstFalsePos === ConditionStack.NO_FALSE) {
      // All true; toggling top makes it the first false
      this._firstFalsePos = this._size - 1
    } else if (this._firstFalsePos === this._size - 1) {
      // Top is the first false; toggling makes everything true
      this._firstFalsePos = ConditionStack.NO_FALSE
    }
    // Otherwise there's a false below the top; toggling the top
    // is unobservable since we only care about the first false
  }
}

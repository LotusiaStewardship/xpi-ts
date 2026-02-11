/**
 * Preconditions utility module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import { BitcoreError } from '../errors'
import { BufferUtil } from './buffer'

/**
 * Utility class for checking preconditions
 * Provides methods to validate state, arguments, and argument types
 */
export class Preconditions {
  /**
   * Check that a state condition is satisfied
   * @param condition - The condition to check
   * @param message - Error message if condition is false
   * @throws {BitcoreError.Precondition.InvalidState} If condition is false
   */
  static checkState(condition: boolean, message: string): void {
    if (!condition) {
      throw new BitcoreError.Precondition.InvalidState(message)
    }
  }

  /**
   * Check that an argument satisfies a condition
   * @param condition - The condition to check
   * @param argumentName - The name of the argument being checked
   * @param message - Optional error message
   * @param docsPath - Optional documentation path
   * @throws {BitcoreError.Precondition.InvalidArgument} If condition is false
   */
  static checkArgument(
    condition: boolean,
    argumentName: string,
    message?: string,
    docsPath?: string,
  ): void {
    if (!condition) {
      throw new BitcoreError.Precondition.InvalidArgument(
        argumentName,
        message,
        docsPath,
      )
    }
  }

  /**
   * Check that an argument is of the expected type
   * @param argument - The argument to check
   * @param type - The expected type (string name like 'string', 'number', 'Buffer', or a constructor function)
   * @param argumentName - Optional name of the argument for error messages
   * @throws {BitcoreError.Precondition.InvalidArgumentType} If argument is not of the expected type
   */
  static checkArgumentType(
    argument: unknown,
    type: string | ((...args: unknown[]) => unknown),
    argumentName?: string,
  ): void {
    argumentName = argumentName || '(unknown name)'
    if (typeof type === 'string') {
      // Special case for Buffer type since typeof Buffer returns 'object'
      if (type === 'Buffer') {
        if (!BufferUtil.isBuffer(argument)) {
          throw new BitcoreError.Precondition.InvalidArgumentType(
            argument,
            type,
            argumentName,
          )
        }
      } else if (typeof argument !== type) {
        // Check primitive types like 'string', 'number', 'boolean', etc.
        throw new BitcoreError.Precondition.InvalidArgumentType(
          argument,
          type,
          argumentName,
        )
      }
    } else {
      // Handle constructor/class type checking using instanceof
      // This allows checking against custom classes like PublicKey, Script, etc.
      if (!(argument instanceof type)) {
        throw new BitcoreError.Precondition.InvalidArgumentType(
          argument,
          type.name,
          argumentName,
        )
      }
    }
  }
}

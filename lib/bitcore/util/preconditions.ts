/**
 * Preconditions utility module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import { BitcoreError } from '../errors.js'

export class Preconditions {
  static checkState(condition: boolean, message: string): void {
    if (!condition) {
      throw new BitcoreError.Precondition.InvalidState(message)
    }
  }

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

  static checkArgumentType(
    argument: unknown,
    type: string | ((...args: unknown[]) => unknown),
    argumentName?: string,
  ): void {
    argumentName = argumentName || '(unknown name)'
    if (typeof type === 'string') {
      if (type === 'Buffer') {
        if (!Buffer.isBuffer(argument)) {
          throw new BitcoreError.Precondition.InvalidArgumentType(
            argument,
            type,
            argumentName,
          )
        }
      } else if (typeof argument !== type) {
        throw new BitcoreError.Precondition.InvalidArgumentType(
          argument,
          type,
          argumentName,
        )
      }
    } else {
      // Handle constructor/class type checking
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

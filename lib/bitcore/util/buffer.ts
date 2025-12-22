/**
 * Buffer utility module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import { Preconditions } from './preconditions.js'

export class BufferUtil {
  /**
   * Fill a buffer with a value.
   *
   * @param buffer Buffer to fill
   * @param value Value to fill with
   * @return Buffer
   */
  static fill(buffer: Buffer, value: number): Buffer {
    Preconditions.checkArgumentType(buffer, 'Buffer', 'buffer')
    Preconditions.checkArgumentType(value, 'number', 'value')
    const length = buffer.length
    for (let i = 0; i < length; i++) {
      buffer[i] = value
    }
    return buffer
  }

  /**
   * Return a copy of a buffer
   *
   * @param original Original buffer
   * @return Buffer
   */
  static copy(original: Buffer): Buffer {
    const buffer = Buffer.alloc(original.length)
    original.copy(buffer)
    return buffer
  }

  /**
   * Returns true if the given argument is an instance of a buffer. Tests for
   * both node's Buffer and Uint8Array
   *
   * @param arg Argument to test
   * @return boolean
   */
  static isBuffer(arg: unknown): arg is Buffer | Uint8Array {
    return Buffer.isBuffer(arg) || arg instanceof Uint8Array
  }

  /**
   * Returns a zero-filled byte array
   *
   * @param bytes Number of bytes
   * @return Buffer
   */
  static emptyBuffer(bytes: number): Buffer {
    Preconditions.checkArgumentType(bytes, 'number', 'bytes')
    const result = Buffer.alloc(bytes)
    for (let i = 0; i < bytes; i++) {
      result.write('\0', i)
    }
    return result
  }

  /**
   * Concatenates buffers
   *
   * Shortcut for Buffer.concat
   */
  static concat(list: ReadonlyArray<Buffer>, totalLength?: number): Buffer {
    return Buffer.concat(list, totalLength)
  }

  /**
   * Check if two buffers are equal
   */
  static equals(a: Buffer, b: Buffer): boolean {
    if (a.length !== b.length) {
      return false
    }
    const length = a.length
    for (let i = 0; i < length; i++) {
      if (a[i] !== b[i]) {
        return false
      }
    }
    return true
  }

  /**
   * Alias for equals
   */
  static equal(a: Buffer, b: Buffer): boolean {
    return BufferUtil.equals(a, b)
  }

  /**
   * Transforms a number from 0 to 255 into a Buffer of size 1 with that value
   *
   * @param integer Number to convert
   * @return Buffer
   */
  static integerAsSingleByteBuffer(integer: number): Buffer {
    Preconditions.checkArgumentType(integer, 'number', 'integer')
    return Buffer.from([integer & 0xff])
  }

  /**
   * Transform a 4-byte integer into a Buffer of length 4.
   *
   * @param integer Number to convert
   * @return Buffer
   */
  static integerAsBuffer(integer: number): Buffer {
    Preconditions.checkArgumentType(integer, 'number', 'integer')
    const bytes: number[] = []
    bytes.push((integer >> 24) & 0xff)
    bytes.push((integer >> 16) & 0xff)
    bytes.push((integer >> 8) & 0xff)
    bytes.push(integer & 0xff)
    return Buffer.from(bytes)
  }

  /**
   * Transform the first 4 values of a Buffer into a number, in little endian encoding
   *
   * @param buffer Buffer to convert
   * @return number
   */
  static integerFromBuffer(buffer: Buffer): number {
    Preconditions.checkArgumentType(buffer, 'Buffer', 'buffer')
    return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]
  }

  /**
   * Transforms the first byte of an array into a number ranging from -128 to 127
   * @param buffer Buffer to convert
   * @return number
   */
  static integerFromSingleByteBuffer(buffer: Buffer): number {
    Preconditions.checkArgumentType(buffer, 'Buffer', 'buffer')
    return buffer[0]
  }

  /**
   * Transforms a buffer into a string with a number in hexa representation
   *
   * Shorthand for buffer.toString('hex')
   *
   * @param buffer Buffer to convert
   * @return string
   */
  static bufferToHex(buffer: Buffer): string {
    Preconditions.checkArgumentType(buffer, 'Buffer', 'buffer')
    return buffer.toString('hex')
  }

  /**
   * Reverse a buffer
   * @param param Buffer to reverse
   * @return Buffer
   */
  static reverse(param: Buffer): Buffer {
    return Buffer.from(param).reverse()
  }
}

// Constants
export const NULL_HASH = BufferUtil.fill(Buffer.alloc(32), 0)
export const EMPTY_BUFFER = Buffer.alloc(0)

/**
 * Buffer utility module
 * Provides helper functions for working with Buffer objects
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */
import { Buffer } from 'buffer/'
export class BufferUtil {
  /** Re-export Buffer class for convenience */
  static Buffer: typeof Buffer = Buffer
  /**
   * Fill a buffer with a value.
   *
   * @param buffer Buffer to fill
   * @param value Value to fill with
   * @return Buffer
   */
  static fill(buffer: Buffer, value: number): Buffer {
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
    const result = Buffer.alloc(bytes)
    for (let i = 0; i < bytes; i++) {
      result.write('\0', i)
    }
    return result
  }

  /**
   * Allocates a new buffer of the specified size.
   *
   * @param size - The desired length of the new buffer in bytes
   * @param fill - Optional value to fill the buffer with (default: 0)
   * @returns A new buffer of the specified size, filled with the specified value or zeros
   */
  static alloc(size: number, fill?: string | number | Buffer): Buffer {
    return Buffer.alloc(size, fill)
  }

  /**
   * Concatenates buffers
   *
   * Shortcut for Buffer.concat
   */
  static concat(list: ReadonlyArray<Buffer>, totalLength?: number): Buffer {
    return Buffer.concat(list as Buffer[], totalLength)
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
    return Buffer.from([integer & 0xff])
  }

  /**
   * Converts a number to a 4-byte big-endian buffer representation.
   *
   * @param integer - Number to convert (32-bit integer)
   * @returns Buffer of length 4 containing the big-endian representation
   */
  static integerAsBuffer(integer: number): Buffer {
    const bytes: number[] = []
    bytes.push((integer >> 24) & 0xff)
    bytes.push((integer >> 16) & 0xff)
    bytes.push((integer >> 8) & 0xff)
    bytes.push(integer & 0xff)
    return Buffer.from(bytes)
  }

  /**
   * Converts a 4-byte big-endian buffer to a 32-bit integer.
   *
   * @param buffer - Buffer to convert (must be at least 4 bytes)
   * @returns The 32-bit integer value
   */
  static integerFromBuffer(buffer: Buffer): number {
    return (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3]
  }

  /**
   * Transforms the first byte of an array into a number ranging from -128 to 127
   * @param buffer Buffer to convert
   * @return number
   */
  static integerFromSingleByteBuffer(buffer: Buffer): number {
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
  /**
   * Allocates a new Buffer using an {array} of octets.
   *
   * @param array
   */
  static from(array: any[]): Buffer
  /**
   * When passed a reference to the .buffer property of a TypedArray instance,
   * the newly created Buffer will share the same allocated memory as the TypedArray.
   * The optional {byteOffset} and {length} arguments specify a memory range
   * within the {arrayBuffer} that will be shared by the Buffer.
   *
   * @param arrayBuffer The .buffer property of a TypedArray or a new ArrayBuffer()
   * @param byteOffset
   * @param length
   */
  static from(
    arrayBuffer: ArrayBuffer,
    byteOffset?: number,
    length?: number,
  ): Buffer
  /**
   * Copies the passed {buffer} data onto a new Buffer instance.
   *
   * @param buffer
   */
  static from(buffer: Buffer | Uint8Array): Buffer
  /**
   * Creates a new Buffer containing the given JavaScript string {str}.
   * If provided, the {encoding} parameter identifies the character encoding.
   * If not provided, {encoding} defaults to 'utf8'.
   *
   * @param str
   */
  static from(str: string, encoding?: BufferEncoding): Buffer
  /**
   * Creates a new Buffer from the given input.
   *
   * This method provides a unified interface for creating buffers from various input types:
   * - Arrays of octets (numbers 0-255)
   * - ArrayBuffer with optional byte offset and length
   * - Existing Buffer or Uint8Array (creates a copy)
   * - Strings with optional encoding
   *
   * @param data - The input data to create a buffer from
   * @param byteOffsetOrEncoding - Byte offset for ArrayBuffer, or encoding for string
   * @param length - Length for ArrayBuffer slice
   * @returns A new Buffer instance
   *
   * @example
   * // From array of octets
   * BufferUtil.from([0x48, 0x65, 0x6c, 0x6c, 0x6f])
   *
   * @example
   * // From string with encoding
   * BufferUtil.from('hello', 'utf8')
   *
   * @example
   * // From ArrayBuffer with offset and length
   * BufferUtil.from(arrayBuffer, 0, 10)
   */
  static from(
    data: any[] | ArrayBuffer | Buffer | Uint8Array | string,
    byteOffsetOrEncoding?: number | BufferEncoding,
    length?: number,
  ): Buffer {
    if (Array.isArray(data)) {
      return Buffer.from(data)
    }
    if (typeof data === 'string') {
      return Buffer.from(
        data,
        (byteOffsetOrEncoding || 'utf8') as BufferEncoding,
      )
    }
    if (data instanceof ArrayBuffer) {
      return Buffer.from(data, byteOffsetOrEncoding as number, length)
    }
    return Buffer.from(data)
  }

  /**
   * Compare two buffers byte-by-byte.
   *
   * Performs a lexicographic comparison of two buffers, comparing each byte
   * sequentially until a difference is found or one buffer ends.
   *
   * @param buf1 - First buffer to compare
   * @param buf2 - Second buffer to compare
   * @returns 0 if buffers are equal, -1 if buf1 < buf2, 1 if buf1 > buf2
   *
   * @example
   * // Equal buffers
   * BufferUtil.compare(Buffer.from([1, 2, 3]), Buffer.from([1, 2, 3])) // returns 0
   *
   * @example
   * // First buffer is less
   * BufferUtil.compare(Buffer.from([1, 2]), Buffer.from([1, 3])) // returns -1
   *
   * @example
   * // First buffer is greater
   * BufferUtil.compare(Buffer.from([1, 3]), Buffer.from([1, 2])) // returns 1
   */
  static compare(buf1: Uint8Array, buf2: Uint8Array): number {
    return Buffer.compare(buf1, buf2)
  }
}

// Constants
export const NULL_HASH = BufferUtil.fill(Buffer.alloc(32), 0)
export const EMPTY_BUFFER = Buffer.alloc(0)

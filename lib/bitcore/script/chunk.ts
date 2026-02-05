import type { Buffer } from 'buffer/'

/**
 * Chunk class for script operations
 * Represents a single chunk in a Lotus script.
 * A chunk can either be an opcode (no data) or a data push operation.
 * Migrated from bitcore-lib-xpi with ESM support
 */
export class Chunk {
  /**
   * Optional data buffer for push operations
   */
  buf?: Buffer

  /**
   * Length of the data buffer
   */
  len?: number

  /**
   * The opcode number for this chunk
   * For data pushes, this indicates the push operation type
   */
  opcodenum: number

  /**
   * Create a new Chunk instance
   * @param data - Optional initialization data
   * @param data.buf - Data buffer for push operations
   * @param data.len - Length of the data buffer
   * @param data.opcodenum - The opcode number
   */
  constructor(data?: { buf?: Buffer; len?: number; opcodenum: number }) {
    if (data) {
      this.buf = data.buf
      this.len = data.len
      this.opcodenum = data.opcodenum
    } else {
      this.opcodenum = 0
    }
  }

  /**
   * Check if this chunk is an opcode (no data)
   * @returns True if this chunk represents an opcode without data
   */
  isOpCode(): boolean {
    return !this.buf && this.opcodenum !== undefined
  }

  /**
   * Check if this chunk contains data
   * @returns True if this chunk has an associated data buffer
   */
  hasData(): boolean {
    return !!this.buf
  }

  /**
   * Get the length of the data buffer
   * @returns The length of the data buffer, or 0 if no buffer exists
   */
  getLength(): number {
    return this.len || 0
  }

  /**
   * Get the data buffer
   * @returns The data buffer, or undefined if this is an opcode-only chunk
   */
  getBuffer(): Buffer | undefined {
    return this.buf
  }

  /**
   * Get the opcode number
   * @returns The opcode number for this chunk
   */
  getOpCode(): number {
    return this.opcodenum
  }

  /**
   * Convert to string representation
   * @returns String representation of the chunk (opcode name or hex data)
   */
  toString(): string {
    if (this.isOpCode()) {
      return `OP_${this.opcodenum}`
    } else if (this.buf) {
      return this.buf.toString('hex')
    }
    return ''
  }

  /**
   * Convert to object representation
   * @returns Plain object containing chunk properties
   */
  toObject(): { buf?: Buffer; len?: number; opcodenum: number } {
    return {
      buf: this.buf,
      len: this.len,
      opcodenum: this.opcodenum,
    }
  }
}

/**
 * Chunk class for script operations
 * Represents a single chunk in a Bitcoin script
 * Migrated from bitcore-lib-xpi with ESM support
 */

export class Chunk {
  buf?: Buffer
  len?: number
  opcodenum: number

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
   */
  isOpCode(): boolean {
    return !this.buf && this.opcodenum !== undefined
  }

  /**
   * Check if this chunk contains data
   */
  hasData(): boolean {
    return !!this.buf
  }

  /**
   * Get the length of the data buffer
   */
  getLength(): number {
    return this.len || 0
  }

  /**
   * Get the data buffer
   */
  getBuffer(): Buffer | undefined {
    return this.buf
  }

  /**
   * Get the opcode number
   */
  getOpCode(): number {
    return this.opcodenum
  }

  /**
   * Convert to string representation
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
   * Convert to object
   */
  toObject(): { buf?: Buffer; len?: number; opcodenum: number } {
    return {
      buf: this.buf,
      len: this.len,
      opcodenum: this.opcodenum,
    }
  }
}

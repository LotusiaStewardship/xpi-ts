/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */
import OpCode from './opcode.js'
import { Script } from '../bitcore/script.js'

/**
 * Check provided script for OP_RETURN op code
 * @param script - The script to check, as a `Buffer` or hex `string`
 * @returns true if the output is an OP_RETURN, false otherwise
 */
export function isOpReturn(script: Buffer | string): boolean {
  if (typeof script === 'string') {
    script = Buffer.from(script, 'hex')
  }
  return script.readUInt8(0) === OpCode.OP_RETURN
}

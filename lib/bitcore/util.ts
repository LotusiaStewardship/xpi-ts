/**
 * Utility functions namespace
 * Migrated from bitcore-lib-xpi with ESM support
 *
 * This module provides a namespace for utility functions,
 * organizing them by category to match the reference implementation.
 */

import { BufferUtil } from './util/buffer.js'
import { JSUtil } from './util/js.js'
import { Preconditions } from './util/preconditions.js'
import { Base32 } from './util/base32.js'
import { convertBits } from './util/convertBits.js'

export const util = {
  buffer: BufferUtil,
  js: JSUtil,
  $: Preconditions,
  base32: Base32,
  convertBits: convertBits,
}

// Export individual utilities for convenience
export { BufferUtil, JSUtil, Preconditions, Base32, convertBits }

/**
 * Convert bits utility
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

import { Preconditions } from './preconditions.js'

/**
 * Converts an array of integers made up of `from` bits into an
 * array of integers made up of `to` bits. The output array is
 * zero-padded if necessary, unless strict mode is true.
 * Original by Pieter Wuille: https://github.com/sipa/bech32.
 *
 * @param data Array of integers made up of `from` bits.
 * @param from Length in bits of elements in the input array.
 * @param to Length in bits of elements in the output array.
 * @param strict Require the conversion to be completed without padding.
 */
export function convertBits(
  data: number[],
  from: number,
  to: number,
  strict: boolean = false,
): number[] {
  let accumulator = 0
  let bits = 0
  const result: number[] = []
  const mask = (1 << to) - 1

  for (let i = 0; i < data.length; i++) {
    const value = data[i]
    Preconditions.checkArgument(
      !(value < 0 || value >> from !== 0),
      'value',
      `value ${value}`,
    )

    accumulator = (accumulator << from) | value
    bits += from
    while (bits >= to) {
      bits -= to
      result.push((accumulator >> bits) & mask)
    }
  }

  if (!strict) {
    if (bits > 0) {
      result.push((accumulator << (to - bits)) & mask)
    }
  } else {
    Preconditions.checkState(
      !(bits >= from || (accumulator << (to - bits)) & mask),
      'Conversion requires padding but strict mode was used',
    )
  }

  return result
}

/**
 * Unit implementation for Lotus
 * Migrated from bitcore-lib-xpi with ESM support and BigInt
 */

import { BN } from './crypto/bn.js'
import { BitcoreError } from './errors.js'
import { Preconditions } from './util/preconditions.js'

/**
 * Unit definitions for XPI (Lotus) amounts.
 *
 * The `UNITS` object maps unit codes to an array of two numbers:
 *   [factor, decimals], where:
 *     - `factor` is the number of satoshis ("base units") in one of the given unit.
 *     - `decimals` is the number of decimal places typically displayed for the unit.
 *
 * Units:
 *   - XPI:       1,000,000 satoshis per XPI (6 decimal places)
 *   - mXPI:      1,000 satoshis per mXPI (3 decimal places)
 *   - uXPI:      100 satoshis per uXPI (2 decimal places)
 *   - bits:      100 satoshis per bit (synonym for uXPI, 2 decimal places)
 *   - satoshis:  1 satoshi per satoshi (0 decimal places)
 */
const UNITS = {
  XPI: [1e6, 6],
  mXPI: [1e3, 3],
  uXPI: [1e2, 2],
  bits: [1e2, 2], // bits is an alias for uXPI
  satoshis: [1, 0],
} as const

export interface UnitData {
  amount: number
  code: string
}

export type UnitCode = keyof typeof UNITS

/**
 * Utility for handling and converting Lotus XPI units. The supported units are
 * XPI, mXPI, bits (also named uXPI) and satoshis. A unit instance can be created with an
 * amount and a unit code, or alternatively using static methods like {fromXPI}.
 * It also allows to be created from a fiat amount and the exchange rate, or
 * alternatively using the {fromFiat} static method.
 * You can consult for different representation of a unit instance using it's
 * {to} method, the fixed unit methods like {toSatoshis} or alternatively using
 * the unit accessors. It also can be converted to a fiat amount by providing the
 * corresponding XPI/fiat exchange rate.
 *
 * @example
 * ```javascript
 * var sats = Unit.fromXPI(1.3).toSatoshis();
 * var mili = Unit.fromBits(1.3).to(Unit.mXPI);
 * var bits = Unit.fromFiat(1.3, 350).bits;
 * var xpi = new Unit(1.3, Unit.bits).XPI;
 * ```
 *
 * @param {Number} amount - The amount to be represented
 * @param {String|Number} code - The unit of the amount or the exchange rate
 * @returns {Unit} A new instance of an Unit
 * @constructor
 */
export class Unit {
  private _value!: bigint

  // Unit constants
  static readonly XPI = 'XPI'
  static readonly mXPI = 'mXPI'
  static readonly uXPI = 'uXPI'
  static readonly bits = 'bits'
  static readonly satoshis = 'satoshis'

  constructor(amount: number, code: UnitCode | number) {
    // convert fiat to XPI
    if (typeof code === 'number') {
      if (code <= 0) {
        throw new Error(`Invalid exchange rate: ${code}`)
      }
      amount = amount / code
      code = Unit.XPI
    }

    this._value = this._from(amount, code as UnitCode)

    // Define getters for each unit
    Object.keys(UNITS).forEach(key => {
      Object.defineProperty(this, key, {
        get: () => this.to(key as UnitCode),
        enumerable: true,
      })
    })
  }

  /**
   * Returns a Unit instance created from JSON string or object
   *
   * @param {Object} data - Object with keys: amount and code
   * @returns {Unit} A Unit instance
   */
  static fromObject(data: UnitData): Unit {
    Preconditions.checkArgument(
      typeof data === 'object',
      'data',
      'Argument is expected to be an object',
    )
    return new Unit(data.amount, data.code as UnitCode)
  }

  /**
   * Returns a Unit instance created from an amount in XPI
   *
   * @param {Number} amount - The amount in XPI
   * @returns {Unit} A Unit instance
   */
  static fromXPI(amount: number): Unit {
    return new Unit(amount, Unit.XPI)
  }

  /**
   * Returns a Unit instance created from an amount in mXPI
   *
   * @param {Number} amount - The amount in mXPI
   * @returns {Unit} A Unit instance
   */
  static fromMillis(amount: number): Unit {
    return new Unit(amount, Unit.mXPI)
  }

  /**
   * Alias for fromMillis
   */
  static fromMilis = Unit.fromMillis

  /**
   * Returns a Unit instance created from an amount in bits
   *
   * @param {Number} amount - The amount in bits
   * @returns {Unit} A Unit instance
   */
  static fromMicros(amount: number): Unit {
    return new Unit(amount, Unit.bits)
  }

  /**
   * Alias for fromMicros
   */
  static fromBits = Unit.fromMicros

  /**
   * Returns a Unit instance created from an amount in satoshis
   *
   * @param {Number|bigint} amount - The amount in satoshis
   * @returns {Unit} A Unit instance
   */
  static fromSatoshis(amount: number | bigint): Unit {
    if (typeof amount === 'bigint') {
      return new Unit(Number(amount), Unit.satoshis)
    }
    return new Unit(amount, Unit.satoshis)
  }

  /**
   * Returns a Unit instance created from a fiat amount and exchange rate.
   *
   * @param {Number} amount - The amount in fiat
   * @param {Number} rate - The exchange rate XPI/fiat
   * @returns {Unit} A Unit instance
   */
  static fromFiat(amount: number, rate: number): Unit {
    return new Unit(amount, rate)
  }

  private _from(amount: number, code: UnitCode): bigint {
    if (!UNITS[code]) {
      throw new Error(`Unrecognized unit code: ${code}`)
    }
    return BigInt(Math.round(amount * UNITS[code][0]))
  }

  /**
   * Returns the value represented in the specified unit
   *
   * @param {String|Number} code - The unit code or exchange rate
   * @returns {Number} The converted value
   */
  to(code: UnitCode | number): number {
    if (typeof code === 'number') {
      if (code <= 0) {
        throw new Error(`Invalid exchange rate: ${code}`)
      }
      return parseFloat((this.to(Unit.XPI) * code).toFixed(2))
    }

    if (!UNITS[code]) {
      throw new Error(`Unrecognized unit code: ${code}`)
    }

    // Use BigInt division for better precision, then convert to Number
    const divisor = BigInt(UNITS[code][0])
    const value = Number(this._value) / Number(divisor)
    return parseFloat(value.toFixed(UNITS[code][1]))
  }

  /**
   * Returns the value represented in XPI
   *
   * @returns {Number} The value converted to XPI
   */
  toXPI(): number {
    return this.to(Unit.XPI)
  }

  /**
   * Returns the value represented in mXPI
   *
   * @returns {Number} The value converted to mXPI
   */
  toMillis(): number {
    return this.to(Unit.mXPI)
  }

  /**
   * Alias for toMillis
   */
  toMilis = this.toMillis

  /**
   * Returns the value represented in bits
   *
   * @returns {Number} The value converted to bits
   */
  toMicros(): number {
    return this.to(Unit.bits)
  }

  /**
   * Alias for toMicros
   */
  toBits = this.toMicros

  /**
   * Returns the value represented in satoshis
   *
   * @returns {bigint} The value converted to satoshis
   */
  toSatoshis(): bigint {
    return this._value
  }

  /**
   * Returns the value represented in fiat
   *
   * @param {number} rate - The exchange rate between XPI/currency
   * @returns {Number} The value converted to fiat
   */
  atRate(rate: number): number {
    return this.to(rate)
  }

  /**
   * Returns a the string representation of the value in satoshis
   *
   * @returns {string} the value in satoshis
   */
  toString(): string {
    return this._value.toString() + ' satoshis'
  }

  /**
   * Returns a plain object representation of the Unit
   *
   * @returns {Object} An object with the keys: amount and code
   */
  toObject(): UnitData {
    return {
      amount: this.to(Unit.XPI),
      code: Unit.XPI,
    }
  }

  /**
   * Alias for toObject
   */
  toJSON = this.toObject

  /**
   * Returns a string formatted for the console
   *
   * @returns {string} the value in satoshis
   */
  inspect(): string {
    return '<Unit: ' + this.toString() + '>'
  }
}

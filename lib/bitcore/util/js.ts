/**
 * JavaScript utility functions
 * Migrated from bitcore-lib-xpi with ESM support
 */

export class JSUtil {
  /**
   * Determines whether a string contains only hexadecimal values
   */
  static isHexa(value: string): boolean {
    if (typeof value !== 'string') {
      return false
    }
    return /^[0-9a-fA-F]+$/.test(value)
  }

  static isHexaString(str: string): boolean {
    return typeof str === 'string' && /^[0-9a-fA-F]+$/.test(str)
  }

  /**
   * Test if an argument is a valid JSON object
   */
  static isValidJSON(arg: string): boolean {
    if (typeof arg !== 'string') {
      return false
    }
    try {
      const parsed = JSON.parse(arg)
      return typeof parsed === 'object'
    } catch (e) {
      return false
    }
  }

  /**
   * Clone an array
   */
  static cloneArray<T>(arr: T[]): T[] {
    return [...arr]
  }

  /**
   * Check if a value is a natural number
   */
  static isNaturalNumber(value: unknown): boolean {
    return (
      (typeof value === 'number' &&
        isFinite(value) &&
        Math.floor(value) === value &&
        value >= 0) ||
      (typeof value === 'string' && /^[0-9]+$/.test(value)) ||
      (typeof value === 'bigint' && value >= 0n)
    )
  }

  /**
   * Define immutable properties on an object
   */
  static defineImmutable(
    obj: object,
    properties: Record<string, unknown>,
  ): object {
    Object.keys(properties).forEach(key => {
      Object.defineProperty(obj, key, {
        value: properties[key],
        writable: false,
        enumerable: true,
        configurable: false,
      })
    })
    return obj
  }
}

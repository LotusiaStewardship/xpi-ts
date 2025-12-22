/**
 * URI class for Lotus URI handling
 * Migrated from bitcore-lib-xpi with ESM support
 */

import { Address } from './address.js'
import { Unit } from './unit.js'
import { JSUtil } from './util/js.js'

// Default prefix for Lotus URI
const DEFAULT_PREFIX = 'giveto:'
const URI_PREFIXES = [DEFAULT_PREFIX]

export interface URIParams {
  address?: string
  amount?: number
  label?: string
  message?: string
  [key: string]: string | number | undefined
}

export class URI {
  private _address?: Address
  private _amount?: number
  private _label?: string
  private _message?: string
  private _otherParams: Record<string, string> = {}

  constructor(data: string | URIParams, knownParams?: string[]) {
    if (typeof data === 'string') {
      this._fromString(data, knownParams)
    } else if (typeof data === 'object') {
      this._fromObject(data)
    } else {
      throw new Error('Invalid URI data')
    }
  }

  /**
   * Create URI from string
   */
  static fromString(data: string): URI {
    return new URI(data)
  }

  /**
   * Create URI from object
   */
  static fromObject(data: URIParams): URI {
    return new URI(data)
  }

  /**
   * Check if URI is valid
   */
  static isValid(data: string | URIParams, knownParams?: string[]): boolean {
    try {
      new URI(data, knownParams)
      return true
    } catch (e) {
      return false
    }
  }

  private _fromString(uriString: string, knownParams?: string[]): void {
    const index = URI_PREFIXES.findIndex(prefix => uriString.startsWith(prefix))
    if (index === -1) {
      throw new Error('Invalid Lotus URI')
    }
    const prefix = URI_PREFIXES[index]
    const uri = uriString.substring(prefix.length) // Remove 'giveto:' prefix
    const parts = uri.split('?')

    if (parts.length === 0) {
      throw new Error('Invalid Lotus URI format')
    }

    // Parse address
    const addressPart = parts[0]
    if (addressPart) {
      try {
        this._address = Address.fromString(addressPart)
      } catch (e) {
        throw new Error('Invalid Lotus address in URI')
      }
    }

    // Parse query parameters
    if (parts.length > 1) {
      const queryString = parts[1]
      const params = new URLSearchParams(queryString)

      for (const [key, value] of params) {
        switch (key) {
          case 'amount':
            this._amount = parseFloat(value)
            break
          case 'label':
            this._label = decodeURIComponent(value)
            break
          case 'message':
            this._message = decodeURIComponent(value)
            break
          default:
            if (!knownParams || knownParams.includes(key)) {
              this._otherParams[key] = decodeURIComponent(value)
            }
            break
        }
      }
    }
  }

  private _fromObject(data: URIParams): void {
    if (data.address) {
      try {
        this._address = Address.fromString(data.address)
      } catch (e) {
        throw new Error('Invalid Lotus address')
      }
    }

    if (data.amount !== undefined) {
      this._amount = data.amount
    }

    if (data.label) {
      this._label = data.label
    }

    if (data.message) {
      this._message = data.message
    }

    // Store other parameters
    Object.keys(data).forEach(key => {
      if (!['address', 'amount', 'label', 'message'].includes(key)) {
        this._otherParams[key] = String(data[key])
      }
    })
  }

  /**
   * Get the address
   */
  get address(): Address | undefined {
    return this._address
  }

  /**
   * Get the amount
   */
  get amount(): number | undefined {
    return this._amount
  }

  /**
   * Get the label
   */
  get label(): string | undefined {
    return this._label
  }

  /**
   * Get the message
   */
  get message(): string | undefined {
    return this._message
  }

  /**
   * Get other parameters
   */
  get otherParams(): Record<string, string> {
    return { ...this._otherParams }
  }

  /**
   * Convert to string
   */
  toString(prefix?: string): string {
    if (!this._address) {
      throw new Error('Cannot convert URI to string without address')
    }

    if (prefix && !URI_PREFIXES.includes(prefix)) {
      throw new Error('Invalid URI prefix specified')
    }

    let uri = `${prefix ?? DEFAULT_PREFIX}${this._address.toString()}`
    const params: string[] = []

    if (this._amount !== undefined) {
      params.push(`amount=${this._amount}`)
    }

    if (this._label) {
      params.push(`label=${encodeURIComponent(this._label)}`)
    }

    if (this._message) {
      params.push(`message=${encodeURIComponent(this._message)}`)
    }

    // Add other parameters
    Object.keys(this._otherParams).forEach(key => {
      params.push(`${key}=${encodeURIComponent(this._otherParams[key])}`)
    })

    if (params.length > 0) {
      uri += '?' + params.join('&')
    }

    return uri
  }

  /**
   * Convert to object
   */
  toObject(): URIParams {
    const obj: URIParams = {}

    if (this._address) {
      obj.address = this._address.toString()
    }

    if (this._amount !== undefined) {
      obj.amount = this._amount
    }

    if (this._label) {
      obj.label = this._label
    }

    if (this._message) {
      obj.message = this._message
    }

    // Add other parameters
    Object.keys(this._otherParams).forEach(key => {
      obj[key] = this._otherParams[key]
    })

    return obj
  }
}

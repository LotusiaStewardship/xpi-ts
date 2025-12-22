/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */
/**
 * Validate a sha256 hash
 * @param str - The sha256 hash to validate
 * @returns Whether the sha256 hash is valid
 */
export function isSha256(str: string) {
  return isHex(str, 64)
}

/**
 * Convert a number or UTF-8 string to a hex string
 * @param data - The data to convert
 * @returns The hex string
 */
export function toHex(data: number | string | Buffer) {
  switch (typeof data) {
    case 'number':
      return data.toString(16).padStart(2, '0')
    case 'string':
      return Buffer.from(data, 'utf8').toString('hex')
    case 'object':
      if (data instanceof Buffer) {
        return data.toString('hex')
      }
  }
  throw new Error('Invalid data type')
}

/**
 * Check if a string is hex-encoded, with optional `length` limit
 * @param str The string to check
 * @param length The length of the hex string to check. If not defined, checks the full string
 * @returns `true` if the string is hex-encoded, `false` otherwise
 */
export function isHex(str: string, length?: number): boolean {
  const regexStr = length ? `^[a-fA-F0-9]{${length}}$` : '^[a-fA-F0-9]+$'
  return new RegExp(regexStr).test(str)
}

/**
 * Check if a string is base64 encoded
 * @param str The string to check
 * @returns `true` if the string is base64 encoded, `false` otherwise
 */
export function isBase64(str: string): boolean {
  return new RegExp('^[a-zA-Z0-9+/]+={0,2}$').test(str)
}

/**
 * Decode a base64-encoded string
 * @param str The base64 encoded string to decode
 * @returns The decoded string
 */
export function decodeBase64(str: string) {
  if (!isBase64(str)) {
    throw new Error('Invalid base64 string')
  }
  return Buffer.from(str, 'base64').toString('utf8')
}

/**
 * Encode a UTF-8 string to a base64-encoded string. Optionally provide a different
 * encoding scheme for the input string
 * @param str The string to encode
 * @returns The base64 encoded string
 */
export function encodeBase64(str: string, encoding: BufferEncoding = 'utf8') {
  if (!new TextDecoder('utf8').decode(Buffer.from(str, encoding))) {
    throw new Error('Not a valid UTF-8 string')
  }
  return Buffer.from(str, encoding).toString('base64')
}

/**
 * Truncate a sha256 hash to 16 + 6 characters
 * @param sha256 - The sha256 hash to truncate
 * @returns The truncated sha256 hash
 */
export function truncateSha256(sha256: string) {
  return sha256.slice(0, 16) + '...' + sha256.slice(-6)
}

/**
 * Truncate a transaction id to 16 + 6 characters
 * @param txid - The transaction id to truncate
 * @returns The truncated transaction id
 */
export function truncateTxid(txid: string) {
  return txid.slice(0, 16) + '...' + txid.slice(-6)
}

/**
 * Truncate an address to 17 + 6 characters
 * @param address - The address to truncate
 * @returns The truncated address
 */
export function truncateAddress(address: string) {
  return address.slice(0, 17) + '...' + address.slice(-6)
}

/**
 * Truncate a block hash to 1 + 16 characters
 * @param blockHash - The block hash to truncate
 * @returns The truncated block hash
 */
export function truncateBlockHash(blockHash: string) {
  return blockHash.slice(0, 1) + '...' + blockHash.slice(-16)
}

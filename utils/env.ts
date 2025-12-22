/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */
/**
 * Check if running in a browser environment
 *
 * @returns true if running in browser, false if running in Node.js
 */
export function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined'
}

/**
 * Check if running in Node.js environment
 *
 * @returns true if running in Node.js, false if running in browser
 */
export function isNode(): boolean {
  return !!(
    typeof process !== 'undefined' &&
    process.versions &&
    process.versions.node
  )
}

/**
 * Word lists for BIP39 mnemonic generation
 * Migrated from @abcpros/bitcore-mnemonic with ESM support and TypeScript
 */

import { english } from './english.js'
import { french } from './french.js'

// Word lists by language code
export const Words = {
  ENGLISH: english,
  FRENCH: french,
  // CHINESE: chinese,
  // ITALIAN: italian,
  // JAPANESE: japanese,
  // KOREAN: korean,
  // SPANISH: spanish,
}

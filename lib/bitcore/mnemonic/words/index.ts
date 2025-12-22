/**
 * Word lists for BIP39 mnemonic generation
 * Migrated from @abcpros/bitcore-mnemonic with ESM support and TypeScript
 */

import { english } from './english.js'

// For now, we'll only include English word list
// Other language word lists can be added later if needed
export const Words = {
  ENGLISH: english,
  // CHINESE: chinese,
  // FRENCH: french,
  // ITALIAN: italian,
  // JAPANESE: japanese,
  // KOREAN: korean,
  // SPANISH: spanish,
}

/**
 * Mnemonic-specific error definitions
 * Migrated from @abcpros/bitcore-mnemonic with ESM support and TypeScript
 */

import { BitcoreError } from '../errors.js'

const mnemonicErrorSpec = {
  name: 'Mnemonic',
  message: 'Internal Error on bitcore-mnemonic module {0}',
  errors: [
    {
      name: 'InvalidEntropy',
      message: 'Entropy length must be an even multiple of 11 bits: {0}',
    },
    {
      name: 'UnknownWordlist',
      message: 'Could not detect the used word list: {0}',
    },
    {
      name: 'InvalidMnemonic',
      message: 'Mnemonic string is invalid: {0}',
    },
  ],
}

export const MnemonicError = BitcoreError.extend(mnemonicErrorSpec)

// Type definitions for the dynamically created error classes
export interface MnemonicErrorType {
  InvalidEntropy: new (entropy: string) => Error
  UnknownWordlist: new (mnemonic: string) => Error
  InvalidMnemonic: new (mnemonic: string) => Error
}

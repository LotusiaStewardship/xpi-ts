/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */

import {
  Address,
  Networks,
  Script,
  ScriptType,
  Mnemonic,
} from '../lib/bitcore/index.js'

/**
 * Represents a cryptocurrency wallet with all necessary cryptographic components.
 */
export interface Wallet {
  /** The hierarchical deterministic private key in string format. */
  hdPrivateKey: string
  /** The wallet's private key in WIF (Wallet Import Format). */
  privateKey: string
  /** The wallet's public key in hexadecimal format. */
  publicKey: string
  /** The wallet's address object. */
  address: Address
  /** The script associated with the wallet's address. */
  script: Script
  /** The script data in hexadecimal format. */
  scriptPayload: string
  /** The type of script (e.g., pubkeyhash, scripthash, taproot). */
  scriptType: ScriptType
}

/**
 * Creates a wallet object from a mnemonic or generates a new one if not provided.
 *
 * @param {Bitcore.Mnemonic | string} [mnemonic] - The mnemonic phrase or a Bitcore.Mnemonic instance to derive the wallet from.
 *   If not provided, a new random mnemonic and wallet will be generated.
 * @returns {Wallet} The generated wallet object containing the private key (WIF), public key (hex),
 *   address, script, script type, and script payload.
 */
export function createWallet(
  mnemonic?: Mnemonic | string,
  path?: string,
): Wallet {
  if (mnemonic) {
    if (typeof mnemonic === 'string') {
      mnemonic = new Mnemonic(mnemonic)
    }
  } else {
    mnemonic = new Mnemonic()
  }
  if (!path) {
    path = "m/44'/10605'/0'/0/0"
  }
  const hdPrivateKey = mnemonic.toHDPrivateKey()
  const privateKey = hdPrivateKey.deriveChild(path).privateKey
  const publicKey = privateKey.publicKey
  const address = privateKey.toAddress(Networks.mainnet)
  const script = Script.fromAddress(address)
  return {
    hdPrivateKey: hdPrivateKey.toString(),
    privateKey: privateKey.toWIF(),
    publicKey: publicKey.toString(),
    address: address,
    script: script,
    scriptType: script.getType(),
    scriptPayload: script.getData().toString('hex'),
  }
}

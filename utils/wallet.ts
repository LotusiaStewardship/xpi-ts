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
  Network,
  buildKeyPathTaproot,
} from '../lib/bitcore/index.js'
import { BIP44_COIN_TYPE } from './constants.js'
/**
 * Represents a cryptocurrency wallet with all necessary cryptographic components.
 */
export interface Wallet {
  /** The hierarchical deterministic private key in string format. */
  hdPrivateKey?: string
  /** The wallet's private key in WIF (Wallet Import Format). */
  privateKey?: string
  /** The wallet's public key in hexadecimal format. */
  publicKey?: string
  /** The wallet's address object. */
  address: Address
  /** The script associated with the wallet's address. */
  script: Script
  /** The script data in hexadecimal format. */
  scriptPayload: string
  /** The type of script (e.g., pubkeyhash, scripthash, taproot). */
  scriptType: ScriptType
}

/** A wallet with all properties of the `Wallet` interface plus keys */
export type WalletWithKeys = Required<Wallet>

/**
 * Creates a cryptocurrency wallet with the specified configuration.
 *
 * @param {Object} options - Configuration options for wallet creation
 * @param {Mnemonic | string} [options.mnemonic] - BIP39 mnemonic phrase. If not provided, a new one is generated.
 * @param {string} [options.path] - BIP44 derivation path. Defaults to `m/44'/{BIP44_COIN_TYPE}'/0'/0/0`
 * @param {Network} [options.network=Networks.mainnet] - The network to use (mainnet, testnet, regtest)
 * @param {ScriptType} [options.scriptType='p2pkh'] - The script type for the wallet address (p2pkh, p2tr-commitment, etc.)
 *
 * @returns {Wallet | WalletWithKeys} A wallet object containing address, script, and optionally cryptographic keys.
 *   When a mnemonic is provided, returns a WalletWithKeys with all key material.
 *   Otherwise returns a Wallet with minimal key information.
 *
 * @example
 * // Create a wallet with a new mnemonic
 * const wallet = createWallet({ network: Networks.testnet })
 *
 * @example
 * // Create a Taproot wallet from an existing mnemonic
 * const wallet = createWallet({
 *   mnemonic: 'abandon abandon abandon...',
 *   scriptType: 'p2tr-commitment',
 *   network: Networks.mainnet
 * })
 */
export function createWallet({
  mnemonic,
  path,
  network = Networks.mainnet, // Default to mainnet
  scriptType = 'p2pkh', // Default to P2PKH
}: {
  mnemonic?: Mnemonic | string
  path?: string
  network?: Network
  scriptType?: ScriptType
}): Wallet | WalletWithKeys {
  if (mnemonic) {
    if (typeof mnemonic === 'string') {
      mnemonic = new Mnemonic(mnemonic)
    }
  } else {
    mnemonic = new Mnemonic()
  }
  if (!path) {
    path = `m/44'/${BIP44_COIN_TYPE}'/0'/0/0`
  }
  const hdPrivateKey = mnemonic.toHDPrivateKey()
  const privateKey = hdPrivateKey.deriveChild(path).privateKey
  const publicKey = privateKey.publicKey
  let script: Script | undefined = undefined
  switch (scriptType) {
    case 'p2tr-commitment':
      script = buildKeyPathTaproot(publicKey)
      break
    // Can add more script types here
    default:
      script = Script.buildPublicKeyHashOut(publicKey)
      break
  }
  return {
    hdPrivateKey: hdPrivateKey.toString(),
    privateKey: privateKey.toWIF(),
    publicKey: publicKey.toString(),
    address: script.toAddress(network)!, // script is always valid address in this context
    script: script,
    scriptType: script.getType(),
    scriptPayload: script.getData().toString('hex'),
  }
}

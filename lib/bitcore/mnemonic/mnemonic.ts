/**
 * BIP39 Mnemonic implementation
 * Migrated from @abcpros/bitcore-mnemonic with ESM support and TypeScript
 */

import { BN } from '../crypto/bn.js'
import { Hash } from '../crypto/hash.js'
import { Random } from '../crypto/random.js'
import { Preconditions } from '../util/preconditions.js'
import { BitcoreError } from '../errors.js'
import { HDPrivateKey } from '../hdprivatekey.js'
import { Network } from '../networks.js'
import { pbkdf2 } from './pbkdf2.js'
import { MnemonicError, MnemonicErrorType } from './errors.js'
import { Words } from './words/index.js'

/**
 * Simple Unicode normalization function
 * Replaces unorm dependency with a basic implementation
 */
function normalizeUnicode(str: string): string {
  // For now, we'll use a simple implementation
  // In a production environment, you might want to use a proper Unicode normalization library
  return str.normalize('NFKD')
}

/**
 * This is an immutable class that represents a BIP39 Mnemonic code.
 * See BIP39 specification for more info: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * A Mnemonic code is a group of easy to remember words used for the generation
 * of deterministic wallets. A Mnemonic can be used to generate a seed using
 * an optional passphrase, for later generate a HDPrivateKey.
 *
 * @example
 * // generate a random mnemonic
 * var mnemonic = new Mnemonic();
 * var phrase = mnemonic.phrase;
 *
 * // use a different language
 * var mnemonic = new Mnemonic(Mnemonic.Words.ENGLISH);
 * var xprivkey = mnemonic.toHDPrivateKey();
 *
 * @param {*=} data - a seed, phrase, or entropy to initialize (can be skipped)
 * @param {Array=} wordlist - the wordlist to generate mnemonics from
 * @returns {Mnemonic} A new instance of Mnemonic
 * @constructor
 */
export class Mnemonic {
  public readonly wordlist: string[]
  public readonly phrase: string

  constructor(data?: Buffer | string | number | string[], wordlist?: string[]) {
    if (Array.isArray(data)) {
      wordlist = data
      data = undefined
    }

    // handle data overloading
    let ent: number | undefined
    let phrase: string | undefined
    let seed: Buffer | undefined

    if (Buffer.isBuffer(data)) {
      seed = data
      ent = seed.length * 8
    } else if (typeof data === 'string') {
      phrase = normalizeUnicode(data)
    } else if (typeof data === 'number') {
      ent = data
    } else if (data) {
      throw new Error('Invalid data: Must be a Buffer, a string or an integer')
    }
    ent = ent || 128

    // check and detect wordlist
    const detectedWordlist = Mnemonic._getDictionary(phrase)
    wordlist = wordlist || detectedWordlist || Words.ENGLISH
    if (phrase && !detectedWordlist) {
      throw new Error(`Could not detect the used word list: ${phrase}`)
    }

    if (seed) {
      phrase = Mnemonic._entropy2mnemonic(seed, wordlist)
    }

    // validate phrase and ent
    if (phrase && !Mnemonic.isValid(phrase, wordlist)) {
      throw new Error(`Mnemonic string is invalid: ${phrase}`)
    }
    // Only validate entropy when generating a new mnemonic (not from seed)
    if (!seed && ent && (ent % 32 !== 0 || ent < 128 || ent > 256)) {
      throw new Error(
        'Values must be ENT > 128 and ENT < 256 and ENT % 32 == 0',
      )
    }

    phrase = phrase || Mnemonic._mnemonic(ent, wordlist)

    // this fixes spacing in JP
    phrase = normalizeUnicode(phrase)

    // Initialize readonly properties
    this.wordlist = wordlist
    this.phrase = phrase
  }

  static Words = Words

  /**
   * Will return a boolean if the mnemonic is valid
   *
   * @example
   *
   * var valid = Mnemonic.isValid('lab rescue lunch elbow recall phrase perfect donkey biology guess moment husband');
   * // true
   *
   * @param {String} mnemonic - The mnemonic string
   * @param {String} [wordlist] - The wordlist used
   * @returns {boolean}
   */
  static isValid(mnemonic: string, wordlist?: string[]): boolean {
    mnemonic = normalizeUnicode(mnemonic)
    const detectedWordlist = Mnemonic._getDictionary(mnemonic)
    wordlist = wordlist || detectedWordlist

    if (!wordlist) {
      return false
    }

    const words = mnemonic.split(' ')
    let bin = ''
    for (let i = 0; i < words.length; i++) {
      const ind = wordlist.indexOf(words[i])
      if (ind < 0) return false
      bin = bin + ('00000000000' + ind.toString(2)).slice(-11)
    }

    const cs = bin.length / 33
    const hash_bits = bin.slice(-cs)
    const nonhash_bits = bin.slice(0, bin.length - cs)
    const buf = Buffer.alloc(nonhash_bits.length / 8)
    for (let i = 0; i < nonhash_bits.length / 8; i++) {
      buf.writeUInt8(parseInt(bin.slice(i * 8, (i + 1) * 8), 2), i)
    }
    const expected_hash_bits = Mnemonic._entropyChecksum(buf)
    return expected_hash_bits === hash_bits
  }

  /**
   * Internal function to check if a mnemonic belongs to a wordlist.
   *
   * @param {String} mnemonic - The mnemonic string
   * @param {String} wordlist - The wordlist
   * @returns {boolean}
   */
  static _belongsToWordlist(mnemonic: string, wordlist: string[]): boolean {
    const words = normalizeUnicode(mnemonic).split(' ')
    for (let i = 0; i < words.length; i++) {
      const ind = wordlist.indexOf(words[i])
      if (ind < 0) return false
    }
    return true
  }

  /**
   * Internal function to detect the wordlist used to generate the mnemonic.
   *
   * @param {String} mnemonic - The mnemonic string
   * @returns {Array} the wordlist or null
   */
  static _getDictionary(mnemonic?: string): string[] | undefined {
    if (!mnemonic) return undefined

    const dicts = Object.keys(Words)
    for (let i = 0; i < dicts.length; i++) {
      const key = dicts[i]
      const wordlist = (Words as Record<string, string[]>)[key]
      if (Mnemonic._belongsToWordlist(mnemonic, wordlist)) {
        return wordlist
      }
    }
    return undefined
  }

  /**
   * Will generate a seed based on the mnemonic and optional passphrase.
   *
   * @param {String} [passphrase]
   * @returns {Buffer}
   */
  toSeed(passphrase?: string): Buffer {
    passphrase = passphrase || ''
    return pbkdf2(
      normalizeUnicode(this.phrase),
      normalizeUnicode('mnemonic' + passphrase),
      2048,
      64,
    )
  }

  /**
   * Will generate a Mnemonic object based on a seed.
   *
   * @param {Buffer} [seed]
   * @param {string} [wordlist]
   * @returns {Mnemonic}
   */
  static fromSeed(seed: Buffer, wordlist?: string[]): Mnemonic {
    Preconditions.checkArgument(Buffer.isBuffer(seed), 'seed must be a Buffer.')
    if (wordlist !== undefined) {
      Preconditions.checkArgument(
        Array.isArray(wordlist) || typeof wordlist === 'string',
        'wordlist must be a string or an array.',
      )
    }
    return new Mnemonic(seed, wordlist)
  }

  /**
   *
   * Generates a HD Private Key from a Mnemonic.
   * Optionally receive a passphrase and Lotus network.
   *
   * @param {String=} [passphrase]
   * @param {Network|String|number=} [network] - The network: 'livenet', 'testnet', or 'regtest
   * @returns {HDPrivateKey}
   */
  toHDPrivateKey(
    passphrase?: string,
    network?: string | Network,
  ): HDPrivateKey {
    const seed = this.toSeed(passphrase)
    return HDPrivateKey.fromSeed(seed, network)
  }

  /**
   * Will return a the string representation of the mnemonic
   *
   * @returns {String} Mnemonic
   */
  toString(): string {
    return this.phrase
  }

  /**
   * Will return a string formatted for the console
   *
   * @returns {String} Mnemonic
   */
  inspect(): string {
    return '<Mnemonic: ' + this.toString() + ' >'
  }

  /**
   * Internal function to generate a random mnemonic
   *
   * @param {Number} ENT - Entropy size, defaults to 128
   * @param {Array} wordlist - Array of words to generate the mnemonic
   * @returns {String} Mnemonic string
   */
  static _mnemonic(ENT: number, wordlist: string[]): string {
    const buf = Random.getRandomBuffer(ENT / 8)
    return Mnemonic._entropy2mnemonic(buf, wordlist)
  }

  /**
   * Internal function to generate mnemonic based on entropy
   *
   * @param {Buffer} entropy - Entropy buffer
   * @param {Array} wordlist - Array of words to generate the mnemonic
   * @returns {String} Mnemonic string
   */
  static _entropy2mnemonic(entropy: Buffer, wordlist: string[]): string {
    let bin = ''
    for (let i = 0; i < entropy.length; i++) {
      bin = bin + ('00000000' + entropy[i].toString(2)).slice(-8)
    }

    bin = bin + Mnemonic._entropyChecksum(entropy)
    if (bin.length % 11 !== 0) {
      throw new Error(
        `Entropy length must be an even multiple of 11 bits: ${bin}`,
      )
    }
    const mnemonic = []
    for (let i = 0; i < bin.length / 11; i++) {
      const wi = parseInt(bin.slice(i * 11, (i + 1) * 11), 2)
      mnemonic.push(wordlist[wi])
    }
    let ret: string
    if (wordlist === Words.ENGLISH) {
      ret = mnemonic.join(' ')
    } else {
      ret = mnemonic.join(' ')
    }
    return ret
  }

  /**
   * Internal function to create checksum of entropy
   *
   * @param {Buffer} entropy
   * @returns {string} Checksum of entropy length / 32
   * @private
   */
  static _entropyChecksum(entropy: Buffer): string {
    const hash = Hash.sha256(entropy)
    const bits = entropy.length * 8
    const cs = bits / 32

    const hashbits = new BN(hash.toString('hex'), 16).toString(2)

    // zero pad the hash bits
    let paddedHashbits = hashbits
    while (paddedHashbits.length % 256 !== 0) {
      paddedHashbits = '0' + paddedHashbits
    }

    const checksum = paddedHashbits.slice(0, cs)

    return checksum
  }
}

export default Mnemonic

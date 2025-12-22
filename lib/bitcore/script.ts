/**
 * Script implementation for Lotus
 * Migrated from bitcore-lib-xpi with ESM support and BigInt
 *
 * Signature Type Detection:
 * Lotus automatically determines signature type by length:
 * - 64 bytes = Schnorr signature
 * - Other lengths (typically 70-72 bytes) = ECDSA signature (DER-encoded)
 *
 * Reference: lotusd/src/script/interpreter.cpp lines 1900-1908
 *
 * This automatic detection happens in the script interpreter during signature
 * verification operations (OP_CHECKSIG, OP_CHECKMULTISIG, etc.)
 */

import { Preconditions } from './util/preconditions.js'
import { BufferReader } from './encoding/bufferreader.js'
import { BufferWriter } from './encoding/bufferwriter.js'
import { Hash } from './crypto/hash.js'
import { Opcode } from './opcode.js'
import { PublicKey } from './publickey.js'
import { Address } from './address.js'
import { Network } from './networks.js'
import { BitcoreError } from './errors.js'
import { BufferUtil } from './util/buffer.js'
import { Signature } from './crypto/signature.js'
import { Chunk } from './chunk.js'
import {
  TAPROOT_SIZE_WITH_STATE,
  TAPROOT_SIZE_WITHOUT_STATE,
} from './taproot.js'

export interface ScriptData {
  chunks: Chunk[]
  _network?: Network
}

export type ScriptInput = Buffer | string | ScriptData | PublicKey | Address
export type ScriptType =
  | 'p2pk'
  | 'p2pkh'
  | 'p2sh'
  | 'p2tr-commitment'
  | 'p2tr-state'
  | 'other'

export class Script {
  chunks!: Chunk[]
  _network?: Network

  /**
   * Create a Script from various input types
   * @param from - The input to create script from (Buffer, string, Script, Address, or ScriptData)
   * @returns A new Script instance
   */
  constructor(from?: ScriptInput) {
    if (Buffer.isBuffer(from)) {
      return Script.fromBuffer(from)
    } else if (from instanceof Address) {
      return Script.fromAddress(from)
    } else if (from instanceof Script) {
      return Script.fromBuffer(from.toBuffer())
    } else if (typeof from === 'string') {
      return Script.fromString(from)
    } else if (
      typeof from === 'object' &&
      from !== null &&
      Array.isArray((from as ScriptData).chunks)
    ) {
      this.set(from as ScriptData)
    } else {
      this.chunks = []
    }
  }

  /**
   * Set script data from a ScriptData object
   * @param obj - The script data object containing chunks
   * @returns This Script instance for chaining
   */
  set(obj: ScriptData): Script {
    Preconditions.checkArgument(
      typeof obj === 'object',
      'obj',
      'Must be an object',
    )
    Preconditions.checkArgument(
      Array.isArray(obj.chunks),
      'obj.chunks',
      'Must be an array',
    )
    this.chunks = obj.chunks
    this._network = obj._network
    return this
  }

  /**
   * Create a Script from a Buffer
   * @param buffer - The buffer containing script bytes
   * @returns A new Script instance
   */
  static fromBuffer(buffer: Buffer): Script {
    const script = new Script()
    script.chunks = []

    const br = new BufferReader(buffer)
    while (!br.finished()) {
      try {
        const opcodenum = br.readUInt8()

        let len: number, buf: Buffer
        if (opcodenum > 0 && opcodenum < Opcode.OP_PUSHDATA1) {
          len = opcodenum
          script.chunks.push(
            new Chunk({
              buf: br.read(len),
              len: len,
              opcodenum: opcodenum,
            }),
          )
        } else if (opcodenum === Opcode.OP_PUSHDATA1) {
          len = br.readUInt8()
          buf = br.read(len)
          script.chunks.push(
            new Chunk({
              buf: buf,
              len: len,
              opcodenum: opcodenum,
            }),
          )
        } else if (opcodenum === Opcode.OP_PUSHDATA2) {
          len = br.readUInt16LE()
          buf = br.read(len)
          script.chunks.push(
            new Chunk({
              buf: buf,
              len: len,
              opcodenum: opcodenum,
            }),
          )
        } else if (opcodenum === Opcode.OP_PUSHDATA4) {
          len = br.readUInt32LE()
          buf = br.read(len)
          script.chunks.push(
            new Chunk({
              buf: buf,
              len: len,
              opcodenum: opcodenum,
            }),
          )
        } else {
          script.chunks.push(
            new Chunk({
              opcodenum: opcodenum,
            }),
          )
        }
      } catch (e) {
        if (e instanceof RangeError) {
          throw new BitcoreError.Script.InvalidBuffer(buffer.toString('hex'))
        }
        throw e
      }
    }

    return script
  }

  /**
   * Create a Script from a hex string
   * @param str - The hex string to parse
   * @returns A new Script instance
   */
  static fromString(str: string): Script {
    Preconditions.checkArgument(
      typeof str === 'string',
      'str',
      'Must be a string',
    )

    // Remove any whitespace and convert to lowercase
    const cleanStr = str.replace(/\s/g, '').toLowerCase()

    // Validate hex string
    if (!/^[0-9a-f]*$/.test(cleanStr)) {
      throw new BitcoreError.Script.InvalidScriptString(str)
    }

    // Convert hex string to buffer and use fromBuffer
    const buffer = Buffer.from(cleanStr, 'hex')
    return Script.fromBuffer(buffer)
  }

  /**
   * Create a Script from an Assembly string
   * @param str - The assembly string to parse
   * @returns A new Script instance
   */
  static fromASM(str: string): Script {
    const script = new Script()
    script.chunks = []

    const tokens = str.split(' ')
    let i = 0
    while (i < tokens.length) {
      const token = tokens[i]
      const opcode = new Opcode(token)
      const opcodenum = opcode.num

      if (opcodenum === undefined) {
        const buf = Buffer.from(tokens[i], 'hex')
        let opcodenum: number
        const len = buf.length
        if (len >= 0 && len < Opcode.OP_PUSHDATA1) {
          opcodenum = len
        } else if (len < Math.pow(2, 8)) {
          opcodenum = Opcode.OP_PUSHDATA1
        } else if (len < Math.pow(2, 16)) {
          opcodenum = Opcode.OP_PUSHDATA2
        } else if (len < Math.pow(2, 32)) {
          opcodenum = Opcode.OP_PUSHDATA4
        } else {
          throw new Error('Invalid push data length')
        }
        script.chunks.push(
          new Chunk({
            buf: buf,
            len: buf.length,
            opcodenum: opcodenum,
          }),
        )
        i = i + 1
      } else {
        script.chunks.push(
          new Chunk({
            opcodenum: opcodenum,
          }),
        )
        i = i + 1
      }
    }
    return script
  }

  /**
   * Create a Script from a hex string (alias for fromString)
   * @param str - The hex string to parse
   * @returns A new Script instance
   */
  static fromHex(str: string): Script {
    return new Script(Buffer.from(str, 'hex'))
  }

  /**
   * Create a Script from an address
   * @param address - The address object or string
   * @returns A new Script instance
   */
  static fromAddress(address: Address | string): Script {
    if (typeof address === 'string') {
      address = Address.fromString(address)
    }
    if (address.isPayToTaproot()) {
      return Script.buildPayToTaproot(address.hashBuffer)
    } else if (address.isPayToScriptHash()) {
      return Script.buildScriptHashOut(address)
    } else if (address.isPayToPublicKeyHash()) {
      return Script.buildPublicKeyHashOut(address)
    }
    throw new BitcoreError.Script.UnrecognizedAddress(address)
  }

  /**
   * Build multisig output script
   */
  static buildMultisigOut(
    publicKeys: PublicKey[],
    threshold: number,
    opts: { noSorting?: boolean } = {},
  ): Script {
    Preconditions.checkArgument(
      threshold <= publicKeys.length,
      'threshold',
      'Number of required signatures must be less than or equal to the number of public keys',
    )
    const script = new Script()
    script.add(Opcode.OP_1 + threshold - 1)
    const sorted = opts.noSorting
      ? publicKeys
      : publicKeys.sort((a, b) => a.toString().localeCompare(b.toString()))
    for (const pubkey of sorted) {
      script.add(pubkey.toBuffer())
    }
    script.add(Opcode.OP_1 + publicKeys.length - 1)
    script.add(Opcode.OP_CHECKMULTISIG)
    return script
  }

  /**
   * Build a public key hash output script (P2PKH)
   * @param to - The public key, address, or string to pay to
   * @returns A P2PKH Script
   */
  static buildPublicKeyHashOut(to: PublicKey | Address | string): Script {
    Preconditions.checkArgument(to !== undefined, 'to', 'Must be defined')
    Preconditions.checkArgument(
      to instanceof PublicKey ||
        to instanceof Address ||
        typeof to === 'string',
      'to',
      'Must be PublicKey, Address, or string',
    )

    let address: Address
    if (to instanceof PublicKey) {
      address = to.toAddress()
    } else if (typeof to === 'string') {
      address = Address.fromString(to)
    } else {
      address = to
    }

    const script = new Script()
    script.chunks = []
    script
      .add(Opcode.OP_DUP)
      .add(Opcode.OP_HASH160)
      .add(address.hashBuffer)
      .add(Opcode.OP_EQUALVERIFY)
      .add(Opcode.OP_CHECKSIG)
    script._network = address.network
    return script
  }

  /**
   * Build a script hash output script (P2SH)
   * @param script - The script or address to hash
   * @returns A P2SH Script
   */
  static buildScriptHashOut(script: Script | Address): Script {
    Preconditions.checkArgument(
      script instanceof Script ||
        (script instanceof Address && script.isPayToScriptHash()),
      'script',
      'Must be Script or P2SH Address',
    )
    const s = new Script()
    s.add(Opcode.OP_HASH160)
      .add(
        script instanceof Address
          ? script.hashBuffer
          : Hash.sha256ripemd160(script.toBuffer()),
      )
      .add(Opcode.OP_EQUAL)

    s._network =
      (script as Script & { _network?: Network })._network ||
      (script as Address & { network?: Network }).network
    return s
  }

  /**
   * Build a multisig input script (P2MS)
   *
   * @param {PublicKey[]} pubkeys - The public keys
   * @param {number} threshold - The threshold number of signatures required
   * @param {Buffer[]} signatures - The signatures
   * @param {{ noSorting?: boolean; cachedMultisig?: Script; checkBits?: Uint8Array; signingMethod?: 'ecdsa' | 'schnorr'; }} [opts] - Options
   * @param {boolean} [opts.noSorting] - Disable sorting of pubkeys
   * @param {Script} [opts.cachedMultisig] - Cached multisig script
   * @param {Uint8Array} [opts.checkBits] - Schnorr checkbits
   * @param {'ecdsa' | 'schnorr'} [opts.signingMethod='ecdsa'] - Signing method
   * @returns {Script} A P2MS Script
   */
  static buildMultisigIn(
    pubkeys: PublicKey[],
    threshold: number,
    signatures: Buffer[],
    opts: {
      noSorting?: boolean
      cachedMultisig?: Script
      checkBits?: Uint8Array
      signingMethod?: 'ecdsa' | 'schnorr'
    } = {},
  ): Script {
    const script = new Script()

    // Handle Schnorr multisig with checkBits
    if (opts.signingMethod === 'schnorr' && opts.checkBits) {
      // Spec according to https://lotusia.org/docs/specs/bitcoin-cash/2019-11-15-schnorrmultisig
      // checkbits are little-endian bitfield indicating which pubkeys should be checked
      const N = pubkeys.length

      // Convert Uint8Array to number (little-endian)
      let checkBitsValue = 0
      for (let i = 0; i < opts.checkBits.length; i++) {
        checkBitsValue |= opts.checkBits[i] << (8 * i)
      }

      // N should only be 1-20
      if (N >= 1 && N <= 4) {
        // For N <= 4, checkbits will always be pushed using OP_1 through OP_15
        script.add(Opcode.OP_1 + checkBitsValue - 1)
      } else if (N >= 5 && N <= 8) {
        // For 5 <= N <= 8, length-1 byte array
        // Special case: 0x81 must be pushed using OP_1NEGATE (only for 2-of-8)
        if (checkBitsValue === 0x81 && N === 8 && threshold === 2) {
          script.add(Opcode.OP_1NEGATE)
        } else if (checkBitsValue >= 0x01 && checkBitsValue <= 0x10) {
          // The byte arrays {0x01} through {0x10} must be pushed using OP_1 through OP_16
          script.add(Opcode.OP_1 + checkBitsValue - 1)
        } else {
          // Other cases pushed using 0x01 <checkbits>
          script.add(0x01)
          script.add(checkBitsValue)
        }
      } else if (N >= 9 && N <= 16) {
        // For 9 <= N <= 16, length-2 byte array: 0x02 LL HH
        script.add(0x02)
        script.add(checkBitsValue & 0xff) // LL (least significant byte)
        script.add((checkBitsValue >> 8) & 0xff) // HH (high bits)
      } else if (N >= 17 && N <= 20) {
        // For 17 <= N <= 20, length-3 byte array: 0x03 LL II HH
        script.add(0x03)
        script.add(checkBitsValue & 0xff) // LL (least significant byte)
        script.add((checkBitsValue >> 8) & 0xff) // II (middle byte)
        script.add((checkBitsValue >> 16) & 0xff) // HH (high bits)
      }
    } else {
      // ECDSA mode: multisig dummy parameter of 0
      script.add(Opcode.OP_0)
    }

    // Add signatures
    for (const sig of signatures) {
      script.add(sig)
    }

    // Add redeem script
    script.add(
      (
        opts.cachedMultisig || Script.buildMultisigOut(pubkeys, threshold, opts)
      ).toBuffer(),
    )

    return script
  }

  /**
   * Build P2SH multisig input script
   */
  static buildP2SHMultisigIn(
    pubkeys: PublicKey[],
    threshold: number,
    signatures: Buffer[],
    opts: {
      noSorting?: boolean
      cachedMultisig?: Script
      checkBits?: Uint8Array
      signingMethod?: 'ecdsa' | 'schnorr'
    } = {},
  ): Script {
    const script = new Script()

    // Handle Schnorr multisig with checkBits
    if (opts.signingMethod === 'schnorr' && opts.checkBits) {
      // Spec according to https://lotusia.org/docs/specs/bitcoin-cash/2019-11-15-schnorrmultisig
      // checkbits are little-endian bitfield indicating which pubkeys should be checked
      const N = pubkeys.length

      // Convert Uint8Array to number (little-endian)
      let checkBitsValue = 0
      for (let i = 0; i < opts.checkBits.length; i++) {
        checkBitsValue |= opts.checkBits[i] << (8 * i)
      }

      // N should only be 1-20
      if (N >= 1 && N <= 4) {
        // For N <= 4, checkbits will always be pushed using OP_1 through OP_15
        script.add(Opcode.OP_1 + checkBitsValue - 1)
      } else if (N >= 5 && N <= 8) {
        // For 5 <= N <= 8, length-1 byte array
        // Special case: 0x81 must be pushed using OP_1NEGATE (only for 2-of-8)
        if (checkBitsValue === 0x81 && N === 8 && threshold === 2) {
          script.add(Opcode.OP_1NEGATE)
        } else if (checkBitsValue >= 0x01 && checkBitsValue <= 0x10) {
          // The byte arrays {0x01} through {0x10} must be pushed using OP_1 through OP_16
          script.add(Opcode.OP_1 + checkBitsValue - 1)
        } else {
          // Other cases pushed using 0x01 <checkbits>
          script.add(0x01)
          script.add(checkBitsValue)
        }
      } else if (N >= 9 && N <= 16) {
        // For 9 <= N <= 16, length-2 byte array: 0x02 LL HH
        script.add(0x02)
        script.add(checkBitsValue & 0xff) // LL (least significant byte)
        script.add((checkBitsValue >> 8) & 0xff) // HH (high bits)
      } else if (N >= 17 && N <= 20) {
        // For 17 <= N <= 20, length-3 byte array: 0x03 LL II HH
        script.add(0x03)
        script.add(checkBitsValue & 0xff) // LL (least significant byte)
        script.add((checkBitsValue >> 8) & 0xff) // II (middle byte)
        script.add((checkBitsValue >> 16) & 0xff) // HH (high bits)
      }
    } else {
      // ECDSA mode: multisig dummy parameter of 0
      script.add(Opcode.OP_0)
    }

    // Add signatures
    for (const sig of signatures) {
      script.add(sig)
    }

    // Add redeem script
    script.add(
      (
        opts.cachedMultisig || Script.buildMultisigOut(pubkeys, threshold, opts)
      ).toBuffer(),
    )

    return script
  }

  /**
   * Build witness multisig output from script
   */
  static buildWitnessMultisigOutFromScript(script: Script): Script {
    const scriptHash = Hash.sha256(script.toBuffer())
    const witnessScript = new Script()
    witnessScript.add(Opcode.OP_0)
    witnessScript.add(scriptHash)
    return witnessScript
  }

  /**
   * Build public key output script
   */
  static buildPublicKeyOut(pubkey: PublicKey): Script {
    const script = new Script()
    script.add(pubkey.toBuffer())
    script.add(Opcode.OP_CHECKSIG)
    return script
  }

  /**
   * Build data output script
   * @param data - The data to push to the stack
   * @param encoding - The encoding of the data (defaults to 'utf8')
   * @returns The data output script
   */
  static buildDataOut(
    data: string | Buffer,
    encoding: string = 'utf8',
  ): Script {
    let buffer: Buffer
    if (typeof data === 'string') {
      if (encoding === 'hex') {
        buffer = Buffer.from(data, 'hex')
      } else {
        buffer = Buffer.from(data, 'utf8')
      }
    } else {
      buffer = data
    }

    const script = new Script()
    script.add(Opcode.OP_RETURN)
    script.add(buffer)
    return script
  }

  /**
   * Build public key input script
   * @param signature - The signature (Signature object or Buffer)
   * @param sigtype - The signature hash type (defaults to Signature.SIGHASH_ALL)
   * @returns The P2PK input script
   */
  static buildPublicKeyIn(
    signature: Signature | Buffer,
    sigtype: number,
  ): Script {
    const script = new Script()
    if (signature instanceof Signature) {
      // For Schnorr signatures, toTxFormat('schnorr') already includes sighash byte
      // Don't concatenate again to avoid double-encoding
      if (signature.isSchnorr) {
        script.add(signature.toTxFormat('schnorr'))
      } else {
        // For ECDSA signatures, concatenate signature with sigtype as single buffer (per Lotus spec)
        signature = signature.toTxFormat()
        script.add(
          BufferUtil.concat([
            signature,
            BufferUtil.integerAsSingleByteBuffer(
              sigtype || Signature.SIGHASH_ALL,
            ),
          ]),
        )
      }
    } else {
      // For Buffer signatures, concatenate with sigtype
      script.add(
        BufferUtil.concat([
          signature,
          BufferUtil.integerAsSingleByteBuffer(
            sigtype || Signature.SIGHASH_ALL,
          ),
        ]),
      )
    }
    return script
  }

  /**
   * Build public key hash input script
   * @param publicKey - The public key
   * @param signature - The signature (Signature object or Buffer)
   * @param sigtype - The signature hash type (defaults to Signature.SIGHASH_ALL)
   * @returns The P2PKH input script
   */
  static buildPublicKeyHashIn(
    publicKey: PublicKey,
    signature: Signature | Buffer,
    sigtype: number,
  ): Script {
    const script = new Script()
    if (signature instanceof Signature) {
      // For Schnorr signatures, toTxFormat('schnorr') already includes sighash byte
      // Don't concatenate again to avoid double-encoding
      if (signature.isSchnorr) {
        script.add(signature.toTxFormat('schnorr'))
      } else {
        // For ECDSA signatures, concatenate signature with sigtype as single buffer (per Lotus spec)
        signature = signature.toTxFormat()
        script.add(
          BufferUtil.concat([
            signature,
            BufferUtil.integerAsSingleByteBuffer(
              sigtype || Signature.SIGHASH_ALL,
            ),
          ]),
        )
      }
    } else {
      // For Buffer signatures, concatenate with sigtype
      script.add(
        BufferUtil.concat([
          signature,
          BufferUtil.integerAsSingleByteBuffer(
            sigtype || Signature.SIGHASH_ALL,
          ),
        ]),
      )
    }
    script.add(publicKey.toBuffer())
    return script
  }

  /**
   * Build a Pay-To-Taproot output script
   *
   * Creates a Taproot output script:
   * OP_SCRIPTTYPE OP_1 <33-byte commitment> [<32-byte state>]
   *
   * Reference: lotusd/src/script/taproot.h
   *
   * @param commitment - 33-byte commitment public key (tweaked)
   * @param state - Optional 32-byte state
   * @returns P2TR script
   */
  static buildPayToTaproot(
    commitment: PublicKey | Buffer,
    state?: Buffer,
  ): Script {
    Preconditions.checkArgument(
      commitment !== undefined,
      'commitment',
      'Must be defined',
    )

    const commitmentBuf =
      commitment instanceof PublicKey ? commitment.toBuffer() : commitment

    if (commitmentBuf.length !== 33) {
      throw new Error(
        'Taproot commitment must be 33-byte compressed public key',
      )
    }

    if (state && state.length !== 32) {
      throw new Error('Taproot state must be exactly 32 bytes')
    }

    const script = new Script()
    script.add(Opcode.OP_SCRIPTTYPE)
    script.add(Opcode.OP_1)
    script.add(commitmentBuf)

    if (state) {
      script.add(state)
    }

    return script
  }

  /**
   * Add a chunk to the script
   * @param chunk - The opcode, buffer, or number to add
   * @returns This Script instance for chaining
   */
  add(chunk: Opcode | Buffer | number): Script {
    if (chunk instanceof Opcode) {
      this.chunks.push(
        new Chunk({
          opcodenum: chunk.num,
        }),
      )
    } else if (Buffer.isBuffer(chunk)) {
      const chunkObj = {
        buf: chunk,
        len: chunk.length,
        opcodenum: chunk.length,
      }
      if (chunk.length < Opcode.OP_PUSHDATA1) {
        chunkObj.opcodenum = chunk.length
      } else if (chunk.length <= 0xff) {
        chunkObj.opcodenum = Opcode.OP_PUSHDATA1
      } else if (chunk.length <= 0xffff) {
        chunkObj.opcodenum = Opcode.OP_PUSHDATA2
      } else {
        chunkObj.opcodenum = Opcode.OP_PUSHDATA4
      }
      this.chunks.push(new Chunk(chunkObj))
    } else if (typeof chunk === 'number') {
      this.chunks.push(
        new Chunk({
          opcodenum: chunk,
        }),
      )
    } else {
      throw new TypeError('Invalid chunk type')
    }
    return this
  }

  /**
   * Convert script to Buffer
   * @returns The script as a Buffer
   */
  toBuffer(): Buffer {
    const bw = new BufferWriter()
    for (const chunk of this.chunks) {
      bw.writeUInt8(chunk.opcodenum)
      if (chunk.buf) {
        if (chunk.opcodenum === Opcode.OP_PUSHDATA1) {
          bw.writeUInt8(chunk.len!)
        } else if (chunk.opcodenum === Opcode.OP_PUSHDATA2) {
          bw.writeUInt16LE(chunk.len!)
        } else if (chunk.opcodenum === Opcode.OP_PUSHDATA4) {
          bw.writeUInt32LE(chunk.len!)
        }
        bw.write(chunk.buf)
      }
    }
    return bw.toBuffer()
  }

  /**
   * Convert script to hex string (alias for toHex)
   * @returns The script as a hex string
   */
  toString(): string {
    return this.toBuffer().toString('hex')
  }

  /**
   * Get P2PKH address string for this script
   * @returns The P2PKH address as a string
   */
  toP2PKH(): string {
    if (!this.isPayToPublicKeyHash()) {
      throw new Error('Script is not a P2PKH address')
    }
    return this.chunks[2].buf!.toString('hex')
  }

  /**
   * Get P2SH address string for this script
   * @returns The P2SH address as a string
   */
  toP2SH(): string {
    if (!this.isPayToScriptHash()) {
      throw new Error('Script is not a P2SH address')
    }
    return this.chunks[1].buf!.toString('hex')
  }

  /**
   * Convert script to ASM string format
   * @returns The script as an ASM string
   */
  toASM(): string {
    let str = ''
    for (let i = 0; i < this.chunks.length; i++) {
      const chunk = this.chunks[i]
      str += this._chunkToString(chunk, 'asm')
    }
    return str.substring(1)
  }

  /**
   * Convert script to hex string
   * @returns The script as a hex string
   */
  toHex(): string {
    return this.toBuffer().toString('hex')
  }

  /**
   * Debug representation of the script
   * @returns A string representation for debugging
   */
  inspect(): string {
    return '<Script: ' + this.toString() + '>'
  }

  /**
   * Internal method to convert chunk to string
   */
  private _chunkToString(chunk: Chunk, type?: string): string {
    const opcodenum = chunk.opcodenum
    const asm = type === 'asm'
    let str = ''
    if (!chunk.buf) {
      // no data chunk
      // Build reverse mapping from Opcode values to names
      const opcodeNames: { [key: number]: string } = {}
      for (const [name, value] of Object.entries(Opcode.map)) {
        // Prefer non-alias names (skip OP_FALSE, OP_TRUE, OP_NOP2, OP_NOP3)
        if (
          name === 'OP_FALSE' ||
          name === 'OP_TRUE' ||
          name === 'OP_NOP2' ||
          name === 'OP_NOP3'
        ) {
          continue
        }
        if (!opcodeNames[value]) {
          opcodeNames[value] = name
        }
      }

      if (opcodeNames[opcodenum!]) {
        if (asm) {
          // A few cases where the opcode name differs from reverseMap
          // aside from 1 to 16 data pushes.
          if (opcodenum === 0) {
            // OP_0 -> 0
            str = str + ' 0'
          } else if (opcodenum === 79) {
            // OP_1NEGATE -> 1
            str = str + ' -1'
          } else {
            str = str + ' ' + opcodeNames[opcodenum!]
          }
        } else {
          str = str + ' ' + opcodeNames[opcodenum!]
        }
      } else {
        let numstr = opcodenum!.toString(16)
        if (numstr.length % 2 !== 0) {
          numstr = '0' + numstr
        }
        if (asm) {
          str = str + ' ' + numstr
        } else {
          str = str + ' ' + '0x' + numstr
        }
      }
    } else {
      // data chunk
      if (
        !asm &&
        (opcodenum === Opcode.OP_PUSHDATA1 ||
          opcodenum === Opcode.OP_PUSHDATA2 ||
          opcodenum === Opcode.OP_PUSHDATA4)
      ) {
        str = str + ' ' + new Opcode(opcodenum!).toString()
      }
      if (chunk.len! > 0) {
        if (asm) {
          str = str + ' ' + chunk.buf.toString('hex')
        } else {
          str = str + ' ' + chunk.len + ' ' + '0x' + chunk.buf.toString('hex')
        }
      }
    }
    return str
  }

  /**
   * Check if script is Pay-To-Public-Key-Hash (P2PKH) output
   * @returns True if script is P2PKH output
   */
  isPayToPublicKeyHash(): boolean {
    return (
      this.chunks.length === 5 &&
      this.chunks[0].opcodenum === Opcode.OP_DUP &&
      this.chunks[1].opcodenum === Opcode.OP_HASH160 &&
      this.chunks[2].opcodenum === 20 && // Direct push of 20 bytes
      this.chunks[2].buf!.length === 20 &&
      this.chunks[3].opcodenum === Opcode.OP_EQUALVERIFY &&
      this.chunks[4].opcodenum === Opcode.OP_CHECKSIG
    )
  }

  /**
   * Check if script is public key hash output (alias for isPayToPublicKeyHash)
   * @returns True if script is P2PKH output
   */
  isPublicKeyHashOut(): boolean {
    return !!(
      this.chunks.length === 5 &&
      this.chunks[0].opcodenum === Opcode.OP_DUP &&
      this.chunks[1].opcodenum === Opcode.OP_HASH160 &&
      this.chunks[2].buf &&
      this.chunks[2].buf.length === 20 &&
      this.chunks[3].opcodenum === Opcode.OP_EQUALVERIFY &&
      this.chunks[4].opcodenum === Opcode.OP_CHECKSIG
    )
  }

  /**
   * Check if script is Pay-To-Script-Hash (P2SH) output
   * @returns True if script is P2SH output
   */
  isPayToScriptHash(): boolean {
    return (
      this.chunks.length === 3 &&
      this.chunks[0].opcodenum === Opcode.OP_HASH160 &&
      this.chunks[1].opcodenum === 20 && // Direct push of 20 bytes
      this.chunks[1].buf!.length === 20 &&
      this.chunks[2].opcodenum === Opcode.OP_EQUAL
    )
  }

  /**
   * Check if script is script hash output (alias for isPayToScriptHash)
   * @returns True if script is P2SH output
   */
  isScriptHashOut(): boolean {
    const buf = this.toBuffer()
    return (
      buf.length === 23 &&
      buf[0] === Opcode.OP_HASH160 &&
      buf[1] === 0x14 &&
      buf[buf.length - 1] === Opcode.OP_EQUAL
    )
  }

  /**
   * Check if this is a Pay-To-Taproot output script
   *
   * Valid formats:
   * - OP_SCRIPTTYPE OP_1 0x21 <33-byte commitment>
   * - OP_SCRIPTTYPE OP_1 0x21 <33-byte commitment> 0x20 <32-byte state>
   *
   * Reference: lotusd/src/script/taproot.cpp IsPayToTaproot()
   *
   * @returns {boolean} if this is a P2TR output script
   */
  isPayToTaproot(): boolean {
    const buf = this.toBuffer()

    if (
      buf.length < TAPROOT_SIZE_WITHOUT_STATE ||
      // Must start with OP_SCRIPTTYPE OP_1
      buf[0] !== Opcode.OP_SCRIPTTYPE ||
      buf[1] !== Opcode.OP_1 ||
      // Next byte must be 0x21 (33 bytes push)
      buf[2] !== 33
    ) {
      return false
    }

    // If exactly 36 bytes, valid without state
    if (buf.length === TAPROOT_SIZE_WITHOUT_STATE) {
      return true
    }

    // If has state, must be exactly 69 bytes with 0x20 (32 bytes) state push
    return buf.length === TAPROOT_SIZE_WITH_STATE && buf[36] === 32
  }

  /**
   * Get the data part of a script, if it has one
   *
   * P2SH: The script hash
   * P2PKH: The public key hash
   * P2TR: The commitment
   *
   * @throws {Error} If the script type is not recognized
   * @returns {Buffer} The data part of the script
   */
  getData(): Buffer {
    // P2SH
    if (this.isScriptHashOut()) {
      if (this.chunks[1] === undefined) {
        return Buffer.alloc(0)
      } else {
        return Buffer.from(this.chunks[1].buf!)
      }
    }
    // P2PKH
    if (this.isPublicKeyHashOut()) {
      return Buffer.from(this.chunks[2].buf!)
    }
    // P2TR
    if (this.isPayToTaproot()) {
      return Buffer.from(this.chunks[2].buf!)
    }

    throw new Error('Unrecognized script type to get data from')
  }

  /**
   * Get address information from script
   * @returns The Address object or null if not applicable
   */
  getAddressInfo(): Address | null {
    if ((this as Script & { _isInput?: boolean })._isInput) {
      return this._getInputAddressInfo()
    } else if ((this as Script & { _isOutput?: boolean })._isOutput) {
      return this._getOutputAddressInfo()
    } else {
      const info = this._getOutputAddressInfo()
      if (!info) {
        return this._getInputAddressInfo()
      }
      return info
    }
  }

  /**
   * Get output address info
   */
  private _getOutputAddressInfo(): Address | null {
    const info: { hashBuffer?: Buffer; type?: string; network?: Network } = {}
    if (this.isPayToTaproot()) {
      // For Taproot, extract the 33-byte commitment public key
      const buf = this.toBuffer()
      info.hashBuffer = buf.slice(3, 36) // Skip OP_SCRIPTTYPE OP_1 0x21
      info.type = Address.PayToTaproot
    } else if (this.isScriptHashOut()) {
      info.hashBuffer = this.getData()
      info.type = Address.PayToScriptHash
    } else if (this.isPublicKeyHashOut()) {
      info.hashBuffer = this.getData()
      info.type = Address.PayToPublicKeyHash
    } else {
      return null
    }
    return new Address(info)
  }

  /**
   * Get input address info
   */
  private _getInputAddressInfo(): Address | null {
    const info: { hashBuffer?: Buffer; type?: string; network?: Network } = {}
    if (this.isPublicKeyHashIn()) {
      // hash the publickey found in the scriptSig
      info.hashBuffer = Hash.sha256ripemd160(this.chunks[1].buf!)
      info.type = Address.PayToPublicKeyHash
    } else if (this.isScriptHashIn()) {
      // hash the redeemscript found at the end of the scriptSig
      info.hashBuffer = Hash.sha256ripemd160(
        this.chunks[this.chunks.length - 1].buf!,
      )
      info.type = Address.PayToScriptHash
    } else {
      return null
    }
    return new Address(info)
  }

  /**
   * Get output address from script
   * @param network - Optional network to use for address
   * @returns The Address object or null if not applicable
   */
  toAddress(network?: Network | string): Address | null {
    const info = this.getAddressInfo()
    if (!info) {
      return null
    }
    if (info instanceof Address) {
      // If a network is provided, create a new address with that network
      if (network) {
        if (this.isPayToTaproot()) {
          const buf = this.toBuffer()
          const commitment = buf.slice(3, 36)
          return Address.fromTaprootCommitment(commitment, network)
        } else if (this.isPublicKeyHashOut()) {
          const hashBuffer = this.getData()
          return Address.fromPublicKeyHash(hashBuffer, network)
        } else if (this.isScriptHashOut()) {
          const hashBuffer = this.getData()
          return Address.fromScriptHash(hashBuffer, network)
        }
      }
      return info
    }
    return null
  }

  /**
   * Check if a push operation at index is minimal
   * @param index - The chunk index to check
   * @returns True if the push is minimal
   */
  checkMinimalPush(index: number): boolean {
    if (index >= this.chunks.length) {
      return false
    }

    const chunk = this.chunks[index]
    const opcodenum = chunk.opcodenum

    if (opcodenum === undefined) {
      return false
    }

    // For push data operations
    if (opcodenum >= 0 && opcodenum <= Opcode.OP_PUSHDATA4) {
      if (!chunk.buf) {
        return opcodenum === Opcode.OP_0
      }

      const dataLength = chunk.buf.length

      // Check minimal encoding
      if (dataLength === 0) {
        return opcodenum === Opcode.OP_0
      } else if (dataLength === 1) {
        return opcodenum === Opcode.OP_1 || opcodenum === Opcode.OP_PUSHDATA1
      } else if (dataLength <= 75) {
        return opcodenum === dataLength
      } else if (dataLength <= 255) {
        return opcodenum === Opcode.OP_PUSHDATA1
      } else if (dataLength <= 65535) {
        return opcodenum === Opcode.OP_PUSHDATA2
      } else {
        return opcodenum === Opcode.OP_PUSHDATA4
      }
    }

    return true
  }

  /**
   * Check if this script is valid
   * @returns True if script is valid
   */
  isValid(): boolean {
    try {
      // Basic validation - check if we can parse the script
      return this.chunks.length > 0
    } catch (e) {
      return false
    }
  }

  /**
   * Clone this script
   * @returns A new Script instance with the same chunks
   */
  clone(): Script {
    const cloned = new Script()
    cloned.chunks = this.chunks.map(
      chunk =>
        new Chunk({
          opcodenum: chunk.opcodenum,
          buf: chunk.buf ? Buffer.from(chunk.buf) : undefined,
          len: chunk.len,
        }),
    )
    return cloned
  }

  /**
   * Check if this is a pay to public key hash input script
   * @returns True if script is P2PKH input
   */
  isPublicKeyHashIn(): boolean {
    if (this.chunks.length === 2) {
      const signatureBuf = this.chunks[0].buf
      const pubkeyBuf = this.chunks[1].buf
      if (
        signatureBuf &&
        signatureBuf.length &&
        pubkeyBuf &&
        pubkeyBuf.length
      ) {
        const version = pubkeyBuf[0]
        if (
          (version === 0x04 || version === 0x06 || version === 0x07) &&
          pubkeyBuf.length === 65
        ) {
          return true
        } else if (
          (version === 0x03 || version === 0x02) &&
          pubkeyBuf.length === 33
        ) {
          return true
        }
      }
    }
    return false
  }

  /**
   * Get public key from P2PK script
   * @returns The public key buffer
   */
  getPublicKey(): Buffer {
    Preconditions.checkState(
      this.isPublicKeyOut(),
      "Can't retrieve PublicKey from a non-PK output",
    )
    return this.chunks[0].buf!
  }

  /**
   * Get public key hash from P2PKH script
   * @returns The public key hash buffer
   */
  getPublicKeyHash(): Buffer {
    Preconditions.checkState(
      this.isPublicKeyHashOut(),
      "Can't retrieve PublicKeyHash from a non-PKH output",
    )
    return this.chunks[2].buf!
  }

  /**
   * Check if this is a public key output script
   * @returns True if script is P2PK output
   */
  isPublicKeyOut(): boolean {
    if (
      this.chunks.length === 2 &&
      this.chunks[0].buf &&
      this.chunks[0].buf.length &&
      this.chunks[1].opcodenum === Opcode.OP_CHECKSIG
    ) {
      const pubkeyBuf = this.chunks[0].buf
      const version = pubkeyBuf[0]
      let isVersion = false
      if (
        (version === 0x04 || version === 0x06 || version === 0x07) &&
        pubkeyBuf.length === 65
      ) {
        isVersion = true
      } else if (
        (version === 0x03 || version === 0x02) &&
        pubkeyBuf.length === 33
      ) {
        isVersion = true
      }
      if (isVersion) {
        return PublicKey.isValid(pubkeyBuf)
      }
    }
    return false
  }

  /**
   * Check if this is a pay to public key input script
   * @returns True if script is P2PK input
   */
  isPublicKeyIn(): boolean {
    if (this.chunks.length === 1) {
      const signatureBuf = this.chunks[0].buf
      if (signatureBuf && signatureBuf.length && signatureBuf[0] === 0x30) {
        return true
      }
    }
    return false
  }

  /**
   * Check if this is a P2SH input script
   * @returns True if script is P2SH input
   */
  isScriptHashIn(): boolean {
    if (this.chunks.length <= 1) {
      return false
    }
    const redeemChunk = this.chunks[this.chunks.length - 1]
    const redeemBuf = redeemChunk.buf
    if (!redeemBuf) {
      return false
    }

    let redeemScript: Script
    try {
      redeemScript = Script.fromBuffer(redeemBuf)
    } catch (e) {
      if (e instanceof BitcoreError.Script.InvalidBuffer) {
        return false
      }
      throw e
    }
    const type = redeemScript.classify()
    return type !== ScriptTypes.UNKNOWN
  }

  /**
   * Check if this is a multisig output script
   * @returns True if script is multisig output
   */
  isMultisigOut(): boolean {
    return (
      this.chunks.length > 3 &&
      this._isSmallIntOp(this.chunks[0].opcodenum!) &&
      this.chunks.slice(1, this.chunks.length - 2).every(function (obj) {
        return obj.buf && Buffer.isBuffer(obj.buf)
      }) &&
      this._isSmallIntOp(this.chunks[this.chunks.length - 2].opcodenum!) &&
      this.chunks[this.chunks.length - 1].opcodenum === Opcode.OP_CHECKMULTISIG
    )
  }

  /**
   * Internal method to check if opcode is small int
   */
  private _isSmallIntOp(opcode: number): boolean {
    return opcode >= Opcode.OP_1 && opcode <= Opcode.OP_16
  }

  /**
   * Check if this is a multisig input script
   * @returns True if script is multisig input
   */
  isMultisigIn(): boolean {
    return (
      this.chunks.length >= 2 &&
      this.chunks[0].opcodenum === 0 &&
      this.chunks.slice(1, this.chunks.length).every(function (obj) {
        return obj.buf && Buffer.isBuffer(obj.buf) && Signature.isTxDER(obj.buf)
      })
    )
  }

  /**
   * Check if this is a valid standard OP_RETURN output
   * @returns True if script is standard OP_RETURN output
   */
  isDataOut(): boolean {
    const step1 =
      this.chunks.length >= 1 &&
      this.chunks[0].opcodenum === Opcode.OP_RETURN &&
      this.toBuffer().length <= 223 // 223 instead of 220 because (+1 for OP_RETURN, +2 for the pushdata opcodes)
    if (!step1) return false
    const chunks = this.chunks.slice(1)
    const script2 = new Script({ chunks: chunks })
    return script2.isPushOnly()
  }

  /**
   * Check if script is push only (contains only push operations)
   * @returns True if script is push only
   */
  isPushOnly(): boolean {
    return this.chunks.every(function (chunk) {
      return (
        chunk.opcodenum! <= Opcode.OP_16 ||
        chunk.opcodenum === Opcode.OP_PUSHDATA1 ||
        chunk.opcodenum === Opcode.OP_PUSHDATA2 ||
        chunk.opcodenum === Opcode.OP_PUSHDATA4
      )
    })
  }

  /**
   * Classify script type (input or output)
   * @returns The script type as a string
   */
  classify(): string {
    if ((this as Script & { _isInput?: boolean })._isInput) {
      return this.classifyInput()
    } else if ((this as Script & { _isOutput?: boolean })._isOutput) {
      return this.classifyOutput()
    } else {
      const outputType = this.classifyOutput()
      return outputType !== ScriptTypes.UNKNOWN
        ? outputType
        : this.classifyInput()
    }
  }

  /**
   * Classify output script type
   * @returns The output script type
   */
  classifyOutput(): string {
    const outputIdentifiers: { [key: string]: () => boolean } = {
      PUBKEY_OUT: this.isPublicKeyOut.bind(this),
      PUBKEYHASH_OUT: this.isPublicKeyHashOut.bind(this),
      MULTISIG_OUT: this.isMultisigOut.bind(this),
      SCRIPTHASH_OUT: this.isScriptHashOut.bind(this),
      DATA_OUT: this.isDataOut.bind(this),
    }

    for (const type in outputIdentifiers) {
      if (outputIdentifiers[type]()) {
        return ScriptTypes[type as keyof typeof ScriptTypes]
      }
    }
    return ScriptTypes.UNKNOWN
  }

  /**
   * Classify input script type
   * @returns The input script type
   */
  classifyInput(): string {
    const inputIdentifiers: { [key: string]: () => boolean } = {
      PUBKEY_IN: this.isPublicKeyIn.bind(this),
      PUBKEYHASH_IN: this.isPublicKeyHashIn.bind(this),
      MULTISIG_IN: this.isMultisigIn.bind(this),
      SCRIPTHASH_IN: this.isScriptHashIn.bind(this),
    }

    for (const type in inputIdentifiers) {
      if (inputIdentifiers[type]()) {
        return ScriptTypes[type as keyof typeof ScriptTypes]
      }
    }
    return ScriptTypes.UNKNOWN
  }

  /**
   * Check if script is one of the known types
   * @returns True if script is standard
   */
  isStandard(): boolean {
    return this.classify() !== ScriptTypes.UNKNOWN
  }

  /**
   * Get script type compatible with chronik-client ScriptType
   *
   * Returns one of:
   * - "p2pk": Pay-to-Public-Key
   * - "p2pkh": Pay-to-Public-Key-Hash
   * - "p2sh": Pay-to-Script-Hash
   * - "p2tr-commitment": Pay-to-Taproot (without state)
   * - "p2tr-state": Pay-to-Taproot (with state)
   * - "other": Non-standard or unknown script type
   * @returns The script type as a string
   */
  getType(): ScriptType {
    // Check output script types
    if (this.isPayToTaproot()) {
      const buf = this.toBuffer()
      // If script has state (69 bytes), return p2tr-state, otherwise p2tr-commitment
      return buf.length === TAPROOT_SIZE_WITH_STATE
        ? 'p2tr-state'
        : 'p2tr-commitment'
    } else if (this.isPublicKeyOut()) {
      return 'p2pk'
    } else if (this.isPublicKeyHashOut()) {
      return 'p2pkh'
    } else if (this.isScriptHashOut()) {
      return 'p2sh'
    }

    // not a recognized format
    return 'other'
  }

  /**
   * Add element at start of script
   * @param obj - The opcode, buffer, or number to prepend
   * @returns This Script instance for chaining
   */
  prepend(obj: Opcode | Buffer | number): Script {
    this._addByType(obj, true)
    return this
  }

  /**
   * Compare scripts for equality
   * @param script - The script to compare against
   * @returns True if scripts are equal
   */
  equals(script: Script): boolean {
    Preconditions.checkState(
      script instanceof Script,
      'Must provide another script',
    )
    if (this.chunks.length !== script.chunks.length) {
      return false
    }
    for (let i = 0; i < this.chunks.length; i++) {
      if (
        Buffer.isBuffer(this.chunks[i].buf) &&
        !Buffer.isBuffer(script.chunks[i].buf)
      ) {
        return false
      }
      if (
        Buffer.isBuffer(this.chunks[i].buf) &&
        !BufferUtil.equals(this.chunks[i].buf!, script.chunks[i].buf!)
      ) {
        return false
      } else if (this.chunks[i].opcodenum !== script.chunks[i].opcodenum) {
        return false
      }
    }
    return true
  }

  /**
   * Internal method to add by type
   */
  private _addByType(
    obj: Opcode | Buffer | number | string | Script,
    prepend: boolean,
  ): void {
    if (typeof obj === 'string') {
      this._addOpcode(obj, prepend)
    } else if (typeof obj === 'number') {
      this._addOpcode(obj, prepend)
    } else if (obj instanceof Opcode) {
      this._addOpcode(obj, prepend)
    } else if (Buffer.isBuffer(obj)) {
      this._addBuffer(obj, prepend)
    } else if (obj instanceof Script) {
      this.chunks = this.chunks.concat(obj.chunks)
    } else if (typeof obj === 'object' && obj !== null) {
      this._insertAtPosition(obj, prepend)
    } else {
      throw new Error('Invalid script chunk')
    }
  }

  /**
   * Internal method to insert at position
   */
  private _insertAtPosition(
    op: { opcodenum?: number; buf?: Buffer; len?: number },
    prepend: boolean,
  ): void {
    if (prepend) {
      this.chunks.unshift(op as Chunk)
    } else {
      this.chunks.push(op as Chunk)
    }
  }

  /**
   * Internal method to add opcode
   */
  private _addOpcode(opcode: string | number | Opcode, prepend: boolean): void {
    let op: number
    if (typeof opcode === 'number') {
      op = opcode
    } else if (opcode instanceof Opcode) {
      op = opcode.num
    } else {
      op = new Opcode(opcode).num
    }
    this._insertAtPosition(
      {
        opcodenum: op,
      },
      prepend,
    )
  }

  /**
   * Internal method to add buffer
   */
  private _addBuffer(buf: Buffer, prepend: boolean): void {
    let opcodenum: number
    const len = buf.length
    if (len >= 0 && len < Opcode.OP_PUSHDATA1) {
      opcodenum = len
    } else if (len < Math.pow(2, 8)) {
      opcodenum = Opcode.OP_PUSHDATA1
    } else if (len < Math.pow(2, 16)) {
      opcodenum = Opcode.OP_PUSHDATA2
    } else if (len < Math.pow(2, 32)) {
      opcodenum = Opcode.OP_PUSHDATA4
    } else {
      throw new Error("You can't push that much data")
    }
    this._insertAtPosition(
      {
        buf: buf,
        len: len,
        opcodenum: opcodenum,
      },
      prepend,
    )
  }

  /**
   * Check for OP_CODESEPARATOR opcodes
   * @returns True if script contains OP_CODESEPARATOR
   */
  hasCodeseparators(): boolean {
    return this.chunks.some(
      chunk => chunk.opcodenum === Opcode.OP_CODESEPARATOR,
    )
  }

  /**
   * Remove OP_CODESEPARATOR opcodes
   * @returns This Script instance for chaining
   */
  removeCodeseparators(): Script {
    const chunks: Chunk[] = []
    for (let i = 0; i < this.chunks.length; i++) {
      if (this.chunks[i].opcodenum !== Opcode.OP_CODESEPARATOR) {
        chunks.push(this.chunks[i])
      }
    }
    this.chunks = chunks
    return this
  }

  /**
   * Find and delete equivalent chunks
   * @param script - The script to find and delete
   * @returns This Script instance for chaining
   */
  findAndDelete(script: Script): Script {
    const buf = script.toBuffer()
    const hex = buf.toString('hex')
    for (let i = 0; i < this.chunks.length; i++) {
      const script2 = new Script({
        chunks: [this.chunks[i]],
      })
      const buf2 = script2.toBuffer()
      const hex2 = buf2.toString('hex')
      if (hex === hex2) {
        this.chunks.splice(i, 1)
      }
    }
    return this
  }

  /**
   * Count signature operations in script
   * @param accurate - Whether to count accurately (default: true)
   * @returns The number of signature operations
   */
  getSignatureOperationsCount(accurate: boolean = true): number {
    let n = 0
    let lastOpcode = 0xffff // Invalid opcode
    for (const chunk of this.chunks) {
      const opcode = chunk.opcodenum!
      if (
        opcode === Opcode.OP_CHECKSIG ||
        opcode === Opcode.OP_CHECKSIGVERIFY
      ) {
        n++
      } else if (
        opcode === Opcode.OP_CHECKMULTISIG ||
        opcode === Opcode.OP_CHECKMULTISIGVERIFY
      ) {
        if (
          accurate &&
          lastOpcode >= Opcode.OP_1 &&
          lastOpcode <= Opcode.OP_16
        ) {
          n += this._decodeOP_N(lastOpcode)
        } else {
          n += 20
        }
      }
      lastOpcode = opcode
    }
    return n
  }

  /**
   * Internal method to decode OP_N
   */
  private _decodeOP_N(opcode: number): number {
    if (opcode === Opcode.OP_0) {
      return 0
    } else if (opcode >= Opcode.OP_1 && opcode <= Opcode.OP_16) {
      return opcode - (Opcode.OP_1 - 1)
    } else {
      throw new Error('Invalid opcode: ' + JSON.stringify(opcode))
    }
  }

  /**
   * Convert to P2SH output script
   * @returns A P2SH Script wrapping this script
   */
  toScriptHashOut(): Script {
    return Script.buildScriptHashOut(this)
  }
}

/**
 * Script utility functions
 * Migrated from bitcore-lib-xpi with ESM support
 */

/**
 * Enum for script types
 */
export const ScriptTypes = {
  /**
   * Unknown script type
   */
  UNKNOWN: 'Unknown',
  /**
   * Pay to public key
   */
  PUBKEY_OUT: 'Pay to public key',
  /**
   * Spend from public key
   */
  PUBKEY_IN: 'Spend from public key',
  /**
   * Pay to public key hash
   */
  PUBKEYHASH_OUT: 'Pay to public key hash',
  /**
   * Spend from public key hash
   */
  PUBKEYHASH_IN: 'Spend from public key hash',
  /**
   * Pay to script hash
   */
  SCRIPTHASH_OUT: 'Pay to script hash',
  /**
   * Spend from script hash
   */
  SCRIPTHASH_IN: 'Spend from script hash',
  /**
   * Pay to multisig
   */
  MULTISIG_OUT: 'Pay to multisig',
  MULTISIG_IN: 'Spend from multisig',
  DATA_OUT: 'Data push',
}

/**
 * Convert script to address
 * @param script - The script to convert
 * @param network - The network to use for address
 * @returns The address object
 */
export function toAddress(script: Script, network: string): Address {
  const addr = script.toAddress(network)
  if (!addr || typeof addr === 'boolean') {
    throw new Error('Cannot convert script to address')
  }
  return addr as Address
}

/**
 * Create empty script
 * @returns An empty Script instance
 */
export function empty(): Script {
  return new Script()
}

import { Preconditions } from '../util/preconditions.js'
import { BitcoreError } from '../errors.js'
import { BufferWriter } from '../encoding/bufferwriter.js'
import { BufferReader } from '../encoding/bufferreader.js'
import { BufferUtil } from '../util/buffer.js'
import { JSUtil } from '../util/js.js'
import { Script } from '../script.js'
import { BN } from '../crypto/bn.js'

const MAX_SAFE_INTEGER = 0x1fffffffffffff

export interface OutputData {
  satoshis?: number | bigint | BN | string
  script?: Script | Buffer | string
  scriptBuffer?: Buffer
}

export interface OutputObject {
  satoshis: number
  script: string
  asm: string
}

/**
 * Represents a transaction output
 */
export class Output {
  // Instance properties
  satoshis!: number
  private _satoshisBN!: BN
  private _scriptBuffer!: Buffer
  private _script?: Script

  constructor(args: OutputData) {
    if (typeof args === 'object' && args !== null) {
      // Handle satoshis
      if (args.satoshis !== undefined) {
        this.satoshis = this._parseSatoshis(args.satoshis)
      } else {
        this.satoshis = 0
        this._satoshisBN = new BN(0)
      }

      // Handle script - match reference logic
      if (Buffer.isBuffer(args.script)) {
        this._scriptBuffer = args.script
      } else if (args.scriptBuffer !== undefined) {
        this._scriptBuffer = args.scriptBuffer
      } else if (args.script !== undefined) {
        this.setScript(args.script)
      } else {
        this._scriptBuffer = Buffer.alloc(0)
      }
    } else {
      throw new TypeError('Unrecognized argument for Output')
    }
  }

  // Factory function to allow calling Output() without 'new'
  static create(args: OutputData): Output {
    return new Output(args)
  }

  /**
   * Parse satoshis from various input types
   */
  private _parseSatoshis(value: number | bigint | BN | string): number {
    if (value instanceof BN) {
      this._satoshisBN = value
      return value.toNumber()
    } else if (typeof value === 'string') {
      const num = parseInt(value)
      Preconditions.checkArgument(
        JSUtil.isNaturalNumber(num),
        'Output satoshis is not a natural number',
      )
      this._satoshisBN = new BN(num)
      return num
    } else if (typeof value === 'bigint') {
      const num = Number(value)
      Preconditions.checkArgument(
        JSUtil.isNaturalNumber(num),
        'Output satoshis is not a natural number',
      )
      this._satoshisBN = new BN(num)
      return num
    } else {
      Preconditions.checkArgument(
        JSUtil.isNaturalNumber(value),
        'Output satoshis is not a natural number',
      )
      this._satoshisBN = new BN(value)
      return value
    }
  }

  /**
   * Get the BN representation of satoshis
   */
  get satoshisBN(): BN {
    return this._satoshisBN
  }

  /**
   * Set the BN representation of satoshis
   */
  set satoshisBN(value: BN) {
    this._satoshisBN = value
    this.satoshis = value.toNumber()
    Preconditions.checkState(
      JSUtil.isNaturalNumber(this.satoshis),
      'Output satoshis is not a natural number',
    )
  }

  /**
   * Get the script for this output
   */
  get script(): Script {
    if (this._script) {
      return this._script
    } else {
      this.setScriptFromBuffer(this._scriptBuffer)
      return this._script!
    }
  }

  /**
   * Get the script buffer
   */
  get scriptBuffer(): Buffer {
    return this._scriptBuffer
  }

  /**
   * Set the script from a buffer
   */
  setScriptFromBuffer(buffer: Buffer): void {
    this._scriptBuffer = buffer
    try {
      this._script = Script.fromBuffer(this._scriptBuffer)
      ;(this._script as Script & { _isOutput?: boolean })._isOutput = true
    } catch (e) {
      if (e instanceof BitcoreError.Script.InvalidBuffer) {
        this._script = undefined
      } else {
        throw e
      }
    }
  }

  /**
   * Set the script for this output
   */
  setScript(script: Script | Buffer | string): Output {
    if (script instanceof Script) {
      this._scriptBuffer = script.toBuffer()
      this._script = script
      ;(this._script as Script & { _isOutput?: boolean })._isOutput = true
    } else if (typeof script === 'string') {
      this._script = Script.fromString(script)
      this._scriptBuffer = this._script.toBuffer()
      ;(this._script as Script & { _isOutput?: boolean })._isOutput = true
    } else if (Buffer.isBuffer(script)) {
      this.setScriptFromBuffer(script)
    } else {
      throw new TypeError('Invalid argument type: script')
    }
    return this
  }

  /**
   * Get the amount in XPI
   */
  getXPI(): number {
    return this.satoshis / 1000000
  }

  /**
   * Set the amount from XPI
   */
  setXPI(xpi: number): Output {
    this.satoshis = Math.round(xpi * 1000000)
    this._satoshisBN = new BN(this.satoshis)
    return this
  }

  /**
   * Check if this output is valid
   */
  isValid(): boolean {
    return (
      this.satoshis >= 0 &&
      this.satoshis <= 21000000 * 1000000 && // Max 21M XPI
      this._scriptBuffer.length > 0
    )
  }

  /**
   * Check if this output is dust (too small to be economical)
   */
  isDust(dustThreshold: number = 546): boolean {
    return this.satoshis < dustThreshold
  }

  /**
   * Check if satoshis are invalid
   */
  invalidSatoshis(): string | false {
    if (this.satoshis > MAX_SAFE_INTEGER) {
      return 'transaction txout satoshis greater than max safe integer'
    }
    if (this.satoshis !== this._satoshisBN.toNumber()) {
      return 'transaction txout satoshis has corrupted value'
    }
    if (this.satoshis < 0) {
      return 'transaction txout negative'
    }
    return false
  }

  /**
   * Check if this is an OP_RETURN output
   */
  isOpReturn(): boolean {
    if (!this._script) {
      this.setScriptFromBuffer(this._scriptBuffer)
    }
    // Check if the first opcode is OP_RETURN (0x6a)
    return !!(
      this._script &&
      this._script.chunks.length > 0 &&
      this._script.chunks[0].opcodenum === 0x6a
    )
  }

  /**
   * Convert to object representation
   */
  toObject(): OutputObject {
    return {
      satoshis: this.satoshis,
      script: this._scriptBuffer.toString('hex'),
      asm: this.script.toASM(),
    }
  }

  /**
   * Convert to JSON
   */
  toJSON = this.toObject

  /**
   * Debug representation
   */
  inspect(): string {
    let scriptStr: string
    if (this.script) {
      scriptStr = this.script.inspect()
    } else {
      scriptStr = this._scriptBuffer.toString('hex')
    }
    return '<Output (' + this.satoshis + ' sats) ' + scriptStr + '>'
  }

  /**
   * Create from buffer reader
   */
  static fromBufferReader(br: BufferReader): Output {
    const obj: OutputData = {}
    obj.satoshis = br.readUInt64LEBN()
    const size = br.readVarintNum()
    if (size !== 0) {
      obj.script = br.read(size)
    } else {
      obj.script = Buffer.from([])
    }
    return new Output(obj)
  }

  /**
   * Serialize to buffer
   */
  toBuffer(): Buffer {
    const bw = new BufferWriter()
    bw.writeUInt64LEBN(this._satoshisBN)
    bw.writeVarintNum(this._scriptBuffer.length)
    bw.write(this._scriptBuffer)
    return bw.concat()
  }

  /**
   * Serialize to buffer writer
   */
  toBufferWriter(writer?: BufferWriter): BufferWriter {
    if (!writer) {
      writer = new BufferWriter()
    }
    writer.writeUInt64LEBN(this._satoshisBN)
    const script = this._scriptBuffer
    writer.writeVarintNum(script.length)
    writer.write(script)
    return writer
  }

  /**
   * Get the size of this output in bytes
   */
  getSize(): number {
    return (
      8 + // satoshis
      BufferWriter.varintBufNum(this._scriptBuffer.length).length +
      this._scriptBuffer.length // script
    )
  }

  /**
   * Clone this output
   */
  clone(): Output {
    return new Output({
      satoshis: this.satoshis,
      script: this.script.clone(),
    })
  }

  /**
   * Create from object
   */
  static fromObject(data: OutputData): Output {
    return new Output(data)
  }

  /**
   * Check if this output is a pay-to-public-key-hash output
   */
  isPayToPublicKeyHash(): boolean {
    return this.script.isPayToPublicKeyHash()
  }

  /**
   * Check if this output is a pay-to-script-hash output
   */
  isPayToScriptHash(): boolean {
    return this.script.isPayToScriptHash()
  }

  /**
   * Get the address for this output (if applicable)
   */
  getAddress(): string | null {
    try {
      const addressInfo = this.script.getAddressInfo()
      return addressInfo ? addressInfo.toString() : null
    } catch (e) {
      return null
    }
  }
}

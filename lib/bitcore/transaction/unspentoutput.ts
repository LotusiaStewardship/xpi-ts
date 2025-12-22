import { Preconditions } from '../util/preconditions.js'
import { JSUtil } from '../util/js.js'
import { Script } from '../script.js'
import { Address } from '../address.js'
import { PublicKey } from '../publickey.js'
import { Unit } from '../unit.js'
import type { MuSigKeyAggContext } from '../crypto/musig2.js'

export interface UnspentOutputData {
  txid?: string
  txId?: string
  vout?: number
  outputIndex?: number
  scriptPubKey?: Script | Buffer | string
  script?: Script | Buffer | string
  amount?: number
  satoshis?: number | bigint
  address?: Address | string
  // Taproot specific fields
  internalPubKey?: PublicKey | Buffer | string
  merkleRoot?: Buffer
  // MuSig2 Taproot specific fields
  keyAggContext?: MuSigKeyAggContext
  mySignerIndex?: number
}

export interface UnspentOutputObject {
  address?: string
  txid: string
  vout: number
  scriptPubKey: string
  amount: number
}

/**
 * Represents an unspent output information: its script, associated amount and address,
 * transaction id and output index.
 */
export class UnspentOutput {
  // Instance properties
  readonly address?: Address
  readonly txId!: string
  readonly outputIndex!: number
  readonly script!: Script
  readonly satoshis!: number
  // Taproot specific properties
  readonly internalPubKey?: PublicKey
  readonly merkleRoot?: Buffer
  // MuSig2 Taproot specific properties
  readonly keyAggContext?: MuSigKeyAggContext
  readonly mySignerIndex?: number

  constructor(data: UnspentOutputData) {
    Preconditions.checkArgument(
      typeof data === 'object' && data !== null,
      'Must provide an object from where to extract data',
    )

    const address = data.address ? new Address(data.address) : undefined
    const txId = data.txid || data.txId

    if (!txId || !JSUtil.isHexaString(txId) || txId.length > 64) {
      throw new Error('Invalid TXID in object: ' + JSON.stringify(data))
    }

    const outputIndex = data.vout !== undefined ? data.vout : data.outputIndex
    if (typeof outputIndex !== 'number') {
      throw new Error('Invalid outputIndex, received ' + outputIndex)
    }

    Preconditions.checkArgument(
      data.scriptPubKey !== undefined || data.script !== undefined,
      'Must provide the scriptPubKey for that output!',
    )

    const script = new Script(data.scriptPubKey || data.script!)

    Preconditions.checkArgument(
      data.amount !== undefined || data.satoshis !== undefined,
      'Must provide an amount for the output',
    )

    let amount: number
    if (data.amount !== undefined) {
      amount = Number(Unit.fromXPI(data.amount).toSatoshis())
    } else if (data.satoshis !== undefined) {
      amount =
        typeof data.satoshis === 'bigint'
          ? Number(data.satoshis)
          : data.satoshis
    } else {
      throw new Error('No amount provided')
    }

    Preconditions.checkArgument(
      typeof amount === 'number',
      'Amount must be a number',
    )

    this.address = address
    this.txId = txId
    this.outputIndex = outputIndex
    this.script = script
    this.satoshis = amount

    // Store Taproot metadata if provided
    if (data.internalPubKey) {
      if (data.internalPubKey instanceof PublicKey) {
        this.internalPubKey = data.internalPubKey
      } else if (Buffer.isBuffer(data.internalPubKey)) {
        this.internalPubKey = new PublicKey(data.internalPubKey)
      } else if (typeof data.internalPubKey === 'string') {
        this.internalPubKey = new PublicKey(data.internalPubKey)
      }
    }
    this.merkleRoot = data.merkleRoot

    // Store MuSig2 Taproot metadata if provided
    this.keyAggContext = data.keyAggContext
    this.mySignerIndex = data.mySignerIndex
  }

  /**
   * Get the amount in XPI
   */
  getXPI(): number {
    return this.satoshis / 1000000
  }

  /**
   * Get the amount as a Unit object
   */
  getUnit(): Unit {
    return Unit.fromSatoshis(this.satoshis)
  }

  /**
   * Check if this unspent output is valid
   */
  isValid(): boolean {
    return (
      JSUtil.isHexaString(this.txId) &&
      this.txId.length === 64 &&
      this.outputIndex >= 0 &&
      this.satoshis > 0 &&
      this.script.isValid()
    )
  }

  /**
   * Check if this unspent output is dust
   */
  isDust(dustThreshold: number = 546): boolean {
    return this.satoshis < dustThreshold
  }

  /**
   * Convert to object representation
   */
  toObject(): UnspentOutputObject {
    return {
      address: this.address ? this.address.toString() : undefined,
      txid: this.txId,
      vout: this.outputIndex,
      scriptPubKey: this.script.toBuffer().toString('hex'),
      amount: Unit.fromSatoshis(this.satoshis).toXPI(),
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
    return (
      '<UnspentOutput: ' +
      this.txId +
      ':' +
      this.outputIndex +
      ', satoshis: ' +
      this.satoshis +
      ', address: ' +
      this.address +
      '>'
    )
  }

  /**
   * Clone this unspent output
   */
  clone(): UnspentOutput {
    return new UnspentOutput({
      txId: this.txId,
      outputIndex: this.outputIndex,
      script: this.script.clone(),
      satoshis: this.satoshis,
      address: this.address,
      internalPubKey: this.internalPubKey,
      merkleRoot: this.merkleRoot,
      keyAggContext: this.keyAggContext,
      mySignerIndex: this.mySignerIndex,
    })
  }

  /**
   * String representation: just "txid:index"
   */
  toString(): string {
    return this.txId + ':' + this.outputIndex
  }

  /**
   * Check if this unspent output is a pay-to-public-key-hash output
   */
  isPayToPublicKeyHash(): boolean {
    return this.script.isPayToPublicKeyHash()
  }

  /**
   * Check if this unspent output is a pay-to-script-hash output
   */
  isPayToScriptHash(): boolean {
    return this.script.isPayToScriptHash()
  }

  /**
   * Get the address for this unspent output
   */
  getAddress(): string | null {
    try {
      const addressInfo = this.script.getAddressInfo()
      return addressInfo ? addressInfo.toString() : null
    } catch (e) {
      return null
    }
  }

  /**
   * Create from a list of unspent outputs
   */
  static fromObject(obj: UnspentOutputData): UnspentOutput {
    return new UnspentOutput(obj)
  }

  /**
   * Create from a list of unspent outputs
   */
  static fromObjects(objects: UnspentOutputData[]): UnspentOutput[] {
    return objects.map(obj => new UnspentOutput(obj))
  }

  /**
   * Filter unspent outputs by address
   */
  static filterByAddress(
    unspentOutputs: UnspentOutput[],
    address: string | Address,
  ): UnspentOutput[] {
    const addressStr =
      typeof address === 'string' ? address : address.toString()
    return unspentOutputs.filter(utxo => {
      const utxoAddress = utxo.getAddress()
      return utxoAddress === addressStr
    })
  }

  /**
   * Filter unspent outputs by minimum amount
   */
  static filterByMinAmount(
    unspentOutputs: UnspentOutput[],
    minAmount: number | bigint,
  ): UnspentOutput[] {
    const minSatoshis =
      typeof minAmount === 'bigint' ? Number(minAmount) : minAmount
    return unspentOutputs.filter(utxo => utxo.satoshis >= minSatoshis)
  }

  /**
   * Calculate total amount of unspent outputs
   */
  static calculateTotal(unspentOutputs: UnspentOutput[]): number {
    return unspentOutputs.reduce((total, utxo) => total + utxo.satoshis, 0)
  }

  /**
   * Select unspent outputs for a target amount (simple selection)
   */
  static selectForAmount(
    unspentOutputs: UnspentOutput[],
    targetAmount: number | bigint,
  ): UnspentOutput[] {
    const targetSatoshis =
      typeof targetAmount === 'bigint' ? Number(targetAmount) : targetAmount
    const selected: UnspentOutput[] = []
    let total = 0

    // Sort by amount (largest first for efficiency)
    const sorted = [...unspentOutputs].sort((a, b) => b.satoshis - a.satoshis)

    for (const utxo of sorted) {
      selected.push(utxo)
      total += utxo.satoshis
      if (total >= targetSatoshis) {
        break
      }
    }

    return selected
  }
}

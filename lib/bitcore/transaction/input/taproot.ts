/**
 * TaprootInput - Input for spending Taproot outputs
 *
 * Bitcore-compatible specialized input for Lotus Taproot scripts.
 * Supports both key-path and script-path spending.
 *
 * Used by nft.ts for NFT transfer transactions.
 */

import { Script } from '../../script'
import { PublicKey } from '../../publickey'
import { Input, type InputData } from '../input'
import type { Buffer } from 'buffer/'

/**
 * Additional data for Taproot input construction
 */
export interface TaprootInputData extends InputData {
  /** Internal public key for the Taproot output */
  internalPubKey?: PublicKey
  /** Merkle root of the tap tree */
  merkleRoot?: Buffer
  /** Control block for script-path spending */
  controlBlock?: Buffer
  /** Tap script for script-path spending */
  tapScript?: Script
}

/**
 * Input for spending Taproot outputs (key-path or script-path)
 */
export class TaprootInput extends Input {
  /** Internal public key for the Taproot output */
  internalPubKey?: PublicKey
  /** Merkle root of the tap tree */
  merkleRoot?: Buffer
  /** Control block for script-path spending */
  controlBlock?: Buffer
  /** Tap script for script-path spending */
  tapScript?: Script

  constructor(data?: TaprootInputData) {
    super(data)
    if (data) {
      this.internalPubKey = data.internalPubKey
      this.merkleRoot = data.merkleRoot
      this.controlBlock = data.controlBlock
      this.tapScript = data.tapScript
    }
  }
}

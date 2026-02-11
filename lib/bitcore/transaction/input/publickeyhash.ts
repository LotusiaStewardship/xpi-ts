/**
 * PublicKeyHashInput - Input for spending P2PKH outputs
 *
 * Bitcore-compatible specialized input for Pay-to-Public-Key-Hash scripts.
 * This is the most common input type used by wallet applications.
 *
 * Used by lotus-bot: new Input.PublicKeyHash({ prevTxId, outputIndex, output, script })
 */

import { Input, type InputData } from '../input'

/**
 * Alias type for Bitcore compat: InputData with Bitcore-style property names
 */
export type PublicKeyHashInputData = InputData

/**
 * Input for spending Pay-to-Public-Key-Hash (P2PKH) outputs
 */
export class PublicKeyHashInput extends Input {
  constructor(data?: InputData) {
    super(data)
  }
}

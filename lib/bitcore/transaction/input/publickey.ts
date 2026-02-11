/**
 * PublicKeyInput - Input for spending P2PK outputs
 *
 * Bitcore-compatible specialized input for Pay-to-Public-Key scripts.
 */

import { Input, type InputData } from '../input'

/**
 * Input for spending Pay-to-Public-Key (P2PK) outputs
 */
export class PublicKeyInput extends Input {
  constructor(data?: InputData) {
    super(data)
  }
}

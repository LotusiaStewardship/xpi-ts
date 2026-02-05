/**
 * MultisigScriptHashInput - Input for spending P2SH multisig outputs
 *
 * Bitcore-compatible specialized input for Pay-to-Script-Hash multisig scripts.
 */

import { Input, type InputData } from '../input'

/**
 * Input for spending Pay-to-Script-Hash multisig outputs
 */
export class MultisigScriptHashInput extends Input {
  constructor(data?: InputData) {
    super(data)
  }
}

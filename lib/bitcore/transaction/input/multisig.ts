/**
 * MultisigInput - Input for spending bare multisig outputs
 *
 * Bitcore-compatible specialized input for bare multisig scripts.
 */

import { Input, type InputData } from '../input'

/**
 * Input for spending bare multisig outputs
 */
export class MultisigInput extends Input {
  constructor(data?: InputData) {
    super(data)
  }
}

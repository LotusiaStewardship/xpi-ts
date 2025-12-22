/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */
import { MAX_OP_RETURN_OUTPUTS } from '../../utils/constants.js'
import { Transaction } from '../bitcore/transaction/index.js'
import { type TransactionRNKC, ScriptProcessor } from '../rank/index.js'

export function processTransaction(tx: Transaction | Buffer | string) {
  // TODO: Implement transaction processing
  if (typeof tx === 'string') {
    if (!/^[a-fA-F0-9]+$/.test(tx)) {
      throw new Error('Invalid transaction string format')
    }
    tx = Transaction.fromString(tx)
  } else if (tx instanceof Buffer) {
    tx = Transaction.fromBuffer(tx)
  }
}
/**
 * Convert a bitcore transaction to an RNKC transaction
 * @param tx - The bitcore transaction to convert
 * @param scriptProcessor - Optional instantiated `ScriptProcessor` for the transaction
 * @returns The RNKC transaction, ready to be indexed
 */
/* export function fromBitcoreToRNKC(
  tx: Transaction,
  scriptProcessor?: ScriptProcessor,
): TransactionRNKC | null {
  // If no script processor is provided, create a new one from outIdx 0
  if (!scriptProcessor) {
    scriptProcessor = new ScriptProcessor(tx.outputs[0].script.toBuffer())
  }
  // Add supplemental scripts to the ScriptProcessor
  // Maximum of 2 supplemental scripts (outIdx 1 and 2)
  for (const output of tx.outputs.slice(1, MAX_OP_RETURN_OUTPUTS)) {
    // if we can't add the next script, abandon the loop and process
    // the RNKC data we have so far
    if (!scriptProcessor.addScript(output.script.toBuffer())) {
      break
    }
  }
  const rnkc = scriptProcessor.processScriptRNKC(tx.outputs[0].satoshis)
  // If the RNKC is invalid, return current result object
  if (!rnkc) {
    return null
  }
  return {
    txid: tx.txid,
    outIdx: 0, // RNKC is always the first output
    firstSeen,
    scriptPayload,
    height: block?.height, // undefined if mempool tx
    sats: BigInt(tx.outputs[0].satoshis),
    timestamp: block?.timestamp, // undefined until block is connected
    ...rnkc,
  }
} */

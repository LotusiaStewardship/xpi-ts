export {
  Input,
  MultisigInput,
  MultisigScriptHashInput,
  PublicKeyInput,
  PublicKeyHashInput,
  TaprootInput,
  MuSigTaprootInput,
} from './input.js'
export { Output } from './output.js'
export { UnspentOutput } from './unspentoutput.js'
export { sighash, sign, verify } from './sighash.js'
export { TransactionSignature } from './signature.js'
export { Transaction } from './transaction.js'

export type { InputData, InputObject } from './input.js'
export type { OutputData, OutputObject } from './output.js'
export type { UnspentOutputData, UnspentOutputObject } from './unspentoutput.js'
export type {
  TransactionSignatureData,
  TransactionSignatureObject,
} from './signature.js'
export type { TransactionData, TransactionObject } from './transaction.js'

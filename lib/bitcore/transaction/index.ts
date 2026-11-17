export {
  Input,
  MultisigInput,
  MultisigScriptHashInput,
  PublicKeyInput,
  PublicKeyHashInput,
  TaprootInput,
  MuSig2TaprootInput,
} from './input'
export { Output } from './output'
export { UnspentOutput } from './unspentoutput'
export { sighash, sign, verify } from './sighash'
export {
  SIGHASH_FORK_VALUE_DEFAULT,
  SIGHASH_FORK_VALUE_REPLAY_PROTECTED,
  REPLAY_PROTECTION_ACTIVATION_TIME,
  isKnownSighashForkValue,
  getSighashForkValue,
  withSighashForkValue,
  replayProtectionFlagsForForkValue,
  getReplayProtectionActivationTime,
  isReplayProtectionEnabledForNextBlock,
  getNextBlockSighashForkValue,
  REPLAY_PROTECTION_ACTIVATION_TIME_ENV,
  REPLAY_PROTECTION_DEFAULT_MARGIN_SECONDS,
  getReplayProtectionWindow,
  isReplayProtectionRefusal,
  getSighashForkValueForTransaction,
} from './replayprotection'
export type {
  NextBlockForkValueArgs,
  ReplayProtectionStatus,
  ReplayProtectionWindowArgs,
  TimeLockedTransactionLike,
} from './replayprotection'
export { TransactionSignature } from './signature'
export { Transaction } from './transaction'

export type { InputData, InputObject } from './input'
export type { OutputData, OutputObject } from './output'
export type { UnspentOutputData, UnspentOutputObject } from './unspentoutput'
export type {
  TransactionSignatureData,
  TransactionSignatureObject,
} from './signature'
export type { TransactionData, TransactionObject } from './transaction'
export type { CoinbaseData, CoinbaseScriptSigData } from './transaction'

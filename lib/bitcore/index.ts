/**
 * Main exports for lotus-lib
 * All modules migrated from bitcore-lib-xpi with ESM and BigInt support
 */

// Crypto modules
export { Hash } from './crypto/hash'
export { Random } from './crypto/random'
export { Point } from './crypto/point'
export { Signature } from './crypto/signature'
export { ECDSA } from './crypto/ecdsa'
export { Schnorr } from './crypto/schnorr'
export { BN } from './crypto/bn'

// MuSig2 module
export {
  muSig2KeyAgg,
  muSig2NonceGen,
  muSig2NonceAgg,
  muSig2PartialSign,
  muSig2PartialSigVerify,
  muSig2SigAgg,
  muSig2TaggedHash,
  type MuSig2KeyAggContext,
  type MuSig2Nonce,
  type MuSig2AggregatedNonce,
} from './crypto/musig2'

// MuSig2 session management
export {
  MuSigSessionManager,
  MuSigSessionPhase,
  type MuSigSession,
} from './musig2/session'

// MuSig2 high-level wrapper (simplified API)
export {
  MuSig2Signer,
  createMuSig2Signer,
  type MuSig2SignerConfig,
  type MuSig2PrepareResult,
  type MuSig2SignResult,
  type MuSig2TaprootSignResult,
} from './musig2/signer'

// Taproot + MuSig2 integration
export {
  buildMuSig2TaprootKey,
  buildMuSig2TaprootKeyWithScripts,
  signTaprootKeyPathWithMuSig2,
  verifyTaprootKeyPathMuSigPartial,
  isMuSigTaprootOutput,
  createMuSigTaprootAddress,
  type MuSig2TaprootKeyResult,
} from './taproot/musig2'

// Sigtype utility functions
export {
  isSchnorrSignature,
  isECDSASignature,
  getSignatureType,
  isValidSignatureLength,
} from './crypto/sigtype'

// Key modules
export { PrivateKey } from './privatekey'
export { PublicKey } from './publickey'
export { HDPrivateKey } from './hdprivatekey'
export { HDPublicKey } from './hdpublickey'

// Utility modules
export { JSUtil } from './util/js'
export { Preconditions } from './util/preconditions'
export { Base32 } from './util/base32'
export { convertBits } from './util/convertBits'
export { BufferUtil, NULL_HASH, EMPTY_BUFFER } from './util/buffer'

// Error handling
export { BitcoreError } from './errors'

// Encoding modules
export { Base58 } from './encoding/base58'
export { Base58Check } from './encoding/base58check'
export { BufferReader } from './encoding/bufferreader'
export { BufferWriter } from './encoding/bufferwriter'
export { Varint } from './encoding/varint'

// Network modules
export {
  Network,
  livenet,
  testnet,
  regtest,
  networks,
  defaultNetwork,
  get as getNetwork,
  add as addNetwork,
  remove as removeNetwork,
  Networks,
  type NetworkName,
} from './networks'

// Address modules
export { Address } from './address'
export { XAddress } from './xaddress'

// Script modules
export { Script, ScriptTypes, type ScriptType } from './script'
export { Opcode } from './opcode'
export { Interpreter } from './script/interpreter'
export { Chunk } from './script/chunk'

// Unit module
export { Unit } from './unit'

// Message module
export { Message } from './message'

// URI module
export { URI } from './uri'

// Transaction components
export {
  Input,
  MultisigInput,
  MultisigScriptHashInput,
  PublicKeyInput,
  PublicKeyHashInput,
  TaprootInput,
  Output,
  UnspentOutput,
  sighash,
  sign,
  verify,
  TransactionSignature,
  Transaction,
} from './transaction'

// Sighash constants
export {
  DEFAULT_SIGN_FLAGS,
  SIGHASH_SINGLE_BUG,
  BITS_64_ON,
} from './transaction/sighash'

// Taproot modules
export {
  // functions
  applyTweakToPublicKey,
  buildKeyPathTaproot,
  buildPayToTaproot,
  buildScriptPathTaproot,
  buildTapTree,
  calculateTapBranch,
  calculateTapLeaf,
  calculateTapTweak,
  createControlBlock,
  extractTaprootCommitment,
  extractTaprootState,
  isTapLeafNode,
  isTapBranchNode,
  taggedHash,
  tweakPublicKey,
  tweakPrivateKey,
  verifyTaprootCommitment,
  verifyTaprootScriptPath,
  verifyTaprootScriptPathFromControlBlock,
  verifyTaprootSpend,
  // constants
  TAPROOT_LEAF_MASK,
  TAPROOT_LEAF_TAPSCRIPT,
  TAPROOT_CONTROL_BASE_SIZE,
  TAPROOT_CONTROL_NODE_SIZE,
  TAPROOT_CONTROL_MAX_NODE_COUNT,
  TAPROOT_CONTROL_MAX_SIZE,
  TAPROOT_SCRIPTTYPE,
  TAPROOT_INTRO_SIZE,
  TAPROOT_SIGHASH_TYPE,
  TAPROOT_SIZE_WITHOUT_STATE,
  TAPROOT_SIZE_WITH_STATE,
  TAPROOT_ANNEX_TAG,
  // types
  type TapLeafNode,
  type TapBranchNode,
  type TapNode,
  type TapLeaf,
  type TapTreeBuildResult,
  type TaprootVerifyResult,
} from './script/taproot'

// Block components
export { Block, BlockHeader, MerkleBlock } from './block'

// Mnemonic components
export {
  type MnemonicInput,
  Mnemonic,
  MnemonicError,
  pbkdf2,
  Words,
} from './mnemonic'

// TypeScript type exports
export type {
  InputData,
  InputObject,
  OutputData,
  OutputObject,
  UnspentOutputData,
  UnspentOutputObject,
  TransactionSignatureData,
  TransactionSignatureObject,
  TransactionData,
  TransactionObject,
} from './transaction'

export type {
  BlockData,
  BlockObject,
  BlockHeaderData,
  BlockHeaderObject,
  MerkleBlockData,
  MerkleBlockObject,
} from './block'

// Additional interface exports for commonly used types
export type { NetworkConfig } from './networks'

export type {
  PrivateKeyData,
  PrivateKeyObject,
  PrivateKeySerialized,
} from './privatekey'

export type {
  PublicKeyData,
  PublicKeyExtra,
  PublicKeyObject,
  PublicKeySerialized,
} from './publickey'

export type {
  HDPrivateKeyData,
  HDPrivateKeyObject,
  HDPrivateKeyBuffers,
  HDPrivateKeyInput,
} from './hdprivatekey'

export type {
  HDPublicKeyData,
  HDPublicKeyObject,
  HDPublicKeyBuffers,
  HDPublicKeyInput,
} from './hdpublickey'

export type { AddressData, AddressObject, CashAddressDecoding } from './address'

export type { XAddressData, XAddressObject } from './xaddress'

export type { ScriptData } from './script'

export type { URIParams } from './uri'

export type { UnitData } from './unit'

export type { TransactionLike } from './transaction/sighash'

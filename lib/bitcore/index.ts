/**
 * Main exports for lotus-lib
 * All modules migrated from bitcore-lib-xpi with ESM and BigInt support
 */

// Crypto modules
//export { BigIntUtil } from './crypto/bigint.js'
export { Hash } from './crypto/hash.js'
export { Random } from './crypto/random.js'
export { Point } from './crypto/point.js'
export { Signature } from './crypto/signature.js'
export { ECDSA } from './crypto/ecdsa.js'
export { Schnorr } from './crypto/schnorr.js'
export { BN } from './crypto/bn.js'

// MuSig2 module
export {
  musigKeyAgg,
  musigNonceGen,
  musigNonceAgg,
  musigPartialSign,
  musigPartialSigVerify,
  musigSigAgg,
  musigTaggedHash,
  type MuSigKeyAggContext,
  type MuSigNonce,
  type MuSigAggregatedNonce,
} from './crypto/musig2.js'

// MuSig2 session management
export {
  MuSigSessionManager,
  MuSigSessionPhase,
  type MuSigSession,
} from './musig2/session.js'

export {
  // MuSig2 high-level wrapper (simplified API)
  MuSig2Signer,
  createMuSig2Signer,
  type MuSig2SignerConfig,
  type MuSig2PrepareResult,
  type MuSig2SignResult,
  type MuSig2TaprootSignResult,
} from './musig2/signer.js'

// Taproot + MuSig2 integration
export {
  buildMuSigTaprootKey,
  buildMuSigTaprootKeyWithScripts,
  signTaprootKeyPathWithMuSig2,
  verifyTaprootKeyPathMuSigPartial,
  isMuSigTaprootOutput,
  createMuSigTaprootAddress,
  type MuSigTaprootKeyResult,
} from './taproot/musig2.js'

// Key modules
export { PrivateKey } from './privatekey.js'
export { PublicKey } from './publickey.js'
export { HDPrivateKey } from './hdprivatekey.js'
export { HDPublicKey } from './hdpublickey.js'

// Utility modules
export { JSUtil } from './util/js.js'
export { Preconditions } from './util/preconditions.js'
export { Base32 } from './util/base32.js'
export { convertBits } from './util/convertBits.js'
export { BufferUtil, NULL_HASH, EMPTY_BUFFER } from './util/buffer.js'
export { util } from './util.js'

// Error handling
export { BitcoreError } from './errors.js'

// Encoding modules
export { Base58 } from './encoding/base58.js'
export { Base58Check } from './encoding/base58check.js'
export { BufferReader } from './encoding/bufferreader.js'
export { BufferWriter, BufferWriterFactory } from './encoding/bufferwriter.js'
export { Varint } from './encoding/varint.js'

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
} from './networks.js'

// Address modules
export { Address } from './address.js'
export { XAddress } from './xaddress.js'

// Script modules
export { Script } from './script.js'
export { Opcode } from './opcode.js'
export { Interpreter } from './script/interpreter.js'
export { Chunk } from './chunk.js'
export { type ScriptType, ScriptTypes, toAddress, empty } from './script.js'

// Unit module
export { Unit } from './unit.js'

// Message module
export { Message } from './message.js'

// URI module
export { URI } from './uri.js'

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
} from './transaction/index.js'

// Sighash constants
export {
  DEFAULT_SIGN_FLAGS,
  SIGHASH_SINGLE_BUG,
  BITS_64_ON,
} from './transaction/sighash.js'

// Taproot modules
export {
  // functions
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
  isPayToTaproot,
  isTapLeafNode,
  isTapBranchNode,
  taggedHash,
  tweakPublicKey,
  tweakPrivateKey,
  verifyTaprootCommitment,
  verifyTaprootScriptPath,
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
} from './taproot.js'

// NFT modules
export { NFT, NFTUtil } from './taproot/nft.js'

export type {
  NFTMetadata,
  NFTAttribute,
  NFTCollectionMetadata,
  NFTData,
  NFTTransfer,
  NFTMintConfig,
  NFTTransferConfig,
  NFTUtxo,
  NFTWithScriptPath,
  NFTWithCollection,
  NFTInfo,
  NFTObject,
} from './taproot/nft.js'

// Block components
export { Block, BlockHeader } from './block/index.js'

// Mnemonic components
export { Mnemonic, MnemonicError, pbkdf2, Words } from './mnemonic/index.js'

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
} from './transaction/index.js'

export type {
  BlockData,
  BlockObject,
  BlockHeaderData,
  BlockHeaderObject,
} from './block/index.js'

// Additional interface exports for commonly used types
export type { NetworkConfig } from './networks.js'

export type {
  PrivateKeyData,
  PrivateKeyObject,
  PrivateKeySerialized,
} from './privatekey.js'

export type {
  PublicKeyData,
  PublicKeyExtra,
  PublicKeyObject,
  PublicKeySerialized,
} from './publickey.js'

export type {
  HDPrivateKeyData,
  HDPrivateKeyObject,
  HDPrivateKeyBuffers,
} from './hdprivatekey.js'

export type {
  HDPublicKeyData,
  HDPublicKeyObject,
  HDPublicKeyBuffers,
} from './hdpublickey.js'

export type {
  AddressData,
  AddressObject,
  CashAddressDecoding,
} from './address.js'

export type { XAddressData, XAddressObject } from './xaddress.js'

export type { ScriptData } from './script.js'

export type { TaprootVerifyResult } from './taproot.js'

export type { URIParams } from './uri.js'

export type { UnitData } from './unit.js'

export type { TransactionLike } from './transaction/sighash.js'

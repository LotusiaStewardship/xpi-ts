/**
 * NFT Implementation for Lotus Taproot
 *
 * Implements NFT creation, transfer, and verification using Taproot's 32-byte state parameter.
 * The state parameter contains a hash commitment to off-chain NFT metadata.
 *
 * Key Features:
 * - Compact on-chain storage (69 bytes per NFT)
 * - Provable metadata commitments via SHA256 hashing
 * - Privacy via key path transfers
 * - Flexible trading mechanisms via script trees
 * - Collection support with shared attributes
 *
 * Reference: lotus-website/app/content/6.docs/specs/2.script/examples/taproot-nfts.md
 *
 * @module NFT
 */

import { Hash } from '../crypto/hash.js'
import { PublicKey } from '../publickey.js'
import { PrivateKey } from '../privatekey.js'
import { Script } from '../script.js'
import {
  buildScriptPathTaproot,
  buildKeyPathTaproot,
  extractTaprootCommitment,
  extractTaprootState,
  isPayToTaproot,
  type TapNode,
  type TapLeaf,
} from '../taproot.js'
import { Transaction } from '../transaction/transaction.js'
import { Output } from '../transaction/output.js'
import { TaprootInput } from '../transaction/input.js'
import {
  UnspentOutput,
  UnspentOutputData,
} from '../transaction/unspentoutput.js'
import { Signature } from '../crypto/signature.js'
import { Address } from '../address.js'
import { Network } from '../networks.js'

/**
 * Standard NFT metadata structure
 * Compatible with OpenSea and other marketplaces
 */
export interface NFTMetadata {
  /** NFT name */
  name: string
  /** NFT description */
  description: string
  /** Image URI (IPFS CID, Arweave, or URL) */
  image: string
  /** Optional attributes/traits */
  attributes?: NFTAttribute[]
  /** Optional collection identifier */
  collection?: string
  /** Optional creator address */
  creator?: string
  /** Optional external URL */
  external_url?: string
  /** Optional animation URL */
  animation_url?: string
  /** Optional background color (hex code without #) */
  background_color?: string
}

/**
 * NFT attribute/trait
 */
export interface NFTAttribute {
  /** Trait type (e.g., "Rarity", "Color") */
  trait_type: string
  /** Trait value */
  value: string | number
  /** Optional display type */
  display_type?: 'number' | 'boost_percentage' | 'boost_number' | 'date'
}

/**
 * Collection metadata structure
 */
export interface NFTCollectionMetadata {
  /** Collection name */
  name: string
  /** Collection description */
  description: string
  /** Total supply */
  totalSupply: number
  /** Creator address */
  creator: string
  /** Optional royalty percentage (0-100) */
  royalty?: number
  /** Optional collection image */
  image?: string
  /** Optional external URL */
  external_url?: string
}

/**
 * NFT data interface (plain object representation)
 */
export interface NFTData {
  /** Taproot script locking the NFT */
  script: Script
  /** NFT address */
  address: Address
  /** Metadata hash (32 bytes, stored on-chain) */
  metadataHash: Buffer
  /** Full metadata (stored off-chain) */
  metadata: NFTMetadata
  /** NFT value in satoshis */
  satoshis: number
  /** Optional transaction ID if minted */
  txid?: string
  /** Optional output index if minted */
  outputIndex?: number
}

/**
 * NFT transfer record for provenance tracking
 */
export interface NFTTransfer {
  /** Transaction ID */
  txid: string
  /** Sender address (null for mint) */
  from: string | null
  /** Recipient address */
  to: string
  /** Metadata hash (must remain constant) */
  metadataHash: string
  /** Timestamp */
  timestamp: number
  /** Optional block height */
  blockHeight?: number
}

/**
 * NFT minting configuration
 */
export interface NFTMintConfig {
  /** Owner's private key */
  ownerKey: PrivateKey
  /** NFT metadata */
  metadata: NFTMetadata
  /** NFT value in satoshis (default: 1000 = 0.001 XPI) */
  satoshis?: number
  /** Optional collection hash */
  collectionHash?: Buffer
  /** Network (default: livenet) */
  network?: Network
}

/**
 * NFT UTXO information
 */
export interface NFTUtxo {
  /** Transaction ID */
  txid: string
  /** Output index */
  outputIndex: number
  /** Taproot script with state */
  script: Script
  /** NFT value in satoshis */
  satoshis: number
}

/**
 * NFT transfer configuration
 */
export interface NFTTransferConfig {
  /** Current owner's private key */
  currentOwnerKey: PrivateKey
  /** New owner's public key */
  newOwnerKey: PublicKey
  /** Current NFT UTXO */
  nftUtxo: NFTUtxo
  /** Metadata hash (must match UTXO) */
  metadataHash: Buffer
  /** Optional fee in satoshis */
  fee?: number
}

/**
 * NFT with script path information
 */
export interface NFTWithScriptPath extends NFTData {
  /** Commitment public key */
  commitment: PublicKey
  /** Merkle root of script tree */
  merkleRoot: Buffer
  /** Array of leaf scripts with merkle paths */
  leaves: TapLeaf[]
}

/**
 * NFT that belongs to a collection
 */
export interface NFTWithCollection extends NFTData {
  /** Collection hash identifier */
  collectionHash: Buffer
}

/**
 * NFT information extracted from script
 */
export interface NFTInfo {
  /** Commitment public key from script */
  commitment: PublicKey
  /** Metadata hash from state parameter */
  metadataHash: Buffer
  /** NFT address */
  address: Address
}

/**
 * NFT JSON serialization format
 */
export interface NFTObject {
  /** Script as hex string */
  script: string
  /** Address as string */
  address: string
  /** Metadata hash as hex string */
  metadataHash: string
  /** Full metadata object */
  metadata: NFTMetadata
  /** NFT value in satoshis */
  satoshis: number
  /** Optional transaction ID */
  txid?: string
  /** Optional output index */
  outputIndex?: number
  /** Optional commitment (hex) */
  commitment?: string
  /** Optional merkle root (hex) */
  merkleRoot?: string
  /** Optional collection hash (hex) */
  collectionHash?: string
}

/**
 * NFT Class - Represents a Lotus NFT instance
 *
 * This class provides an object-oriented interface for working with NFTs.
 * It wraps NFT data and provides methods for common operations like
 * transferring, verifying, and updating NFT state.
 *
 * @example
 * ```typescript
 * // Create a new NFT
 * const nft = new NFT({
 *   metadata: { name: 'My NFT', description: '...', image: 'ipfs://...' },
 *   ownerKey: privateKey.publicKey,
 *   satoshis: 1000,
 * })
 *
 * // Transfer to new owner
 * const transferTx = nft.transfer(newOwnerKey, currentOwnerPrivateKey)
 *
 * // Verify metadata
 * const isValid = nft.verifyMetadata()
 * ```
 */
export class NFT {
  private _script: Script
  private _address: Address
  private _metadataHash: Buffer
  private _metadata: NFTMetadata
  private _satoshis: number
  private _txid?: string
  private _outputIndex?: number
  private _commitment?: PublicKey
  private _merkleRoot?: Buffer
  private _leaves?: TapLeaf[]
  private _collectionHash?: Buffer

  /**
   * Create a new NFT instance
   *
   * @param config - NFT configuration
   */
  constructor(config: {
    /** NFT metadata */
    metadata: NFTMetadata
    /** Owner's public key */
    ownerKey: PublicKey
    /** NFT value in satoshis (default: 1000) */
    satoshis?: number
    /** Network (default: livenet) */
    network?: Network
    /** Optional script tree for advanced spending conditions */
    scriptTree?: TapNode
    /** Optional collection hash for collection NFTs */
    collectionHash?: Buffer
    /** Optional transaction ID if already minted */
    txid?: string
    /** Optional output index if already minted */
    outputIndex?: number
  }) {
    this._metadata = config.metadata
    this._satoshis = config.satoshis || 1000
    this._txid = config.txid
    this._outputIndex = config.outputIndex
    this._collectionHash = config.collectionHash

    // Compute metadata hash
    if (config.collectionHash) {
      this._metadataHash = NFTUtil.hashCollectionNFT(
        config.collectionHash,
        config.metadata,
      )
    } else {
      this._metadataHash = NFTUtil.hashMetadata(config.metadata)
    }

    // Create script based on configuration
    if (config.scriptTree) {
      const result = buildScriptPathTaproot(
        config.ownerKey,
        config.scriptTree,
        this._metadataHash,
      )
      this._script = result.script
      this._commitment = result.commitment
      this._merkleRoot = result.merkleRoot
      this._leaves = result.leaves
    } else {
      this._script = buildKeyPathTaproot(config.ownerKey, this._metadataHash)
    }

    const address = this._script.toAddress(config.network)
    if (!address) {
      throw new Error('Failed to create address from script')
    }
    this._address = address
  }

  /**
   * Create NFT instance from existing script
   *
   * @param script - Taproot script with state
   * @param metadata - NFT metadata
   * @param satoshis - NFT value
   * @param txid - Optional transaction ID
   * @param outputIndex - Optional output index
   * @returns NFT instance
   */
  static fromScript(
    script: Script,
    metadata: NFTMetadata,
    satoshis: number,
    txid?: string,
    outputIndex?: number,
  ): NFT {
    if (!isPayToTaproot(script)) {
      throw new Error('Script is not a valid Pay-To-Taproot script')
    }

    const metadataHash = extractTaprootState(script)
    if (!metadataHash) {
      throw new Error('Script does not have state parameter')
    }

    // Verify metadata matches the on-chain hash
    const computedHash = NFTUtil.hashMetadata(metadata)
    if (!computedHash.equals(metadataHash)) {
      throw new Error('Metadata does not match on-chain hash')
    }

    const address = script.toAddress()
    if (!address) {
      throw new Error('Failed to create address from script')
    }

    // Create a minimal instance
    const nft = Object.create(NFT.prototype)
    nft._script = script
    nft._address = address
    nft._metadataHash = metadataHash
    nft._metadata = metadata
    nft._satoshis = satoshis
    nft._txid = txid
    nft._outputIndex = outputIndex

    return nft
  }

  /**
   * Create NFT instance from UTXO
   *
   * @param utxo - Unspent output or NFT UTXO information
   * @param metadata - NFT metadata
   * @returns NFT instance
   */
  static fromUTXO(
    utxo: UnspentOutput | NFTUtxo | UnspentOutputData,
    metadata: NFTMetadata,
  ): NFT {
    // Handle different UTXO types
    if (utxo instanceof UnspentOutput) {
      return NFT.fromScript(
        utxo.script,
        metadata,
        utxo.satoshis,
        utxo.txId,
        utxo.outputIndex,
      )
    }

    // Handle UnspentOutputData or NFTUtxo
    const scriptData =
      'script' in utxo ? utxo.script : (utxo as UnspentOutputData).scriptPubKey
    if (!scriptData) {
      throw new Error('UTXO must have script or scriptPubKey')
    }

    const script =
      scriptData instanceof Script ? scriptData : new Script(scriptData)

    const txid =
      'txId' in utxo && utxo.txId ? utxo.txId : (utxo as NFTUtxo).txid
    const outputIndex =
      'outputIndex' in utxo
        ? utxo.outputIndex
        : (utxo as UnspentOutputData).vout

    const satoshis =
      'satoshis' in utxo && typeof utxo.satoshis === 'number'
        ? utxo.satoshis
        : 'amount' in utxo && utxo.amount
          ? utxo.amount * 1000000
          : 1000

    return NFT.fromScript(script, metadata, satoshis, txid, outputIndex)
  }

  // Getters
  get script(): Script {
    return this._script
  }

  get address(): Address {
    return this._address
  }

  get metadataHash(): Buffer {
    return this._metadataHash
  }

  get metadata(): NFTMetadata {
    return this._metadata
  }

  get satoshis(): number {
    return this._satoshis
  }

  get txid(): string | undefined {
    return this._txid
  }

  get outputIndex(): number | undefined {
    return this._outputIndex
  }

  get commitment(): PublicKey | undefined {
    return this._commitment
  }

  get merkleRoot(): Buffer | undefined {
    return this._merkleRoot
  }

  get leaves(): TapLeaf[] | undefined {
    return this._leaves
  }

  get collectionHash(): Buffer | undefined {
    return this._collectionHash
  }

  /**
   * Check if this NFT has script tree (script path spending)
   */
  hasScriptTree(): boolean {
    return this._leaves !== undefined && this._leaves.length > 0
  }

  /**
   * Check if this NFT belongs to a collection
   */
  isCollectionNFT(): boolean {
    return this._collectionHash !== undefined
  }

  /**
   * Verify that the metadata matches the on-chain hash
   *
   * @returns true if metadata is valid
   */
  verifyMetadata(): boolean {
    return NFTUtil.verifyMetadata(this._metadata, this._metadataHash)
  }

  /**
   * Create a transfer transaction to a new owner
   *
   * @param newOwnerKey - New owner's public key
   * @param currentOwnerKey - Current owner's private key
   * @param fee - Optional transaction fee in satoshis
   * @returns Signed transfer transaction
   *
   * @throws Error if NFT doesn't have UTXO information
   */
  transfer(
    newOwnerKey: PublicKey,
    currentOwnerKey: PrivateKey,
    fee?: number,
  ): Transaction {
    if (!this._txid || this._outputIndex === undefined) {
      throw new Error(
        'Cannot transfer NFT without UTXO information (txid and outputIndex)',
      )
    }

    return NFTUtil.transferNFT({
      currentOwnerKey,
      newOwnerKey,
      nftUtxo: {
        txid: this._txid,
        outputIndex: this._outputIndex,
        script: this._script,
        satoshis: this._satoshis,
      },
      metadataHash: this._metadataHash,
      fee,
    })
  }

  /**
   * Update the UTXO information after the NFT is minted or transferred
   *
   * @param txid - Transaction ID
   * @param outputIndex - Output index
   */
  updateUTXO(txid: string, outputIndex: number): void {
    this._txid = txid
    this._outputIndex = outputIndex
  }

  /**
   * Get comprehensive NFT information
   *
   * @returns NFT info object
   */
  getInfo(): NFTInfo {
    const commitment =
      this._commitment || extractTaprootCommitment(this._script)

    return {
      commitment,
      metadataHash: this._metadataHash,
      address: this._address,
    }
  }

  /**
   * Create an Output object for this NFT
   *
   * @returns Output instance
   */
  toOutput(): Output {
    return new Output({
      script: this._script,
      satoshis: this._satoshis,
    })
  }

  /**
   * Create an UnspentOutput object for this NFT
   *
   * @returns UnspentOutput instance
   * @throws Error if NFT doesn't have UTXO information
   */
  toUnspentOutput(): UnspentOutput {
    if (!this._txid || this._outputIndex === undefined) {
      throw new Error(
        'Cannot create UnspentOutput without UTXO information (txid and outputIndex)',
      )
    }

    return new UnspentOutput({
      txid: this._txid,
      outputIndex: this._outputIndex,
      script: this._script,
      satoshis: this._satoshis,
      address: this._address,
    })
  }

  /**
   * Get NFT UTXO information
   *
   * @returns NFT UTXO data
   * @throws Error if NFT doesn't have UTXO information
   */
  getUtxo(): NFTUtxo {
    if (!this._txid || this._outputIndex === undefined) {
      throw new Error(
        'Cannot get UTXO without transaction information (txid and outputIndex)',
      )
    }

    return {
      txid: this._txid,
      outputIndex: this._outputIndex,
      script: this._script,
      satoshis: this._satoshis,
    }
  }

  /**
   * Serialize NFT to JSON
   *
   * @returns JSON representation
   */
  toJSON(): NFTObject {
    return {
      script: this._script.toBuffer().toString('hex'),
      address: this._address.toString(),
      metadataHash: this._metadataHash.toString('hex'),
      metadata: this._metadata,
      satoshis: this._satoshis,
      txid: this._txid,
      outputIndex: this._outputIndex,
      commitment: this._commitment?.toString(),
      merkleRoot: this._merkleRoot?.toString('hex'),
      collectionHash: this._collectionHash?.toString('hex'),
    }
  }

  /**
   * Serialize NFT to a plain object matching the NFTData interface
   *
   * @returns NFTData interface object
   */
  toObject(): NFTData {
    return {
      script: this._script,
      address: this._address,
      metadataHash: this._metadataHash,
      metadata: this._metadata,
      satoshis: this._satoshis,
      txid: this._txid,
      outputIndex: this._outputIndex,
    }
  }

  /**
   * Get string representation of the NFT
   *
   * @returns String representation
   */
  toString(): string {
    return `NFT(${this._metadata.name}, ${this._address.toString()})`
  }
}

/**
 * NFT Utility Class
 */
export class NFTUtil {
  /**
   * Hash NFT metadata to 32-byte commitment
   *
   * Creates a SHA256 hash of the JSON-stringified metadata.
   * This hash is stored in the Taproot state parameter on-chain.
   *
   * @param metadata - NFT metadata object
   * @returns 32-byte hash
   *
   * @example
   * ```typescript
   * const metadata = {
   *   name: 'Lotus NFT #1',
   *   description: 'First NFT',
   *   image: 'ipfs://Qm...',
   * }
   * const hash = NFTUtil.hashMetadata(metadata)
   * console.log(hash.toString('hex')) // 32-byte hex string
   * ```
   */
  static hashMetadata(metadata: NFTMetadata): Buffer {
    const metadataJSON = JSON.stringify(metadata)
    return Hash.sha256(Buffer.from(metadataJSON, 'utf8'))
  }

  /**
   * Hash collection metadata
   *
   * @param collectionInfo - Collection metadata
   * @returns 32-byte hash
   */
  static hashCollection(collectionInfo: NFTCollectionMetadata): Buffer {
    const collectionJSON = JSON.stringify(collectionInfo)
    return Hash.sha256(Buffer.from(collectionJSON, 'utf8'))
  }

  /**
   * Create combined hash for collection NFT
   *
   * Combines collection hash with individual NFT metadata for
   * NFTs that belong to a collection.
   *
   * @param collectionHash - Collection hash
   * @param nftMetadata - Individual NFT metadata
   * @returns 32-byte combined hash
   */
  static hashCollectionNFT(
    collectionHash: Buffer,
    nftMetadata: NFTMetadata,
  ): Buffer {
    const combinedData = {
      collection: collectionHash.toString('hex'),
      nft: nftMetadata,
    }
    const combinedJSON = JSON.stringify(combinedData)
    return Hash.sha256(Buffer.from(combinedJSON, 'utf8'))
  }

  /**
   * Verify metadata matches hash
   *
   * @param metadata - NFT metadata
   * @param hash - Claimed hash
   * @returns true if metadata matches hash
   */
  static verifyMetadata(metadata: NFTMetadata, hash: Buffer): boolean {
    const computedHash = NFTUtil.hashMetadata(metadata)
    return computedHash.equals(hash)
  }

  /**
   * Verify collection NFT metadata
   *
   * @param collectionHash - Collection hash
   * @param nftMetadata - NFT metadata
   * @param hash - Claimed combined hash
   * @returns true if metadata matches hash
   */
  static verifyCollectionNFT(
    collectionHash: Buffer,
    nftMetadata: NFTMetadata,
    hash: Buffer,
  ): boolean {
    const computedHash = NFTUtil.hashCollectionNFT(collectionHash, nftMetadata)
    return computedHash.equals(hash)
  }

  /**
   * Extract state from NFT script
   *
   * @param script - Taproot script
   * @returns Metadata hash or null if no state
   * @throws Error if not a valid Taproot script
   */
  static extractMetadataHash(script: Script): Buffer | null {
    if (!isPayToTaproot(script)) {
      throw new Error('Script is not a valid Pay-To-Taproot script')
    }
    return extractTaprootState(script)
  }

  /**
   * Create a simple key-path NFT
   *
   * Creates an NFT with key-path-only spending (maximum privacy).
   * The NFT can be transferred by signing with the owner's key.
   *
   * @param ownerKey - Owner's public key
   * @param metadata - NFT metadata
   * @param satoshis - NFT value in satoshis (default: 1000)
   * @param network - Network (default: livenet)
   * @returns NFTData instance
   *
   * @example
   * ```typescript
   * const ownerKey = new PrivateKey()
   * const metadata = {
   *   name: 'My NFT',
   *   description: 'A unique collectible',
   *   image: 'ipfs://Qm...',
   * }
   * const nft = NFTUtil.createKeyPathNFT(ownerKey.publicKey, metadata)
   * console.log('NFT address:', nft.address.toString())
   * console.log('Metadata hash:', nft.metadataHash.toString('hex'))
   * ```
   */
  static createKeyPathNFT(
    ownerKey: PublicKey,
    metadata: NFTMetadata,
    satoshis: number = 1000,
    network?: Network,
  ): NFTData {
    // Hash the metadata
    const metadataHash = NFTUtil.hashMetadata(metadata)

    // Create key-path-only Taproot output with state
    const script = buildKeyPathTaproot(ownerKey, metadataHash)

    // Create address
    const address = script.toAddress(network)
    if (!address) {
      throw new Error('Failed to create address from script')
    }

    return {
      script,
      address,
      metadataHash,
      metadata,
      satoshis,
    }
  }

  /**
   * Create an NFT with script tree (for trading, escrow, etc.)
   *
   * @param ownerKey - Owner's public key
   * @param metadata - NFT metadata
   * @param scriptTree - Taproot script tree
   * @param satoshis - NFT value in satoshis (default: 1000)
   * @param network - Network (default: livenet)
   * @returns NFT instance with script tree info
   */
  static createScriptPathNFT(
    ownerKey: PublicKey,
    metadata: NFTMetadata,
    scriptTree: TapNode,
    satoshis: number = 1000,
    network?: Network,
  ): NFTWithScriptPath {
    const metadataHash = NFTUtil.hashMetadata(metadata)

    const { script, commitment, merkleRoot, leaves } = buildScriptPathTaproot(
      ownerKey,
      scriptTree,
      metadataHash,
    )

    const address = script.toAddress(network)
    if (!address) {
      throw new Error('Failed to create address from script')
    }

    return {
      script,
      address,
      metadataHash,
      metadata,
      satoshis,
      commitment,
      merkleRoot,
      leaves,
    }
  }

  /**
   * Create a collection NFT
   *
   * Creates an NFT that belongs to a collection. The metadata hash includes
   * both the collection identifier and individual NFT metadata.
   *
   * @param ownerKey - Owner's public key
   * @param collectionHash - Collection hash
   * @param nftMetadata - Individual NFT metadata
   * @param satoshis - NFT value in satoshis (default: 1000)
   * @param network - Network
   * @returns NFT instance with collection info
   */
  static createCollectionNFT(
    ownerKey: PublicKey,
    collectionHash: Buffer,
    nftMetadata: NFTMetadata,
    satoshis: number = 1000,
    network?: Network,
  ): NFTWithCollection {
    const metadataHash = NFTUtil.hashCollectionNFT(collectionHash, nftMetadata)

    const script = buildKeyPathTaproot(ownerKey, metadataHash)
    const address = script.toAddress(network)
    if (!address) {
      throw new Error('Failed to create address from script')
    }

    return {
      script,
      address,
      metadataHash,
      metadata: nftMetadata,
      satoshis,
      collectionHash,
    }
  }

  /**
   * Mint a single NFT
   *
   * Creates a transaction that mints an NFT by creating a Taproot output
   * with metadata commitment in the state parameter.
   *
   * Note: This function creates the output structure. You need to add inputs
   * and sign the transaction.
   *
   * @param config - Mint configuration
   * @returns Transaction with NFT output (needs inputs and signing)
   *
   * @example
   * ```typescript
   * const tx = NFTUtil.mintNFT({
   *   ownerKey: privateKey,
   *   metadata: {
   *     name: 'My NFT',
   *     description: 'A unique collectible',
   *     image: 'ipfs://Qm...',
   *   },
   *   satoshis: 1000,
   * })
   *
   * // Add funding input and change output
   * tx.from(utxo)
   * tx.change(changeAddress)
   * tx.sign(privateKey)
   * ```
   */
  static mintNFT(config: NFTMintConfig): Transaction {
    const nft = NFTUtil.createKeyPathNFT(
      config.ownerKey.publicKey,
      config.metadata,
      config.satoshis || 1000,
      config.network,
    )

    const tx = new Transaction()
    tx.addOutput(
      new Output({
        script: nft.script,
        satoshis: nft.satoshis,
      }),
    )

    return tx
  }

  /**
   * Mint multiple NFTs in a single transaction (batch minting)
   *
   * @param ownerKey - Owner's private key
   * @param nftMetadataList - Array of NFT metadata
   * @param satoshisPerNFT - Value per NFT (default: 1000)
   * @param network - Network
   * @returns Transaction with multiple NFT outputs
   */
  static mintBatch(
    ownerKey: PrivateKey,
    nftMetadataList: NFTMetadata[],
    satoshisPerNFT: number = 1000,
    network?: Network,
  ): Transaction {
    const tx = new Transaction()

    for (const metadata of nftMetadataList) {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        satoshisPerNFT,
        network,
      )

      tx.addOutput(
        new Output({
          script: nft.script,
          satoshis: nft.satoshis,
        }),
      )
    }

    return tx
  }

  /**
   * Mint a collection of NFTs
   *
   * @param ownerKey - Owner's private key
   * @param collectionInfo - Collection metadata
   * @param nftMetadataList - Array of individual NFT metadata
   * @param satoshisPerNFT - Value per NFT (default: 1000)
   * @param network - Network
   * @returns Transaction with collection NFT outputs
   */
  static mintCollection(
    ownerKey: PrivateKey,
    collectionInfo: NFTCollectionMetadata,
    nftMetadataList: NFTMetadata[],
    satoshisPerNFT: number = 1000,
    network?: Network,
  ): Transaction {
    const collectionHash = NFTUtil.hashCollection(collectionInfo)
    const tx = new Transaction()

    for (const nftMetadata of nftMetadataList) {
      const nft = NFTUtil.createCollectionNFT(
        ownerKey.publicKey,
        collectionHash,
        nftMetadata,
        satoshisPerNFT,
        network,
      )

      tx.addOutput(
        new Output({
          script: nft.script,
          satoshis: nft.satoshis,
        }),
      )
    }

    return tx
  }

  /**
   * Transfer an NFT to a new owner (key path)
   *
   * Creates a transaction that transfers an NFT by spending the current
   * NFT UTXO and creating a new NFT output for the new owner with the
   * same metadata hash.
   *
   * @param config - Transfer configuration
   * @returns Signed transaction ready to broadcast
   *
   * @example
   * ```typescript
   * const transferTx = NFTUtil.transferNFT({
   *   currentOwnerKey: currentOwner,
   *   newOwnerKey: newOwner.publicKey,
   *   nftUtxo: {
   *     txid: 'abc123...',
   *     outputIndex: 0,
   *     script: nftScript,
   *     satoshis: 1000,
   *   },
   *   metadataHash: metadataHash,
   * })
   *
   * console.log('Transfer TX:', transferTx.serialize())
   * ```
   */
  static transferNFT(config: NFTTransferConfig): Transaction {
    const { currentOwnerKey, newOwnerKey, nftUtxo, metadataHash, fee } = config

    // Verify input script has the correct metadata hash
    const inputState = NFTUtil.extractMetadataHash(nftUtxo.script)
    if (!inputState || !inputState.equals(metadataHash)) {
      throw new Error('Input script metadata hash does not match')
    }

    // Create new NFT output for recipient with same metadata hash
    const newNFTScript = buildKeyPathTaproot(newOwnerKey, metadataHash)

    // Calculate output value (subtract fee if specified)
    const outputSatoshis = fee ? nftUtxo.satoshis - fee : nftUtxo.satoshis

    if (outputSatoshis < 546) {
      throw new Error('Output value below dust limit (546 satoshis)')
    }

    // Create transaction
    const tx = new Transaction()

    // Add NFT input
    tx.addInput(
      new TaprootInput({
        prevTxId: Buffer.from(nftUtxo.txid, 'hex'),
        outputIndex: nftUtxo.outputIndex,
        output: new Output({
          script: nftUtxo.script,
          satoshis: nftUtxo.satoshis,
        }),
        script: new Script(), // Empty script for key path
      }),
    )

    // Add new NFT output
    tx.addOutput(
      new Output({
        script: newNFTScript,
        satoshis: outputSatoshis,
      }),
    )

    // Sign with Schnorr + SIGHASH_LOTUS
    tx.sign(
      currentOwnerKey,
      Signature.SIGHASH_ALL | Signature.SIGHASH_LOTUS,
      'schnorr',
    )

    return tx
  }

  /**
   * Validate NFT transfer preserves metadata
   *
   * Verifies that an NFT transfer maintains the same metadata hash
   * from input to output, ensuring NFT authenticity.
   *
   * @param inputScript - Input script
   * @param outputScript - Output script
   * @returns true if metadata hash is preserved
   */
  static validateTransfer(inputScript: Script, outputScript: Script): boolean {
    const inputState = NFTUtil.extractMetadataHash(inputScript)
    const outputState = NFTUtil.extractMetadataHash(outputScript)

    if (!inputState || !outputState) {
      return false
    }

    return inputState.equals(outputState)
  }

  /**
   * Trace NFT provenance
   *
   * Verifies that all transfers in the provenance chain maintain the
   * same metadata hash, proving authenticity from mint to current owner.
   *
   * @param transfers - Array of transfers (chronological order)
   * @returns true if provenance is valid
   */
  static verifyProvenance(transfers: NFTTransfer[]): boolean {
    if (transfers.length === 0) {
      return false
    }

    const originalHash = transfers[0].metadataHash

    for (const transfer of transfers) {
      if (transfer.metadataHash !== originalHash) {
        return false
      }
    }

    return true
  }

  /**
   * Check if a script is an NFT (has state parameter)
   *
   * @param script - Script to check
   * @returns true if script is an NFT
   */
  static isNFT(script: Script): boolean {
    if (!isPayToTaproot(script)) {
      return false
    }
    const state = extractTaprootState(script)
    return state !== null
  }

  /**
   * Get NFT info from script
   *
   * @param script - NFT script
   * @returns NFT information
   * @throws Error if not a valid NFT
   */
  static getNFTInfo(script: Script): NFTInfo {
    if (!NFTUtil.isNFT(script)) {
      throw new Error('Script is not an NFT')
    }

    const commitment = extractTaprootCommitment(script)
    const metadataHash = extractTaprootState(script)!
    const address = script.toAddress()
    if (!address) {
      throw new Error('Failed to create address from NFT script')
    }

    return {
      commitment,
      metadataHash,
      address,
    }
  }
}

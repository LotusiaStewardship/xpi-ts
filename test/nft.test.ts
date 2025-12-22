/**
 * NFT Module Tests
 *
 * Comprehensive tests for Taproot-based NFT implementation
 */

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert'
import {
  PrivateKey,
  PublicKey,
  NFTUtil,
  Hash,
  Script,
  Opcode,
  Transaction,
  isPayToTaproot,
  buildKeyPathTaproot,
  extractTaprootState,
  Output,
  Networks,
  TapNode,
  NFTMetadata,
  NFTCollectionMetadata,
} from '../lib/bitcore/index.js'

describe('NFT Module', () => {
  let ownerKey: PrivateKey
  let metadata: NFTMetadata
  let metadataHash: Buffer

  beforeEach(() => {
    ownerKey = new PrivateKey(undefined, Networks.regtest)
    metadata = {
      name: 'Test NFT',
      description: 'A test NFT',
      image: 'ipfs://QmTest123',
      attributes: [
        { trait_type: 'Rarity', value: 'Common' },
        { trait_type: 'Edition', value: '1/10' },
      ],
    }
    metadataHash = NFTUtil.hashMetadata(metadata)
  })

  describe('Metadata Hashing', () => {
    it('should hash metadata to 32 bytes', () => {
      const hash = NFTUtil.hashMetadata(metadata)
      assert.strictEqual(hash.length, 32)
      assert.ok(Buffer.isBuffer(hash))
    })

    it('should produce consistent hashes for same metadata', () => {
      const hash1 = NFTUtil.hashMetadata(metadata)
      const hash2 = NFTUtil.hashMetadata(metadata)
      assert.ok(hash1.equals(hash2))
    })

    it('should produce different hashes for different metadata', () => {
      const metadata2 = { ...metadata, name: 'Different NFT' }
      const hash1 = NFTUtil.hashMetadata(metadata)
      const hash2 = NFTUtil.hashMetadata(metadata2)
      assert.ok(!hash1.equals(hash2))
    })

    it('should verify metadata against hash', () => {
      const hash = NFTUtil.hashMetadata(metadata)
      assert.ok(NFTUtil.verifyMetadata(metadata, hash))
    })

    it('should reject invalid metadata', () => {
      const hash = NFTUtil.hashMetadata(metadata)
      const fakeMetadata = { ...metadata, name: 'Fake NFT' }
      assert.ok(!NFTUtil.verifyMetadata(fakeMetadata, hash))
    })
  })

  describe('Collection Hashing', () => {
    let collectionInfo: NFTCollectionMetadata

    beforeEach(() => {
      collectionInfo = {
        name: 'Test Collection',
        description: 'A test collection',
        totalSupply: 100,
        creator: ownerKey.toAddress().toString(),
        royalty: 5,
      }
    })

    it('should hash collection metadata', () => {
      const hash = NFTUtil.hashCollection(collectionInfo)
      assert.strictEqual(hash.length, 32)
    })

    it('should create combined hash for collection NFT', () => {
      const collectionHash = NFTUtil.hashCollection(collectionInfo)
      const combinedHash = NFTUtil.hashCollectionNFT(collectionHash, metadata)
      assert.strictEqual(combinedHash.length, 32)
    })

    it('should verify collection NFT metadata', () => {
      const collectionHash = NFTUtil.hashCollection(collectionInfo)
      const combinedHash = NFTUtil.hashCollectionNFT(collectionHash, metadata)
      assert.ok(
        NFTUtil.verifyCollectionNFT(collectionHash, metadata, combinedHash),
      )
    })
  })

  describe('NFT Creation', () => {
    it('should create key-path NFT', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      assert.ok(nft.script)
      assert.ok(nft.address)
      assert.strictEqual(nft.metadataHash.length, 32)
      assert.deepStrictEqual(nft.metadata, metadata)
      assert.strictEqual(nft.satoshis, 1000)
    })

    it('should create NFT script with state', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const script = nft.script
      assert.ok(isPayToTaproot(script))

      const state = extractTaprootState(script)
      assert.ok(state)
      assert.ok(state.equals(metadataHash))
    })

    it('should create script-path NFT', () => {
      const script1 = new Script()
        .add(ownerKey.publicKey.toBuffer())
        .add(Opcode.OP_CHECKSIG)

      const tree: TapNode = { script: script1 }

      const nft = NFTUtil.createScriptPathNFT(
        ownerKey.publicKey,
        metadata,
        tree,
        1000,
        Networks.regtest,
      )

      assert.ok(nft.script)
      assert.ok(nft.commitment)
      assert.ok(nft.merkleRoot)
      assert.ok(nft.leaves)
      assert.strictEqual(nft.leaves.length, 1)
    })

    it('should create collection NFT', () => {
      const collectionInfo: NFTCollectionMetadata = {
        name: 'Test Collection',
        description: 'A test collection',
        totalSupply: 100,
        creator: ownerKey.toAddress().toString(),
      }

      const collectionHash = NFTUtil.hashCollection(collectionInfo)
      const nft = NFTUtil.createCollectionNFT(
        ownerKey.publicKey,
        collectionHash,
        metadata,
        1000,
        Networks.regtest,
      )

      assert.ok(nft.script)
      assert.ok(nft.address)
      assert.ok(nft.collectionHash)
      assert.ok(nft.collectionHash.equals(collectionHash))
    })
  })

  describe('NFT Minting', () => {
    it('should create mint transaction', () => {
      const tx = NFTUtil.mintNFT({
        ownerKey,
        metadata,
        satoshis: 1000,
        network: Networks.regtest,
      })

      assert.ok(tx instanceof Transaction)
      assert.strictEqual(tx.outputs.length, 1)
      assert.strictEqual(tx.outputs[0].satoshis, 1000)
      assert.ok(isPayToTaproot(tx.outputs[0].script))
    })

    it('should batch mint NFTs', () => {
      const metadataList = [
        { ...metadata, name: 'NFT #1' },
        { ...metadata, name: 'NFT #2' },
        { ...metadata, name: 'NFT #3' },
      ]

      const tx = NFTUtil.mintBatch(
        ownerKey,
        metadataList,
        1000,
        Networks.regtest,
      )

      assert.strictEqual(tx.outputs.length, 3)
      for (let i = 0; i < 3; i++) {
        assert.strictEqual(tx.outputs[i].satoshis, 1000)
        assert.ok(isPayToTaproot(tx.outputs[i].script))
      }
    })

    it('should mint collection', () => {
      const collectionInfo: NFTCollectionMetadata = {
        name: 'Test Collection',
        description: 'A test collection',
        totalSupply: 5,
        creator: ownerKey.toAddress().toString(),
      }

      const metadataList = Array.from({ length: 5 }, (_, i) => ({
        ...metadata,
        name: `Collection NFT #${i + 1}`,
      }))

      const tx = NFTUtil.mintCollection(
        ownerKey,
        collectionInfo,
        metadataList,
        1000,
        Networks.regtest,
      )

      assert.strictEqual(tx.outputs.length, 5)
    })
  })

  describe('NFT Transfer', () => {
    it('should create transfer transaction', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const newOwner = new PrivateKey(undefined, Networks.regtest)

      const transferTx = NFTUtil.transferNFT({
        currentOwnerKey: ownerKey,
        newOwnerKey: newOwner.publicKey,
        nftUtxo: {
          txid: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
          outputIndex: 0,
          script: nft.script,
          satoshis: 1000,
        },
        metadataHash: nft.metadataHash,
      })

      assert.ok(transferTx instanceof Transaction)
      assert.strictEqual(transferTx.inputs.length, 1)
      assert.strictEqual(transferTx.outputs.length, 1)
      assert.strictEqual(transferTx.outputs[0].satoshis, 1000)
    })

    it('should preserve metadata hash in transfer', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const newOwner = new PrivateKey(undefined, Networks.regtest)

      const transferTx = NFTUtil.transferNFT({
        currentOwnerKey: ownerKey,
        newOwnerKey: newOwner.publicKey,
        nftUtxo: {
          txid: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
          outputIndex: 0,
          script: nft.script,
          satoshis: 1000,
        },
        metadataHash: nft.metadataHash,
      })

      const inputState = NFTUtil.extractMetadataHash(nft.script)
      const outputState = NFTUtil.extractMetadataHash(
        transferTx.outputs[0].script,
      )

      assert.ok(inputState)
      assert.ok(outputState)
      assert.ok(inputState.equals(outputState))
    })

    it('should validate transfer', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const newOwner = new PrivateKey(undefined, Networks.regtest)

      const transferTx = NFTUtil.transferNFT({
        currentOwnerKey: ownerKey,
        newOwnerKey: newOwner.publicKey,
        nftUtxo: {
          txid: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
          outputIndex: 0,
          script: nft.script,
          satoshis: 1000,
        },
        metadataHash: nft.metadataHash,
      })

      const isValid = NFTUtil.validateTransfer(
        nft.script,
        transferTx.outputs[0].script,
      )

      assert.ok(isValid)
    })

    it('should reject transfer with mismatched metadata', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const differentMetadata = { ...metadata, name: 'Different NFT' }
      const differentNFT = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        differentMetadata,
        1000,
        Networks.regtest,
      )

      const isValid = NFTUtil.validateTransfer(nft.script, differentNFT.script)

      assert.ok(!isValid)
    })

    it('should reject transfer with wrong metadata hash', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const wrongHash = Buffer.alloc(32, 0xff)
      const newOwner = new PrivateKey(undefined, Networks.regtest)

      assert.throws(() => {
        NFTUtil.transferNFT({
          currentOwnerKey: ownerKey,
          newOwnerKey: newOwner.publicKey,
          nftUtxo: {
            txid: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            outputIndex: 0,
            script: nft.script,
            satoshis: 1000,
          },
          metadataHash: wrongHash,
        })
      })
    })
  })

  describe('NFT Verification', () => {
    it('should identify NFT script', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      assert.ok(NFTUtil.isNFT(nft.script))
    })

    it('should reject non-NFT script', () => {
      const normalScript = new Script()
        .add(ownerKey.publicKey.toBuffer())
        .add(Opcode.OP_CHECKSIG)

      assert.ok(!NFTUtil.isNFT(normalScript))
    })

    it('should extract NFT info', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const info = NFTUtil.getNFTInfo(nft.script)

      assert.ok(info.commitment)
      assert.strictEqual(info.metadataHash.length, 32)
      assert.ok(info.metadataHash.equals(nft.metadataHash))
      assert.ok(info.address)
    })

    it('should extract metadata hash', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const hash = NFTUtil.extractMetadataHash(nft.script)

      assert.ok(hash)
      assert.strictEqual(hash.length, 32)
      assert.ok(hash.equals(nft.metadataHash))
    })

    it('should return null for script without state', () => {
      const script = buildKeyPathTaproot(ownerKey.publicKey)
      const hash = NFTUtil.extractMetadataHash(script)
      assert.strictEqual(hash, null)
    })
  })

  describe('Provenance Tracking', () => {
    it('should verify valid provenance chain', () => {
      const transfers = [
        {
          txid: 'mint_tx',
          from: null,
          to: 'lotus:qz1234...',
          metadataHash: metadataHash.toString('hex'),
          timestamp: Date.now() - 30 * 24 * 60 * 60 * 1000,
        },
        {
          txid: 'transfer1_tx',
          from: 'lotus:qz1234...',
          to: 'lotus:qz5678...',
          metadataHash: metadataHash.toString('hex'),
          timestamp: Date.now() - 15 * 24 * 60 * 60 * 1000,
        },
        {
          txid: 'transfer2_tx',
          from: 'lotus:qz5678...',
          to: 'lotus:qz9012...',
          metadataHash: metadataHash.toString('hex'),
          timestamp: Date.now(),
        },
      ]

      assert.ok(NFTUtil.verifyProvenance(transfers))
    })

    it('should reject provenance with changed metadata', () => {
      const differentHash = Buffer.alloc(32, 0xff)

      const transfers = [
        {
          txid: 'mint_tx',
          from: null,
          to: 'lotus:qz1234...',
          metadataHash: metadataHash.toString('hex'),
          timestamp: Date.now() - 30 * 24 * 60 * 60 * 1000,
        },
        {
          txid: 'transfer1_tx',
          from: 'lotus:qz1234...',
          to: 'lotus:qz5678...',
          metadataHash: differentHash.toString('hex'), // Changed!
          timestamp: Date.now(),
        },
      ]

      assert.ok(!NFTUtil.verifyProvenance(transfers))
    })

    it('should reject empty provenance', () => {
      assert.ok(!NFTUtil.verifyProvenance([]))
    })
  })

  describe('Script Size', () => {
    it('should create 69-byte NFT script', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const scriptSize = nft.script.toBuffer().length
      assert.strictEqual(scriptSize, 69) // OP_SCRIPTTYPE + OP_1 + 33-byte commitment + 32-byte state
    })

    it('should have correct script structure', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const buf = nft.script.toBuffer()

      // OP_SCRIPTTYPE
      assert.strictEqual(buf[0], Opcode.OP_SCRIPTTYPE)
      // OP_1
      assert.strictEqual(buf[1], Opcode.OP_1)
      // 33-byte push
      assert.strictEqual(buf[2], 33)
      // Commitment (33 bytes)
      const commitment = buf.subarray(3, 36)
      assert.strictEqual(commitment.length, 33)
      // 32-byte push
      assert.strictEqual(buf[36], 32)
      // State (32 bytes)
      const state = buf.subarray(37, 69)
      assert.strictEqual(state.length, 32)
      assert.ok(state.equals(metadataHash))
    })
  })

  describe('Error Handling', () => {
    it('should throw on non-NFT script info extraction', () => {
      const normalScript = new Script()
        .add(ownerKey.publicKey.toBuffer())
        .add(Opcode.OP_CHECKSIG)

      assert.throws(() => {
        NFTUtil.getNFTInfo(normalScript)
      })
    })

    it('should throw on non-Taproot script metadata extraction', () => {
      const normalScript = new Script()
        .add(ownerKey.publicKey.toBuffer())
        .add(Opcode.OP_CHECKSIG)

      assert.throws(() => {
        NFTUtil.extractMetadataHash(normalScript)
      })
    })

    it('should throw on dust amount transfer', () => {
      const nft = NFTUtil.createKeyPathNFT(
        ownerKey.publicKey,
        metadata,
        1000,
        Networks.regtest,
      )

      const newOwner = new PrivateKey(undefined, Networks.regtest)

      assert.throws(() => {
        NFTUtil.transferNFT({
          currentOwnerKey: ownerKey,
          newOwnerKey: newOwner.publicKey,
          nftUtxo: {
            txid: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            outputIndex: 0,
            script: nft.script,
            satoshis: 1000,
          },
          metadataHash: nft.metadataHash,
          fee: 500, // Would leave only 500 sats (below 546 dust limit)
        })
      })
    })
  })
})

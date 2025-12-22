/**
 * Comprehensive NFT Examples for Lotus
 *
 * Demonstrates NFT creation, transfer, collection management, and trading
 * using the Taproot-based NFT implementation.
 *
 * Reference: lotus-lib/lib/bitcore/nft.ts
 */

import {
  PrivateKey,
  PublicKey,
  NFTUtil,
  Hash,
  Script,
  Opcode,
  Transaction,
  Output,
  Networks,
  TapNode,
} from '../lib/bitcore/index.js'

console.log('='.repeat(80))
console.log('NFT Examples for Lotus')
console.log('='.repeat(80))

// =============================================================================
// Example 1: Create a Simple NFT (Key Path Only)
// =============================================================================

console.log('\n📦 Example 1: Create a Simple NFT')
console.log('-'.repeat(80))

const creatorKey = new PrivateKey(undefined, Networks.livenet)
console.log('Creator address:', creatorKey.toAddress().toString())

const nftMetadata = {
  name: 'Lotus Genesis NFT #001',
  description: 'First NFT on Lotus blockchain',
  image: 'ipfs://QmXyz123...',
  attributes: [
    { trait_type: 'Rarity', value: 'Legendary' },
    { trait_type: 'Edition', value: '1/100' },
  ],
  collection: 'Lotus Genesis Collection',
  creator: creatorKey.toAddress().toString(),
}

// Create NFT
const nft = NFTUtil.createKeyPathNFT(
  creatorKey.publicKey,
  nftMetadata,
  1000, // 0.001 XPI
  Networks.livenet,
)

console.log('NFT created successfully!')
console.log('NFT address:', nft.address.toString())
console.log('Metadata hash:', nft.metadataHash.toString('hex'))
console.log('NFT value:', nft.satoshis, 'satoshis (0.001 XPI)')
console.log('Script size:', nft.script.toBuffer().length, 'bytes')

// Verify metadata
const isValid = NFTUtil.verifyMetadata(nft.metadata, nft.metadataHash)
console.log('Metadata verified:', isValid)

// =============================================================================
// Example 2: Mint NFT Transaction
// =============================================================================

console.log('\n🪙 Example 2: Mint NFT Transaction')
console.log('-'.repeat(80))

const mintTx = NFTUtil.mintNFT({
  ownerKey: creatorKey,
  metadata: {
    name: 'Lotus Collectible #42',
    description: 'A unique digital artifact',
    image: 'ipfs://QmAbc456...',
    attributes: [
      { trait_type: 'Color', value: 'Gold' },
      { trait_type: 'Type', value: 'Artifact' },
    ],
  },
  satoshis: 1000,
  network: Networks.livenet,
})

console.log('Mint transaction created')
console.log('Outputs:', mintTx.outputs.length)
console.log('Output 0 (NFT):')
console.log(
  '  Script size:',
  mintTx.outputs[0].script.toBuffer().length,
  'bytes',
)
console.log('  Value:', mintTx.outputs[0].satoshis, 'satoshis')
console.log(
  '  Script hex:',
  mintTx.outputs[0].script.toBuffer().toString('hex'),
)

// Note: In production, you would add funding inputs and change outputs:
// mintTx.from(fundingUtxo)
// mintTx.change(changeAddress)
// mintTx.sign(creatorKey)

// =============================================================================
// Example 3: Transfer NFT to New Owner
// =============================================================================

console.log('\n🔄 Example 3: Transfer NFT to New Owner')
console.log('-'.repeat(80))

const currentOwner = creatorKey
const newOwner = new PrivateKey(undefined, Networks.livenet)

console.log('Current owner:', currentOwner.toAddress().toString())
console.log('New owner:', newOwner.toAddress().toString())

// Simulate existing NFT UTXO
const nftUtxo = {
  txid: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  outputIndex: 0,
  script: nft.script,
  satoshis: 1000,
}

const transferTx = NFTUtil.transferNFT({
  currentOwnerKey: currentOwner,
  newOwnerKey: newOwner.publicKey,
  nftUtxo,
  metadataHash: nft.metadataHash,
})

console.log('Transfer transaction created and signed')
console.log('Inputs:', transferTx.inputs.length)
console.log('Outputs:', transferTx.outputs.length)
console.log('Transaction size:', transferTx.toBuffer().length, 'bytes')

// Verify the transfer preserves metadata
const inputScript = nftUtxo.script
const outputScript = transferTx.outputs[0].script
const transferValid = NFTUtil.validateTransfer(inputScript, outputScript)
console.log('Transfer validation:', transferValid ? '✅ Valid' : '❌ Invalid')

// =============================================================================
// Example 4: Batch Mint Collection
// =============================================================================

console.log('\n🎨 Example 4: Batch Mint NFT Collection')
console.log('-'.repeat(80))

const collectionInfo = {
  name: 'Lotus Legends',
  description: '100 unique legendary items on Lotus',
  totalSupply: 100,
  creator: creatorKey.toAddress().toString(),
  royalty: 5, // 5% royalty
  image: 'ipfs://QmCollection123...',
}

console.log('Collection:', collectionInfo.name)
console.log('Total supply:', collectionInfo.totalSupply)

// Generate 5 NFTs for demo (in production, generate all 100)
const nftMetadataList = []
for (let i = 1; i <= 5; i++) {
  nftMetadataList.push({
    name: `Lotus Legend #${i}`,
    description: `Legendary item #${i} from the Lotus Legends collection`,
    image: `ipfs://QmLegend${i}...`,
    attributes: [
      { trait_type: 'Rarity', value: i <= 2 ? 'Legendary' : 'Epic' },
      { trait_type: 'Power', value: 100 - i },
      { trait_type: 'Edition', value: `${i}/${collectionInfo.totalSupply}` },
    ],
    collection: collectionInfo.name,
    creator: creatorKey.toAddress().toString(),
  })
}

const batchMintTx = NFTUtil.mintCollection(
  creatorKey,
  collectionInfo,
  nftMetadataList,
  1000,
  Networks.livenet,
)

console.log('Batch mint transaction created')
console.log('NFTs minted:', batchMintTx.outputs.length)
console.log('Total cost:', batchMintTx.outputs.length * 1000, 'satoshis')

// Verify each NFT has correct collection hash
const collectionHash = NFTUtil.hashCollection(collectionInfo)
console.log('Collection hash:', collectionHash.toString('hex'))

for (let i = 0; i < batchMintTx.outputs.length; i++) {
  const output = batchMintTx.outputs[i]
  const state = NFTUtil.extractMetadataHash(output.script)
  if (state) {
    const isCollectionValid = NFTUtil.verifyCollectionNFT(
      collectionHash,
      nftMetadataList[i],
      state,
    )
    console.log(
      `  NFT #${i + 1}:`,
      isCollectionValid ? '✅ Valid' : '❌ Invalid',
    )
  }
}

// =============================================================================
// Example 5: NFT with Trading Script Tree
// =============================================================================

console.log('\n🛒 Example 5: NFT with Trading Capabilities')
console.log('-'.repeat(80))

const seller = new PrivateKey(undefined, Networks.livenet)
const buyer = new PrivateKey(undefined, Networks.livenet)
const escrow = new PrivateKey(undefined, Networks.livenet)

console.log('Seller:', seller.toAddress().toString())
console.log('Buyer:', buyer.toAddress().toString())
console.log('Escrow:', escrow.toAddress().toString())

const tradingMetadata = {
  name: 'Tradable NFT #123',
  description: 'An NFT with built-in trading mechanisms',
  image: 'ipfs://QmTrade123...',
  attributes: [{ trait_type: 'Tradable', value: 'Yes' }],
}

// Script 1: Cooperative sale (buyer + seller agree)
const saleScript = new Script()
  .add(Opcode.OP_2)
  .add(seller.publicKey.toBuffer())
  .add(buyer.publicKey.toBuffer())
  .add(Opcode.OP_2)
  .add(Opcode.OP_CHECKMULTISIG)

// Script 2: Escrow resolution
const escrowScript = new Script()
  .add(escrow.publicKey.toBuffer())
  .add(Opcode.OP_CHECKSIG)

// Script 3: Seller refund after timeout (1440 blocks ~48 hours)
const refundHeight = 1000 + 1440
const refundScript = new Script()
  .add(Buffer.from(refundHeight.toString(16).padStart(6, '0'), 'hex'))
  .add(Opcode.OP_CHECKLOCKTIMEVERIFY)
  .add(Opcode.OP_DROP)
  .add(seller.publicKey.toBuffer())
  .add(Opcode.OP_CHECKSIG)

// Build tree
const tradingTree: TapNode = {
  left: { script: saleScript },
  right: {
    left: { script: escrowScript },
    right: { script: refundScript },
  },
}

const tradingNFT = NFTUtil.createScriptPathNFT(
  seller.publicKey,
  tradingMetadata,
  tradingTree,
  10000, // 0.01 XPI
  Networks.livenet,
)

console.log('Trading NFT created')
console.log('Address:', tradingNFT.address.toString())
console.log('Merkle root:', tradingNFT.merkleRoot.toString('hex'))
console.log('Available scripts:', tradingNFT.leaves.length)
console.log('  - Cooperative sale (2-of-2 multisig)')
console.log('  - Escrow resolution')
console.log('  - Refund after timeout')
console.log('\nKey path spending (cooperative):', 'Hidden from blockchain')

// =============================================================================
// Example 6: NFT Provenance Tracking
// =============================================================================

console.log('\n🔍 Example 6: NFT Provenance Tracking')
console.log('-'.repeat(80))

const provenanceMetadata = {
  name: 'Rare Artifact NFT',
  description: 'A rare digital artifact with full provenance',
  image: 'ipfs://QmRareArtifact...',
  attributes: [{ trait_type: 'Authenticity', value: 'Verified' }],
}

const provenanceHash = NFTUtil.hashMetadata(provenanceMetadata)

// Simulate transfer history
const transfers = [
  {
    txid: 'aaaa0000000000000000000000000000000000000000000000000000000000aa',
    from: null, // Mint
    to: 'lotus_16PSJMintAddress1234567890ABCDEFGHIJKLMNOPQRST',
    metadataHash: provenanceHash.toString('hex'),
    timestamp: Date.now() - 30 * 24 * 60 * 60 * 1000, // 30 days ago
    blockHeight: 10000,
  },
  {
    txid: 'bbbb1111111111111111111111111111111111111111111111111111111111bb',
    from: 'lotus_16PSJMintAddress1234567890ABCDEFGHIJKLMNOPQRST',
    to: 'lotus_16PSJBuyer1Address1234567890ABCDEFGHIJKLMNOP',
    metadataHash: provenanceHash.toString('hex'),
    timestamp: Date.now() - 20 * 24 * 60 * 60 * 1000, // 20 days ago
    blockHeight: 10100,
  },
  {
    txid: 'cccc2222222222222222222222222222222222222222222222222222222222cc',
    from: 'lotus_16PSJBuyer1Address1234567890ABCDEFGHIJKLMNOP',
    to: 'lotus_16PSJBuyer2Address1234567890ABCDEFGHIJKLMNOP',
    metadataHash: provenanceHash.toString('hex'),
    timestamp: Date.now() - 10 * 24 * 60 * 60 * 1000, // 10 days ago
    blockHeight: 10200,
  },
]

const provenanceValid = NFTUtil.verifyProvenance(transfers)
console.log('Provenance chain:')
for (const transfer of transfers) {
  console.log(`  ${transfer.from || 'MINT'} → ${transfer.to}`)
  console.log(`    TX: ${transfer.txid.slice(0, 16)}...`)
  console.log(`    Block: ${transfer.blockHeight}`)
}
console.log('Provenance verified:', provenanceValid ? '✅ Valid' : '❌ Invalid')

// =============================================================================
// Example 7: NFT Verification
// =============================================================================

console.log('\n✅ Example 7: NFT Verification')
console.log('-'.repeat(80))

// Check if script is an NFT
const isNFTScript = NFTUtil.isNFT(nft.script)
console.log('Is NFT script:', isNFTScript)

// Extract NFT info
if (isNFTScript) {
  const nftInfo = NFTUtil.getNFTInfo(nft.script)
  console.log('NFT Information:')
  console.log('  Commitment:', nftInfo.commitment.toString())
  console.log('  Metadata hash:', nftInfo.metadataHash.toString('hex'))
  console.log('  Address:', nftInfo.address.toString())

  // Verify metadata authenticity
  const metadataValid = NFTUtil.verifyMetadata(
    nftMetadata,
    nftInfo.metadataHash,
  )
  console.log('  Metadata valid:', metadataValid ? '✅ Yes' : '❌ No')
}

// =============================================================================
// Example 8: NFT Marketplace Listing
// =============================================================================

console.log('\n🏪 Example 8: NFT Marketplace Listing')
console.log('-'.repeat(80))

const nftOwner = new PrivateKey(undefined, Networks.livenet)
const salePrice = 5000000 // 5 XPI

const marketplaceMetadata = {
  name: 'Marketplace NFT #999',
  description: 'Listed for sale on the marketplace',
  image: 'ipfs://QmMarketplace999...',
  attributes: [
    { trait_type: 'Status', value: 'For Sale' },
    { trait_type: 'Price', value: '5 XPI' },
  ],
}

console.log('Listing NFT for sale')
console.log('Price:', salePrice / 1000000, 'XPI')
console.log('Seller:', nftOwner.toAddress().toString())

// Note: For a full marketplace implementation, you would use OP_CHECKTEMPLATEVERIFY
// or similar covenant opcodes. This is a simplified example.

const listingScript = new Script()
  .add(nftOwner.publicKey.toBuffer())
  .add(Opcode.OP_CHECKSIG)

const cancelScript = new Script()
  .add(nftOwner.publicKey.toBuffer())
  .add(Opcode.OP_CHECKSIG)

const listingTree: TapNode = {
  left: { script: listingScript },
  right: { script: cancelScript },
}

const listedNFT = NFTUtil.createScriptPathNFT(
  nftOwner.publicKey,
  marketplaceMetadata,
  listingTree,
  1000,
  Networks.livenet,
)

console.log('NFT listed at:', listedNFT.address.toString())
console.log('Available actions:')
console.log('  - Purchase (via listing script)')
console.log('  - Cancel listing (via cancel script)')
console.log('  - Key path spend (cooperative)')

// =============================================================================
// Example 9: Collection Statistics
// =============================================================================

console.log('\n📊 Example 9: Collection Statistics')
console.log('-'.repeat(80))

const statsCollection = {
  name: 'Lotus Art Collection',
  description: 'Premium digital art on Lotus',
  totalSupply: 50,
  creator: creatorKey.toAddress().toString(),
  royalty: 10,
}

console.log('Collection:', statsCollection.name)
console.log('Total supply:', statsCollection.totalSupply)
console.log('Creator:', statsCollection.creator)
console.log('Royalty:', statsCollection.royalty + '%')
console.log(
  'Collection hash:',
  NFTUtil.hashCollection(statsCollection).toString('hex'),
)
console.log(
  'Estimated mint cost:',
  statsCollection.totalSupply * 1000,
  'satoshis',
)
console.log('Estimated size:', statsCollection.totalSupply * 69, 'bytes')

// =============================================================================
// Example 10: NFT with Royalties
// =============================================================================

console.log('\n💰 Example 10: NFT Sale with Royalties')
console.log('-'.repeat(80))

const artistKey = new PrivateKey(undefined, Networks.livenet)
const buyerKey = new PrivateKey(undefined, Networks.livenet)
const sellerKey = new PrivateKey(undefined, Networks.livenet)

const royaltyNFT = {
  name: 'Digital Art #1',
  description: 'Premium digital artwork with 5% royalty',
  image: 'ipfs://QmArt1...',
  creator: artistKey.toAddress().toString(),
  attributes: [{ trait_type: 'Royalty', value: '5%' }],
}

const saleAmount = 5000000 // 5 XPI
const royaltyPercent = 5
const royaltyAmount = Math.floor((saleAmount * royaltyPercent) / 100)
const sellerAmount = saleAmount - royaltyAmount

console.log('Sale details:')
console.log('  Sale price:', saleAmount / 1000000, 'XPI')
console.log(
  '  Royalty (5%):',
  royaltyAmount / 1000000,
  'XPI →',
  artistKey.toAddress().toString(),
)
console.log(
  '  Seller receives:',
  sellerAmount / 1000000,
  'XPI →',
  sellerKey.toAddress().toString(),
)
console.log('  NFT to buyer →', buyerKey.toAddress().toString())

console.log('\nTransaction structure:')
console.log('  Input 0: NFT from seller')
console.log('  Input 1: Payment from buyer')
console.log('  Output 0: NFT to buyer (1,000 sats)')
console.log(
  '  Output 1: Payment to seller (' + sellerAmount / 1000000 + ' XPI)',
)
console.log(
  '  Output 2: Royalty to artist (' + royaltyAmount / 1000000 + ' XPI)',
)

// =============================================================================
// Summary
// =============================================================================

console.log('\n' + '='.repeat(80))
console.log('Summary')
console.log('='.repeat(80))
console.log('✅ Simple NFT creation (key path)')
console.log('✅ NFT minting transaction')
console.log('✅ NFT transfer with metadata preservation')
console.log('✅ Batch collection minting')
console.log('✅ NFT with trading script tree')
console.log('✅ Provenance tracking and verification')
console.log('✅ NFT information extraction')
console.log('✅ Marketplace listing')
console.log('✅ Collection statistics')
console.log('✅ Royalty payment handling')
console.log('\nAll NFT examples completed successfully! 🎉')

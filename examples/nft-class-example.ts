/**
 * NFT Class Usage Examples
 *
 * Demonstrates the object-oriented NFT class interface
 */

import {
  PrivateKey,
  NFT,
  NFTUtil,
  Networks,
  Script,
  Opcode,
  TapNode,
} from '../lib/bitcore/index.js'

console.log('='.repeat(80))
console.log('NFT Class Examples')
console.log('='.repeat(80))

// =============================================================================
// Example 1: Create NFT using class constructor
// =============================================================================

console.log('\n📦 Example 1: Create NFT using class constructor')
console.log('-'.repeat(80))

const ownerKey = new PrivateKey(undefined, Networks.livenet)

const nft = new NFT({
  metadata: {
    name: 'Lotus Art #1',
    description: 'A beautiful digital artwork',
    image: 'ipfs://QmArt123...',
    attributes: [
      { trait_type: 'Artist', value: 'Digital Creator' },
      { trait_type: 'Style', value: 'Abstract' },
    ],
  },
  ownerKey: ownerKey.publicKey,
  satoshis: 1000,
  network: Networks.livenet,
})

console.log('NFT created:', nft.toString())
console.log('Address:', nft.address.toString())
console.log('Metadata hash:', nft.metadataHash.toString('hex'))
console.log('Satoshis:', nft.satoshis)
console.log('Has script tree:', nft.hasScriptTree())
console.log('Is collection NFT:', nft.isCollectionNFT())

// Verify metadata
const isValid = nft.verifyMetadata()
console.log('Metadata verified:', isValid ? '✅' : '❌')

// =============================================================================
// Example 2: Create NFT with script tree
// =============================================================================

console.log('\n🌳 Example 2: Create NFT with script tree')
console.log('-'.repeat(80))

const sellerKey = new PrivateKey(undefined, Networks.livenet)
const buyerKey = new PrivateKey(undefined, Networks.livenet)

// Create a simple trading script
const tradingScript = new Script()
  .add(Opcode.OP_2)
  .add(sellerKey.publicKey.toBuffer())
  .add(buyerKey.publicKey.toBuffer())
  .add(Opcode.OP_2)
  .add(Opcode.OP_CHECKMULTISIG)

const scriptTree: TapNode = {
  script: tradingScript,
}

const tradingNFT = new NFT({
  metadata: {
    name: 'Tradable NFT #42',
    description: 'NFT with built-in trading mechanism',
    image: 'ipfs://QmTrade42...',
  },
  ownerKey: sellerKey.publicKey,
  scriptTree,
  satoshis: 5000,
  network: Networks.livenet,
})

console.log('Trading NFT created:', tradingNFT.toString())
console.log('Has script tree:', tradingNFT.hasScriptTree())
console.log('Number of leaves:', tradingNFT.leaves?.length)
console.log('Merkle root:', tradingNFT.merkleRoot?.toString('hex'))

// =============================================================================
// Example 3: Create collection NFT
// =============================================================================

console.log('\n🎨 Example 3: Create collection NFT')
console.log('-'.repeat(80))

const collectionInfo = {
  name: 'Lotus Collection',
  description: 'Premium NFT collection',
  totalSupply: 100,
  creator: ownerKey.toAddress().toString(),
  royalty: 5,
}

const collectionHash = NFTUtil.hashCollection(collectionInfo)

const collectionNFT = new NFT({
  metadata: {
    name: 'Collection Item #1',
    description: 'First item in the collection',
    image: 'ipfs://QmCollection1...',
    attributes: [
      { trait_type: 'Number', value: '1' },
      { trait_type: 'Rarity', value: 'Legendary' },
    ],
  },
  ownerKey: ownerKey.publicKey,
  collectionHash,
  satoshis: 1000,
  network: Networks.livenet,
})

console.log('Collection NFT created:', collectionNFT.toString())
console.log('Is collection NFT:', collectionNFT.isCollectionNFT())
console.log('Collection hash:', collectionNFT.collectionHash?.toString('hex'))

// =============================================================================
// Example 4: Load NFT from script (simulating blockchain retrieval)
// =============================================================================

console.log('\n🔄 Example 4: Load NFT from existing script')
console.log('-'.repeat(80))

// Simulate loading an NFT from blockchain
const existingNFT = NFT.fromScript(
  nft.script,
  nft.metadata,
  nft.satoshis,
  'abc123...', // Mock txid
  0, // output index
)

console.log('Loaded NFT:', existingNFT.toString())
console.log('TXID:', existingNFT.txid)
console.log('Output index:', existingNFT.outputIndex)

// =============================================================================
// Example 5: Transfer NFT (with UTXO info)
// =============================================================================

console.log('\n➡️  Example 5: Transfer NFT')
console.log('-'.repeat(80))

// Create NFT with UTXO information
const nftWithUTXO = new NFT({
  metadata: {
    name: 'Transferable NFT',
    description: 'An NFT ready to transfer',
    image: 'ipfs://QmTransfer...',
  },
  ownerKey: ownerKey.publicKey,
  satoshis: 1000,
  network: Networks.livenet,
  txid: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  outputIndex: 0,
})

const newOwner = new PrivateKey(undefined, Networks.livenet)

try {
  const transferTx = nftWithUTXO.transfer(newOwner.publicKey, ownerKey)
  console.log('Transfer transaction created')
  console.log('Transaction size:', transferTx.toBuffer().length, 'bytes')
  console.log('Inputs:', transferTx.inputs.length)
  console.log('Outputs:', transferTx.outputs.length)
} catch (error) {
  console.error('Transfer error:', (error as Error).message)
}

// =============================================================================
// Example 6: Serialize and deserialize NFT
// =============================================================================

console.log('\n💾 Example 6: Serialize NFT')
console.log('-'.repeat(80))

const serialized = nft.toJSON()
console.log('Serialized NFT:')
console.log('  Address:', serialized.address)
console.log('  Metadata hash:', serialized.metadataHash)
console.log('  Name:', serialized.metadata.name)
console.log('  Satoshis:', serialized.satoshis)

const asObject = nft.toObject()
console.log('\nAs plain object (NFTData):')
console.log('  Script length:', asObject.script.toBuffer().length)
console.log('  Address:', asObject.address.toString())

// =============================================================================
// Example 7: Create Output from NFT
// =============================================================================

console.log('\n📤 Example 7: Convert NFT to Output')
console.log('-'.repeat(80))

const output = nft.toOutput()
console.log('Output created:')
console.log('  Satoshis:', output.satoshis)
console.log('  Script length:', output.script.toBuffer().length)
console.log('  Script type: Taproot with state')

// =============================================================================
// Example 8: Get NFT info
// =============================================================================

console.log('\n ℹ️  Example 8: Get NFT information')
console.log('-'.repeat(80))

const info = nft.getInfo()
console.log('NFT Info:')
console.log('  Commitment:', info.commitment.toString())
console.log('  Metadata hash:', info.metadataHash.toString('hex'))
console.log('  Address:', info.address.toString())

// =============================================================================
// Example 9: Update UTXO after minting
// =============================================================================

console.log('\n🔄 Example 9: Update NFT UTXO info after minting')
console.log('-'.repeat(80))

const newNFT = new NFT({
  metadata: {
    name: 'Fresh NFT',
    description: 'Just minted',
    image: 'ipfs://QmFresh...',
  },
  ownerKey: ownerKey.publicKey,
  satoshis: 1000,
  network: Networks.livenet,
})

console.log('Before mint - TXID:', newNFT.txid)
console.log('Before mint - Output index:', newNFT.outputIndex)

// Simulate minting and updating UTXO
newNFT.updateUTXO(
  'def456890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  0,
)

console.log('After mint - TXID:', newNFT.txid)
console.log('After mint - Output index:', newNFT.outputIndex)

// =============================================================================
// Example 10: Comparison with NFTUtil
// =============================================================================

console.log('\n🔧 Example 10: NFT class vs NFTUtil')
console.log('-'.repeat(80))

// Using NFTUtil (functional approach)
const nftData = NFTUtil.createKeyPathNFT(
  ownerKey.publicKey,
  {
    name: 'Functional NFT',
    description: 'Created with NFTUtil',
    image: 'ipfs://QmFunc...',
  },
  1000,
  Networks.livenet,
)

console.log('NFTUtil approach:')
console.log('  Type: Plain object (NFTData)')
console.log('  Address:', nftData.address.toString())
console.log('  Has methods: No')

// Using NFT class (OOP approach)
const nftClass = new NFT({
  metadata: {
    name: 'OOP NFT',
    description: 'Created with NFT class',
    image: 'ipfs://QmOOP...',
  },
  ownerKey: ownerKey.publicKey,
  satoshis: 1000,
  network: Networks.livenet,
})

console.log('\nNFT class approach:')
console.log('  Type: NFT instance')
console.log('  Address:', nftClass.address.toString())
console.log('  Has methods: Yes (transfer, verify, etc.)')
console.log(
  '  Can call:',
  typeof nftClass.verifyMetadata === 'function'
    ? 'nft.verifyMetadata()'
    : 'N/A',
)

// =============================================================================
// Summary
// =============================================================================

console.log('\n' + '='.repeat(80))
console.log('Summary')
console.log('='.repeat(80))
console.log('✅ Created NFT with class constructor')
console.log('✅ Created NFT with script tree')
console.log('✅ Created collection NFT')
console.log('✅ Loaded NFT from script')
console.log('✅ Transferred NFT (instance method)')
console.log('✅ Serialized NFT to JSON')
console.log('✅ Converted NFT to Output')
console.log('✅ Retrieved NFT info')
console.log('✅ Updated NFT UTXO')
console.log('✅ Compared class vs util approaches')
console.log('\nNFT class examples completed successfully! 🎉')

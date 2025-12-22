# lotus-wallet-lib

> **Bitcore-compatible wallet SDK for Lotus**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue)](https://www.typescriptlang.org/)
[![Node](https://img.shields.io/badge/Node.js->=22-green)](https://nodejs.org/)

A comprehensive TypeScript library providing Bitcoin-like transaction primitives, advanced cryptographic protocols, and RANK protocol support for the Lotus (XPI) blockchain ecosystem.

---

## Features

### 🔐 Cryptography & Signatures

- **Bitcore Modules** - Complete Bitcoin-like transaction primitives adapted for Lotus
  - Private/public key management
  - HD wallets (BIP32/BIP39)
  - Transaction building and signing
  - Address generation (P2PKH, P2SH, Taproot)
  - Script interpreter
- **MuSig2** - Multi-signature Schnorr signatures (BIP327)
  - 2-round non-interactive signing
  - Privacy-preserving multisig (indistinguishable from single-sig)
- **Taproot** - Pay-to-Taproot address support
  - Script path spending
  - Key path spending
  - MuSig2 integration
  - RANK protocol integration

### 📊 RANK Protocol

- **Social Ranking System** - On-chain reputation and content ranking
  - Positive/negative/neutral sentiment tracking
  - Multi-platform support (Twitter, Lotusia)
  - Comment system (RNKC)
  - Script builder and parser
  - Fee-based spam prevention

### 🔧 Utilities

- **RPC Client** - Full-featured lotusd RPC interface
  - Network information
  - Block and transaction queries
  - Mining information
  - Mempool management
- **Constants & Settings** - Lotus-specific network parameters
  - Network configurations
  - Protocol constants
  - Fee calculations
- **Encoding Utilities** - Base58, Base58Check, Base32, Varint

---

## Installation

```bash
# Install from GitHub source
$ npm install LotusiaStewardship/lotus-wallet-lib
```

### Requirements

- Node.js >= 22
- TypeScript >= 5.0 (for development)

---

## Quick Start

### Basic Transaction

```typescript
import { Bitcore } from 'lotus-wallet-lib'
import { BIP44_COIN_TYPE } from 'lotus-wallet-lib/utils/constants'

// Generate mnemonic
const mnemonic = new Bitcore.Mnemonic()
const phrase = mnemonic.phrase

// Derive HD wallet
const hdKey = mnemonic.toHDPrivateKey('passphrase')
const childKey = hdKey.deriveChild(`m/44'/${BIP44_COIN_TYPE}'/0'/0/0`)

// Get private key and address
const privateKey = childKey.privateKey
const address = privateKey.toAddress()

console.log('Address:', address.toString())

// Build transaction
const tx = new Bitcore.Transaction()
  .from(unspentOutput)
  .to(recipientAddress, 100_000_000) // 100 XPI
  .change(changeAddress)
  .sign(privateKey)

console.log('Transaction:', tx.serialize())
```

### HD Wallet (BIP32/BIP39)

```typescript
import { Bitcore } from 'lotus-wallet-lib'
import { BIP44_COIN_TYPE } from 'lotus-wallet-lib/utils/constants'

// Generate mnemonic
const mnemonic = new Bitcore.Mnemonic()
const phrase = mnemonic.phrase

// Derive HD wallet
const hdKey = mnemonic.toHDPrivateKey('passphrase')
const childKey = hdKey.deriveChild(`m/44'/${BIP44_COIN_TYPE}'/0'/0/0`)

// Get private key and address
const privateKey = childKey.privateKey
const address = privateKey.toAddress()

console.log('First address:', address.toString())

// Or derive from existing mnemonic
const existingMnemonic = new Bitcore.Mnemonic(
  'your twelve word mnemonic phrase here',
)
const restoredHdKey = existingMnemonic.toHDPrivateKey()
```

### MuSig2 Multi-Signature

```typescript
import { Bitcore } from 'lotus-wallet-lib'

// Create MuSig2 signer
const signer = new Bitcore.MuSig2Signer({
  signers: [alicePubKey, bobPubKey],
  myPrivateKey: alicePrivKey,
})

// Round 1: Generate nonces
const prepare = signer.prepare(message)
// Share prepare.myPublicNonces with other signers

// Round 2: Collect partial signatures
const myPartialSig = signer.createPartialSignature(
  prepare,
  allPublicNonces,
  message,
)
// Collect partial signatures from other signers

// Aggregate final signature
const result = signer.sign(prepare, allPublicNonces, message, allPartialSigs)
```

### RANK Social Ranking

```typescript
import { Bitcore, RANK } from 'lotus-wallet-lib'

// Create RANK script
const rankScript = RANK.toScriptRANK(
  'positive', // sentiment
  'twitter', // platform
  '@username', // profileId
  '1234567890', // postId (optional)
)

// Create RNKC script (comment) - returns array of buffers
const rnkcScripts = RANK.toScriptRNKC({
  platform: 'twitter',
  profileId: '@original_author',
  postId: '0987654321',
  comment: 'Great post!',
})

// Add to transaction
const tx = new Bitcore.Transaction()
  .from(utxo)
  .addOutput(
    new Bitcore.Output({
      script: rankScript,
      satoshis: 0,
    }),
  )
  // Add RNKC scripts (outIdx 1 and 2)
  .addOutput(
    new Bitcore.Output({
      script: rnkcScripts[0],
      satoshis: 0,
    }),
  )
  .addOutput(
    new Bitcore.Output({
      script: rnkcScripts[1] || Buffer.from('6a', 'hex'), // OP_RETURN if only one script needed
      satoshis: 0,
    }),
  )
  .to(address, amount)
```

### Taproot Addresses

```typescript
import { Bitcore } from 'lotus-wallet-lib'

// Create simple Taproot address (key-path only)
const privateKey = new Bitcore.PrivateKey()
const internalPubKey = privateKey.publicKey

const taprootScript = Bitcore.buildKeyPathTaproot(internalPubKey)
const taprootAddress = taprootScript.toAddress()

console.log('Taproot address:', taprootAddress?.toString())

// Taproot with script paths
const script1 = new Bitcore.Script()
  .add(internalPubKey.toBuffer())
  .add(Bitcore.Opcode.OP_CHECKSIG)

const script2 = new Bitcore.Script()
  .add(720) // ~1 day timelock (30 blocks per hour (2min average) * 24 hours per day)
  .add(Bitcore.Opcode.OP_CHECKSEQUENCEVERIFY)
  .add(Bitcore.Opcode.OP_DROP)
  .add(internalPubKey.toBuffer())
  .add(Bitcore.Opcode.OP_CHECKSIG)

// Build tree with script paths
const tree = {
  left: { script: script1 },
  right: { script: script2 },
}

const taprootWithScripts = Bitcore.buildScriptPathTaproot(internalPubKey, tree)
const addressWithScripts = taprootWithScripts.toAddress()

console.log('Taproot with scripts:', addressWithScripts?.toString())
```

### RPC Client

```typescript
import { Bitcore } from 'lotus-wallet-lib'
import { type RPCConfig, RPCClient } from 'lotus-wallet-lib/lib/rpc'

// Configure daemon connection
const config: RPCConfig = {
  user: 'rpcuser',
  password: 'rpcpass',
  address: '127.0.0.1',
  port: 10604,
}

const rpcClient = new RPCClient(config)

// Get blockchain info
const blockCount = await rpcClient.getBlockCount()
const blockHash = await rpcClient.getBlockHash(blockCount)
const block = await rpcClient.getBlock(blockHash)

// Get transaction info
const tx = await rpcClient.getRawTransaction(txid)

// Send raw transaction
const txid = await rpcClient.sendRawTransaction(tx.serialize())
console.log('Transaction ID:', txid)
```

---

## Core Modules

### Bitcore

Bitcoin-like transaction primitives adapted for Lotus XPI:

- **Transaction building** - Inputs, outputs, signing
- **Script system** - P2PKH, P2SH, P2TR, custom scripts
- **Cryptography** - ECDSA, Schnorr signatures
- **Addresses** - P2PKH, P2SH, P2TR (X-addresses)
- **HD Wallets** - BIP32 derivation, BIP39 mnemonics
- **Encoding** - Base58, Base58Check, Varint

```typescript
import * as Bitcore from 'lotus-wallet-lib/lib/bitcore'
// or
import { PrivateKey, Transaction, Address } from 'lotus-wallet-lib'
```

### MuSig2

Multi-signature Schnorr signatures:

- **2-round signing** - Non-interactive nonce exchange
- **Security** - Replay protection, nonce aggregation
- **Privacy** - Indistinguishable from single signatures

```typescript
import {
  MuSig2Session,
  MuSig2Signer,
} from 'lotus-wallet-lib/lib/bitcore/musig2'
```

### RANK Protocol

On-chain social ranking and reputation system:

- **Sentiment tracking** - Positive/negative/neutral
- **Multi-platform** - Twitter, Lotusia
- **Comments** - RNKC protocol
- **Spam prevention** - Fee-based filtering

```typescript
import {
  toScriptRANK,
  toScriptRNKC,
  ScriptProcessor,
} from 'lotus-wallet-lib/lib/rank'
```

### Taproot

Pay-to-Taproot support with script paths:

- **Key path spending** - Standard Taproot addresses
- **Script path spending** - MAST-like script trees
- **MuSig2 integration** - Multi-sig via Taproot
- **RANK integration** - RANK protocol via Taproot

```typescript
import { Taproot } from 'lotus-wallet-lib/lib/bitcore/taproot'
```

### RPC Client

Full-featured RPC client for lotusd:

- **Network queries** - Get network info, peers, blocks
- **Transaction handling** - Send raw transactions, query mempool
- **Mining info** - Get block height, difficulty, hash rate
- **Type-safe** - Full TypeScript support

```typescript
import { type RPCConfig, RPCClient } from 'lotus-wallet-lib/lib/rpc'
```

---

## Examples

The library includes comprehensive examples in the [`examples/`](examples/) directory:

### Taproot Examples

- `taproot-example.ts` - Basic Taproot usage
- `taproot-rank-multisig.ts` - RANK protocol with multisig
- `taproot-rank-timelock.ts` - Timelock scripts
- `taproot-rnkc-moderation.ts` - Moderation scripts

### MuSig2 Examples

- `musig2-example.ts` - Basic 2-of-2 signing
- `musig2-session-example.ts` - Session management
- `musig2-browser-compatibility.ts` - Browser usage

### NFT Examples

- `nft-class-example.ts` - NFT class usage
- `nft-examples.ts` - NFT creation and transfer

### Running Examples

```bash
# Basic example
npx tsx examples/taproot-example.ts

# MuSig2 signing
npx tsx examples/musig2-example.ts

# RANK protocol
npx tsx examples/rank-example.ts
```

---

## Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

### Getting Started

- [MuSig2 Start Here](docs/MUSIG2_START_HERE.md) - Introduction to MuSig2
- [MuSig2 Quick Reference](docs/MUSIG2_QUICK_REFERENCE.md) - Quick reference guide
- [Taproot Quickstart](docs/TAPROOT_QUICKSTART.md) - Taproot introduction

### Architecture & Implementation

- [MuSig2 Implementation](docs/MUSIG2_IMPLEMENTATION.md) - MuSig2 design
- [Taproot Implementation](docs/TAPROOT_IMPLEMENTATION.md) - Taproot details

### Security

- [MuSig2 Security Analysis](docs/MUSIG2_SECURITY_ANALYSIS.md) - Security audit
- [Signature Encoding](docs/SIGNATURE_ENCODING.md) - Signature format

### API References

- [Taproot API Reference](docs/taproot/api-reference.md) - Taproot API

---

## Testing

```bash
# Run all tests
npm test

# Run specific test suite
npm test -- test/crypto/musig2/

# Run with coverage
npm run test:coverage
```

---

## Development

### Build

```bash
# Compile TypeScript
npm run build

# Watch mode
npm run build:watch
```

### Linting & Formatting

```bash
# Format code
npm run format

# Lint code
npm run lint
```

---

## Lotus Network Information

**Lotus (XPI)** is a Bitcoin-based cryptocurrency with several key differences:

- **Decimals**: 6 (1 XPI = 1,000,000 satoshis) vs Bitcoin's 8
- **Supply**: Inflationary with no hard cap
- **Consensus**: Proof-of-Work (SHA-256d)
- **Features**: OP_RETURN data, Taproot, RANK protocol

**Network Resources:**

- Official Website: https://lotusia.org
- Documentation: https://lotusia.org/docs
- Block Explorer: https://explorer.lotusia.org
- Full Node (lotusd): https://github.com/LotusiaStewardship/lotusd

---

## Community

**Discord:** [Lotusia](https://discord.gg/fZrFa3vf)  
**Telegram:** [Lotusia Discourse](https://t.me/LotusiaDiscourse)  
**GitHub:** [LotusiaStewardship](https://github.com/LotusiaStewardship)

---

## Contributing

Contributions are welcome! Please:

1. Read the relevant documentation thoroughly
2. Follow the existing code style (Prettier + ESLint)
3. Add tests for new features
4. Update documentation as needed
5. Submit a pull request

### Development Setup

```bash
# Clone repository
git clone https://github.com/LotusiaStewardship/lotus-wallet-lib.git
cd lotus-wallet-lib

# Install dependencies
npm install

# Build library
npm run build

# Run tests
npm test
```

---

## License

[MIT License](LICENSE) - Copyright (c) 2025 The Lotusia Stewardship

---

## Related Projects

- **lotus-sdk** - Full Lotus SDK with P2P networking  
  https://github.com/LotusiaStewardship/lotus-sdk

- **lotusd** - Lotus full node implementation  
  https://github.com/LotusiaStewardship/lotusd

- **lotus-explorer** - Lotus blockchain explorer  
  https://github.com/LotusiaStewardship/lotus-explorer

- **lotus-backend-ts** - Lotus backend services  
  https://github.com/LotusiaStewardship/lotus-backend-ts

- **rank-dashboard** - RANK protocol dashboard  
  https://github.com/LotusiaStewardship/rank-dashboard

---

**Built with ❤️ for the Lotus Ecosystem** 🌸

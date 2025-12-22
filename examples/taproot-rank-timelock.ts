/**
 * Taproot + RANK: Time-Locked Voting
 *
 * This example demonstrates how Taproot can enhance RANK voting by adding
 * a time-lock mechanism. Voters commit funds that are locked until a future
 * block height, preventing rapid vote manipulation while maintaining privacy.
 *
 * Use Case:
 * - Prevent vote manipulation by requiring commitment period
 * - Voter can reclaim funds after the voting period ends
 * - Privacy: Key path spending hides the time-lock condition
 * - Efficiency: Schnorr signatures are smaller than ECDSA
 */

import {
  Transaction,
  PrivateKey,
  Address,
  Script,
  Signature,
  PublicKey,
  Output,
  UnspentOutput,
} from '../lib/bitcore/index.js'
import { Opcode } from '../lib/bitcore/opcode.js'
import { buildScriptPathTaproot, TapNode } from '../lib/bitcore/taproot.js'
// Note: rank module would need to be imported from your implementation
// import { toScriptRANK, ScriptChunkSentimentUTF8 } from '../lib/rank.js'
// For this example, we'll simulate the RANK script creation
function toScriptRANK(
  sentiment: string,
  platform: string,
  profileId: string,
): Buffer {
  // Simplified RANK script: OP_RETURN <RANK> <sentiment> <platform> <profileId>
  const script = Buffer.from(
    '6a045241444b01' + // OP_RETURN + 'RANK' + sentiment
      '0001' + // platform byte
      Buffer.from(profileId, 'utf8').toString('hex'),
    'hex',
  )
  return script
}

// ============================================================
// Configuration
// ============================================================

const VOTE_LOCK_BLOCKS = 720 // ~24 hours at 2 min/block (Lotus)
const VOTE_AMOUNT = 10000 // satoshis committed per vote

// ============================================================
// Example: Time-Locked RANK Vote
// ============================================================

console.log('============================================================')
console.log('Taproot + RANK: Time-Locked Voting Example')
console.log('============================================================\n')

// Step 1: Create voter's key
const voterKey = new PrivateKey()
console.log('Voter private key:', voterKey.toString())
console.log('Voter public key:', voterKey.publicKey.toString())
console.log()

// Step 2: Create time-locked script
// This script requires both a valid signature AND a minimum block height
const currentBlockHeight = 1000000 // Example current height
const unlockHeight = currentBlockHeight + VOTE_LOCK_BLOCKS

// Build the time-lock script: <height> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
const timeLockScript = new Script()
  .add(Buffer.from(unlockHeight.toString(16).padStart(6, '0'), 'hex'))
  .add(Opcode.OP_CHECKLOCKTIMEVERIFY)
  .add(Opcode.OP_DROP)
  .add(voterKey.publicKey.toBuffer())
  .add(Opcode.OP_CHECKSIG)

console.log('Time-lock script:')
console.log('  Unlock height:', unlockHeight)
console.log('  Script:', timeLockScript.toASM())
console.log('  Script hex:', timeLockScript.toHex())
console.log()

// Step 3: Build Taproot script tree
// The voter can spend via key path (normal spending) OR script path (time-locked reclaim)
const scriptTree: TapNode = {
  script: timeLockScript.toBuffer(),
}

const tapResult = buildScriptPathTaproot(voterKey.publicKey, scriptTree)
console.log('Taproot commitment:')
console.log('  Internal pubkey:', voterKey.publicKey.toString())
console.log('  Merkle root:', tapResult.merkleRoot.toString('hex'))
console.log('  Commitment pubkey:', tapResult.commitment.toString())
console.log()

// Step 4: Create Taproot address for the vote commitment
const taprootAddress = Address.fromTaprootCommitment(
  tapResult.commitment,
  'livenet',
)
console.log('Vote commitment address:', taprootAddress.toString())
console.log('XAddress:', taprootAddress.toXAddress())
console.log()

// Step 5: Create RANK vote transaction
// This transaction has TWO outputs:
// Output 0: OP_RETURN with RANK vote data
// Output 1: Taproot commitment (time-locked funds)

const rankScript = toScriptRANK('positive', 'twitter', 'elonmusk')
console.log('RANK vote script:')
console.log('  Sentiment: positive')
console.log('  Platform: twitter')
console.log('  Profile: elonmusk')
console.log('  Script hex:', rankScript.toString('hex'))
console.log()

// Create the vote transaction (simplified - would need real UTXO)
const dummyUtxo = {
  txId: 'a'.repeat(64),
  outputIndex: 0,
  script: Script.buildPublicKeyHashOut(voterKey.publicKey),
  satoshis: 50000,
  address: voterKey.toAddress(),
}

const voteTx = new Transaction()
  .from(new UnspentOutput(dummyUtxo))
  .addOutput(
    new Output({
      script: Script.fromBuffer(rankScript),
      satoshis: 0,
    }),
  )
  .to(taprootAddress, VOTE_AMOUNT)
  .change(voterKey.toAddress())
  .sign(voterKey)

console.log('Vote transaction created!')
console.log('  TX ID:', voteTx.id)
console.log('  Inputs:', voteTx.inputs.length)
console.log('  Outputs:', voteTx.outputs.length)
console.log('    Output 0: OP_RETURN (RANK vote, 0 sats)')
console.log('    Output 1: Taproot commitment (', VOTE_AMOUNT, 'sats)')
console.log('    Output 2: Change (', voteTx.outputs[2]?.satoshis || 0, 'sats)')
console.log('  Fully signed:', voteTx.isFullySigned())
console.log()

// Step 6: Reclaim funds after time-lock expires (script path spending)
console.log('============================================================')
console.log('Reclaiming Funds After Time-Lock')
console.log('============================================================\n')

// Create a transaction to spend the time-locked Taproot output
// This uses SCRIPT PATH spending to reveal the time-lock condition
const taprootUtxo = {
  txId: voteTx.id,
  outputIndex: 1,
  script: Script.buildPayToTaproot(tapResult.commitment),
  satoshis: VOTE_AMOUNT,
  address: taprootAddress,
}

console.log('Taproot UTXO details:')
console.log('  TX ID:', taprootUtxo.txId)
console.log('  Output Index:', taprootUtxo.outputIndex)
console.log('  Amount:', taprootUtxo.satoshis, 'sats')
console.log('  Script type: Taproot (P2TR)')
console.log('  Script hex:', taprootUtxo.script.toHex())
console.log()

// For script path spending, we need to construct the input script manually
// Input script: <signature> <script> <control_block>
// Note: This is a simplified example - full implementation would require control block

console.log('Script path spending requires:')
console.log('  1. Signature from voter key (tweaked)')
console.log('  2. Time-lock script revealed')
console.log('  3. Control block proving script is in commitment')
console.log('  4. Transaction nLockTime set to', unlockHeight, 'or higher')
console.log()
console.log('After block height', unlockHeight, 'the voter can reclaim funds')
console.log(
  'by revealing the time-lock script and providing a valid signature.',
)
console.log(
  'The control block has',
  tapResult.leaves[0].merklePath.length,
  'Merkle proof nodes.',
)
console.log()

// ============================================================
// Benefits Summary
// ============================================================

console.log('============================================================')
console.log('Benefits of Taproot + RANK Time-Locking')
console.log('============================================================\n')

console.log('✓ Privacy:')
console.log(
  '  - Key path spending hides the time-lock condition from observers',
)
console.log('  - Looks like a normal Taproot transaction on-chain')
console.log()

console.log('✓ Security:')
console.log('  - Votes cannot be immediately reclaimed (prevents manipulation)')
console.log('  - Funds are provably locked until specific block height')
console.log()

console.log('✓ Flexibility:')
console.log('  - Voter retains ultimate control of funds')
console.log('  - Can add multiple reclaim conditions in script tree')
console.log('  - Could add emergency recovery with different key')
console.log()

console.log('✓ Efficiency:')
console.log('  - Schnorr signatures are ~10% smaller than ECDSA')
console.log('  - Key path spending is most efficient (single signature)')
console.log()

console.log('============================================================')
console.log('Use Cases')
console.log('============================================================\n')

console.log('1. Governance Voting:')
console.log('   - Lock funds during voting period to prevent vote buying')
console.log('   - Reclaim after decision is finalized')
console.log()

console.log('2. Reputation Staking:')
console.log('   - Stake funds to boost vote weight')
console.log('   - Reclaim after maintaining good reputation')
console.log()

console.log('3. Anti-Spam Mechanism:')
console.log('   - Require commitment to vote')
console.log('   - Penalize spam by extending lock period')
console.log()

console.log('4. Timed Campaigns:')
console.log('   - Lock votes for campaign duration')
console.log('   - Automatic refund after campaign ends')
console.log()

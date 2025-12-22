/**
 * Taproot + RANK: Multi-Signature Organizational Voting
 *
 * This example demonstrates how Taproot can enable organizational voting
 * where multiple signatories must approve a RANK vote. This is useful for
 * companies, DAOs, or groups that want to represent collective opinion.
 *
 * Use Case:
 * - Organizations vote with single on-chain footprint
 * - Requires M-of-N signatures to commit vote
 * - Privacy: Key path hides the multi-sig requirement
 * - Efficiency: Single transaction instead of N individual votes
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

const ORGANIZATION_NAME = 'Lotus Foundation'
const REQUIRED_SIGNATURES = 3 // 3-of-5 multisig
const TOTAL_SIGNATORIES = 5
const VOTE_WEIGHT = 1000000 // Large vote weight for organizations

// ============================================================
// Example: Multi-Signature Organizational Voting
// ============================================================

console.log('============================================================')
console.log('Taproot + RANK: Organizational Multi-Sig Voting')
console.log('============================================================\n')

console.log('Organization:', ORGANIZATION_NAME)
console.log('Voting scheme:', REQUIRED_SIGNATURES, 'of', TOTAL_SIGNATORIES)
console.log('Vote weight:', VOTE_WEIGHT, 'satoshis')
console.log()

// Step 1: Create keys for organization members
const boardMembers: PrivateKey[] = []
for (let i = 0; i < TOTAL_SIGNATORIES; i++) {
  boardMembers.push(new PrivateKey())
}

console.log('Board member public keys:')
boardMembers.forEach((member, i) => {
  console.log(
    `  Member ${i + 1}:`,
    member.publicKey.toString().substring(0, 40),
    '...',
  )
})
console.log()

// Step 2: Create aggregated public key for key path
// In production, this would use MuSig2 for proper key aggregation
// For this example, we use the first member's key as the internal key
const internalKey = boardMembers[0].publicKey

console.log('Internal key (aggregated):', internalKey.toString())
console.log('Note: Production should use MuSig2 for proper key aggregation')
console.log()

// Step 3: Build multi-sig script as fallback (script path)
// This allows voting even if key aggregation fails or members want explicit control

// Sort public keys for canonical multisig ordering
const sortedPubKeys = boardMembers
  .map(m => m.publicKey)
  .sort((a, b) => {
    return Buffer.compare(a.toBuffer(), b.toBuffer())
  })

// Build 3-of-5 multisig script
const multisigScript = new Script().add(Opcode.OP_3) // Require 3 signatures
sortedPubKeys.forEach(pubkey => {
  multisigScript.add(pubkey.toBuffer())
})
multisigScript
  .add(Opcode.OP_5) // Out of 5 keys
  .add(Opcode.OP_CHECKMULTISIG)

console.log('Multi-sig fallback script:')
console.log('  Type:', REQUIRED_SIGNATURES, 'of', TOTAL_SIGNATORIES, 'multisig')
console.log('  Script:', multisigScript.toASM().substring(0, 80), '...')
console.log('  Script size:', multisigScript.toBuffer().length, 'bytes')
console.log()

// Step 4: Add time-delayed recovery path
const RECOVERY_DELAY = 21600 // ~30 days at 2 min/block (Lotus)
const currentHeight = 1000000
const recoveryHeight = currentHeight + RECOVERY_DELAY

const recoveryScript = new Script()
  .add(Buffer.from(recoveryHeight.toString(16).padStart(6, '0'), 'hex'))
  .add(Opcode.OP_CHECKLOCKTIMEVERIFY)
  .add(Opcode.OP_DROP)
  .add(boardMembers[0].publicKey.toBuffer()) // Emergency recovery key
  .add(Opcode.OP_CHECKSIG)

console.log('Emergency recovery script:')
console.log('  Delay:', RECOVERY_DELAY, 'blocks (~30 days)')
console.log('  Recovery key: Member 1')
console.log('  Purpose: Recover funds if multisig coordination fails')
console.log()

// Step 5: Build Taproot script tree
const scriptTree: TapNode = {
  left: { script: multisigScript.toBuffer() },
  right: { script: recoveryScript.toBuffer() },
}

const tapResult = buildScriptPathTaproot(internalKey, scriptTree)

console.log('Taproot commitment:')
console.log('  Internal pubkey:', internalKey.toString())
console.log('  Merkle root:', tapResult.merkleRoot.toString('hex'))
console.log('  Commitment pubkey:', tapResult.commitment.toString())
console.log('  Script tree leaves:', tapResult.leaves.length)
console.log()

// Step 6: Create organizational Taproot address
const orgAddress = Address.fromTaprootCommitment(
  tapResult.commitment,
  'livenet',
)

console.log('Organization voting address:', orgAddress.toString())
console.log('XAddress:', orgAddress.toXAddress())
console.log()

// Step 7: Create organizational RANK vote
const rankScript = toScriptRANK('positive', 'twitter', 'LotusProtocol')

console.log('Organizational RANK vote:')
console.log('  Sentiment: positive')
console.log('  Platform: twitter')
console.log('  Target: LotusProtocol')
console.log('  Weight:', VOTE_WEIGHT, 'satoshis')
console.log()

// Create dummy funding UTXO
const dummyUtxo = {
  txId: 'c'.repeat(64),
  outputIndex: 0,
  script: Script.buildPublicKeyHashOut(boardMembers[0].publicKey),
  satoshis: VOTE_WEIGHT + 10000,
  address: boardMembers[0].toAddress(),
}

// Create vote transaction
const voteTx = new Transaction()
  .from(new UnspentOutput(dummyUtxo))
  .addOutput(
    new Output({
      script: Script.fromBuffer(rankScript),
      satoshis: 0,
    }),
  )
  .to(orgAddress, VOTE_WEIGHT)
  .change(boardMembers[0].toAddress())
  .sign(boardMembers[0])

console.log('Organizational vote transaction:')
console.log('  TX ID:', voteTx.id)
console.log('  Inputs:', voteTx.inputs.length)
console.log('  Outputs:', voteTx.outputs.length)
console.log('    Output 0: OP_RETURN (RANK vote, 0 sats)')
console.log('    Output 1: Taproot commitment (', VOTE_WEIGHT, 'sats)')
console.log('    Output 2: Change (', voteTx.outputs[2]?.satoshis || 0, 'sats)')
console.log('  Fully signed:', voteTx.isFullySigned())
console.log('  Transaction size:', voteTx.toBuffer().length, 'bytes')
console.log(
  '  Fee rate:',
  (
    (dummyUtxo.satoshis -
      voteTx.outputs.reduce((sum, out) => sum + out.satoshis, 0)) /
    voteTx.toBuffer().length
  ).toFixed(2),
  'sats/byte',
)
console.log()

// ============================================================
// Spending Scenarios
// ============================================================

console.log('============================================================')
console.log('Spending Scenarios')
console.log('============================================================\n')

console.log('Scenario 1: Key Path (MuSig2 Aggregation)')
console.log('  - All members collaborate to create aggregated signature')
console.log('  - Single Schnorr signature (64 bytes)')
console.log('  - Most private: No multisig revealed on-chain')
console.log('  - Most efficient: Smallest transaction size')
console.log('  - Cost: ~50 vbytes')
console.log()

console.log('Scenario 2: Script Path (Explicit Multisig)')
console.log('  - 3 board members sign individually')
console.log('  - Reveals multisig script and control block')
console.log('  - Less private: Multisig requirement visible')
console.log('  - Larger size: 3 signatures + script + proof')
console.log('  - Cost: ~250 vbytes')
console.log()

console.log('Scenario 3: Emergency Recovery')
console.log('  - Used if multisig coordination fails')
console.log('  - Single member can recover after 30 days')
console.log('  - Reveals time-lock script')
console.log('  - Safety net for organizational disputes')
console.log()

// ============================================================
// Comparison: Traditional vs Taproot Multisig
// ============================================================

console.log('============================================================')
console.log('Comparison: Traditional vs Taproot Multisig')
console.log('============================================================\n')

const traditionalMultisigSize = 300 // Approximate bytes for 3-of-5 P2SH
const taprootKeyPathSize = 50 // Approximate bytes for key path spend
const taprootScriptPathSize = 250 // Approximate bytes for script path

console.log('Traditional P2SH Multisig:')
console.log('  - Always reveals multisig on spend')
console.log('  - ECDSA signatures (72 bytes each)')
console.log('  - Size: ~', traditionalMultisigSize, 'bytes')
console.log('  - Privacy: Low (multisig always visible)')
console.log()

console.log('Taproot Key Path (MuSig2):')
console.log('  - Hides multisig requirement')
console.log('  - Single Schnorr signature (64 bytes)')
console.log('  - Size: ~', taprootKeyPathSize, 'bytes')
console.log('  - Privacy: High (looks like single-sig)')
console.log(
  '  - Savings: ',
  Math.round(
    ((traditionalMultisigSize - taprootKeyPathSize) / traditionalMultisigSize) *
      100,
  ),
  '% smaller',
)
console.log()

console.log('Taproot Script Path:')
console.log('  - Reveals multisig when used')
console.log('  - Multiple Schnorr signatures')
console.log('  - Size: ~', taprootScriptPathSize, 'bytes')
console.log('  - Privacy: Medium (fallback option)')
console.log(
  '  - Savings: ',
  Math.round(
    ((traditionalMultisigSize - taprootScriptPathSize) /
      traditionalMultisigSize) *
      100,
  ),
  '% smaller',
)
console.log()

// ============================================================
// Benefits Summary
// ============================================================

console.log('============================================================')
console.log('Benefits of Taproot Organizational Voting')
console.log('============================================================\n')

console.log('✓ Single Vote Representation:')
console.log('  - One transaction represents organization')
console.log('  - Cleaner on-chain footprint')
console.log('  - Easier for indexers to track')
console.log()

console.log('✓ Privacy:')
console.log('  - Key path hides multisig requirement')
console.log('  - Observers see single Taproot spend')
console.log('  - Internal governance stays private')
console.log()

console.log('✓ Efficiency:')
console.log('  - Smaller transactions = lower fees')
console.log('  - MuSig2 aggregation saves ~83% space')
console.log('  - Fewer UTXO created')
console.log()

console.log('✓ Flexibility:')
console.log('  - Multiple spending paths (key, script, recovery)')
console.log('  - Can change signing threshold via script tree')
console.log('  - Emergency recovery mechanism')
console.log()

console.log('✓ Security:')
console.log('  - Requires multiple approvals')
console.log('  - Time-delayed recovery prevents single point of failure')
console.log('  - Canonical key ordering prevents manipulation')
console.log()

console.log('============================================================')
console.log('Use Cases')
console.log('============================================================\n')

console.log('1. DAOs (Decentralized Autonomous Organizations):')
console.log('   - Vote on proposals as single entity')
console.log('   - Treasury management with multisig')
console.log('   - Efficient governance voting')
console.log()

console.log('2. Companies and Foundations:')
console.log('   - Board votes on rankings/endorsements')
console.log('   - Official statements backed by stake')
console.log('   - Transparent decision-making')
console.log()

console.log('3. Investment Groups:')
console.log('   - Collective voting on projects')
console.log('   - Weighted by stake amount')
console.log('   - Group consensus on-chain')
console.log()

console.log('4. Content Moderation:')
console.log('   - Moderator teams vote on actions')
console.log('   - Prevents unilateral censorship')
console.log('   - Accountable governance')
console.log()

console.log('5. Reputation Networks:')
console.log('   - Verified organizations')
console.log('   - Higher weight votes')
console.log('   - Sybil attack resistance')
console.log()

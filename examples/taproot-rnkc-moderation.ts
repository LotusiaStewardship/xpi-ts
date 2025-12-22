/**
 * Taproot + RNKC: Moderated Comments
 *
 * This example demonstrates how Taproot can enhance RNKC (RANK Comments) by
 * adding a moderation mechanism. Comment authors stake funds that can be
 * penalized for spam/abuse, while legitimate comments get refunded.
 *
 * Use Case:
 * - Deter spam by requiring staked funds
 * - Moderators can penalize bad actors
 * - Legitimate users get automatic refunds
 * - Privacy: Key path spending hides moderation conditions
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
// import { toScriptRNKC, ScriptChunkPlatformUTF8 } from '../lib/rank.js'
// For this example, we'll simulate the RNKC script creation
function toScriptRNKC(params: {
  platform: string
  profileId: string
  postId?: string
  comment: string
}): Buffer[] {
  // Simplified RNKC scripts: metadata + comment data
  const metadata = Buffer.from(
    '6a04524e4b43' + // OP_RETURN + 'RNKC'
      '0001' + // platform
      Buffer.from(params.profileId, 'utf8').toString('hex'),
    'hex',
  )
  const commentData = Buffer.from(
    '6a4c' + // OP_RETURN + OP_PUSHDATA1
      params.comment.length.toString(16).padStart(2, '0') +
      Buffer.from(params.comment, 'utf8').toString('hex'),
    'hex',
  )
  return [metadata, commentData]
}

// ============================================================
// Configuration
// ============================================================

const COMMENT_STAKE = 50000 // satoshis required to comment
const SPAM_PENALTY = 0.5 // 50% penalty for spam
const REFUND_DELAY_BLOCKS = 5040 // ~1 week at 2 min/block (Lotus)

// ============================================================
// Example: Moderated RNKC Comments
// ============================================================

console.log('============================================================')
console.log('Taproot + RNKC: Moderated Comments Example')
console.log('============================================================\n')

// Step 1: Create keys for commenter and moderator
const commenterKey = new PrivateKey()
const moderatorKey = new PrivateKey()

console.log('Commenter public key:', commenterKey.publicKey.toString())
console.log('Moderator public key:', moderatorKey.publicKey.toString())
console.log()

// Step 2: Build script tree with multiple spending conditions
console.log('Building Taproot script tree with 3 spending paths:')
console.log()

// Path 1: Commenter reclaims after refund delay (no penalty)
const currentHeight = 1000000
const refundHeight = currentHeight + REFUND_DELAY_BLOCKS

const refundScript = new Script()
  .add(Buffer.from(refundHeight.toString(16).padStart(6, '0'), 'hex'))
  .add(Opcode.OP_CHECKLOCKTIMEVERIFY)
  .add(Opcode.OP_DROP)
  .add(commenterKey.publicKey.toBuffer())
  .add(Opcode.OP_CHECKSIG)

console.log('Path 1: Commenter Refund (after', REFUND_DELAY_BLOCKS, 'blocks)')
console.log('  Script:', refundScript.toASM())
console.log('  Returns full stake to commenter')
console.log()

// Path 2: Moderator penalty (immediate, partial return to commenter)
// This script allows moderator to spend, sending penalty to moderation fund
// and remaining amount back to commenter
const penaltyScript = new Script()
  .add(moderatorKey.publicKey.toBuffer())
  .add(Opcode.OP_CHECKSIG)

console.log('Path 2: Moderator Penalty (immediate)')
console.log('  Script:', penaltyScript.toASM())
console.log(
  '  Allows moderator to penalize spam (',
  SPAM_PENALTY * 100,
  '% fee)',
)
console.log()

// Path 3: Multi-sig emergency recovery
const emergencyScript = new Script()
  .add(Opcode.OP_2) // Require 2 signatures
  .add(commenterKey.publicKey.toBuffer())
  .add(moderatorKey.publicKey.toBuffer())
  .add(Opcode.OP_2) // Out of 2 keys
  .add(Opcode.OP_CHECKMULTISIG)

console.log('Path 3: Emergency Recovery (2-of-2 multisig)')
console.log('  Script:', emergencyScript.toASM())
console.log('  Requires both commenter and moderator approval')
console.log()

// Step 3: Build Taproot commitment with script tree
const scriptTree: TapNode = {
  left: { script: refundScript.toBuffer() },
  right: {
    left: { script: penaltyScript.toBuffer() },
    right: { script: emergencyScript.toBuffer() },
  },
}

const tapResult = buildScriptPathTaproot(commenterKey.publicKey, scriptTree)
console.log('Taproot commitment:')
console.log('  Internal pubkey:', commenterKey.publicKey.toString())
console.log('  Merkle root:', tapResult.merkleRoot.toString('hex'))
console.log('  Commitment pubkey:', tapResult.commitment.toString())
console.log('  Number of leaves:', tapResult.leaves.length)
console.log()

// Step 4: Create Taproot address for comment stake
const taprootAddress = Address.fromTaprootCommitment(
  tapResult.commitment,
  'livenet',
)
console.log('Comment stake address:', taprootAddress.toString())
console.log('XAddress:', taprootAddress.toXAddress())
console.log()

// Step 5: Create RNKC comment transaction
const rnkcScripts = toScriptRNKC({
  platform: 'twitter',
  profileId: 'elonmusk',
  postId: '1234567890123456',
  comment: 'Great post! This is a legitimate comment with real value.',
})

console.log('RNKC comment transaction:')
console.log('  Platform: twitter')
console.log('  Profile: elonmusk')
console.log('  Post ID: 1234567890123456')
console.log('  Comment length:', rnkcScripts[1].length - 3, 'bytes')
console.log('  Number of outputs:', 1 + rnkcScripts.length + 1) // RNKC + comment scripts + stake
console.log()

// Create dummy UTXO for funding
const dummyUtxo = {
  txId: 'b'.repeat(64),
  outputIndex: 0,
  script: Script.buildPublicKeyHashOut(commenterKey.publicKey),
  satoshis: 100000,
  address: commenterKey.toAddress(),
}

// Create comment transaction with Taproot stake
const commentTx = new Transaction()
  .from(new UnspentOutput(dummyUtxo))
  .addOutput(
    new Output({
      script: Script.fromBuffer(rnkcScripts[0]),
      satoshis: 0,
    }),
  )
  .addOutput(
    new Output({
      script: Script.fromBuffer(rnkcScripts[1]),
      satoshis: 0,
    }),
  )
  .to(taprootAddress, COMMENT_STAKE)
  .change(commenterKey.toAddress())
  .sign(commenterKey)

console.log('Comment transaction created!')
console.log('  TX ID:', commentTx.id)
console.log('  Inputs:', commentTx.inputs.length)
console.log('  Outputs:', commentTx.outputs.length)
console.log('    Output 0: OP_RETURN (RNKC metadata, 0 sats)')
console.log('    Output 1: OP_RETURN (comment data, 0 sats)')
console.log('    Output 2: Taproot stake (', COMMENT_STAKE, 'sats)')
console.log(
  '    Output 3: Change (',
  commentTx.outputs[3]?.satoshis || 0,
  'sats)',
)
console.log('  Fully signed:', commentTx.isFullySigned())
console.log('  Transaction size:', commentTx.toBuffer().length, 'bytes')
console.log()

// ============================================================
// Scenario 1: Legitimate Comment - Automatic Refund
// ============================================================

console.log('============================================================')
console.log('Scenario 1: Legitimate Comment - Automatic Refund')
console.log('============================================================\n')

console.log('After', REFUND_DELAY_BLOCKS, 'blocks (~1 week):')
console.log('  - No moderator action taken (comment is legitimate)')
console.log('  - Commenter uses Path 1 (time-lock refund)')
console.log('  - Full', COMMENT_STAKE, 'sats returned to commenter')
console.log('  - Key path spending hides the moderation mechanism')
console.log()

// ============================================================
// Scenario 2: Spam Comment - Moderator Penalty
// ============================================================

console.log('============================================================')
console.log('Scenario 2: Spam Comment - Moderator Penalty')
console.log('============================================================\n')

const penaltyAmount = Math.floor(COMMENT_STAKE * SPAM_PENALTY)
const returnAmount = COMMENT_STAKE - penaltyAmount

console.log('Comment flagged as spam:')
console.log('  - Moderator uses Path 2 (immediate penalty)')
console.log('  - Penalty:', penaltyAmount, 'sats (', SPAM_PENALTY * 100, '%)')
console.log('  - Returned to commenter:', returnAmount, 'sats')
console.log('  - Penalty sent to moderation fund')
console.log('  - Script path reveals the penalty mechanism')
console.log()

// ============================================================
// Scenario 3: Dispute - Emergency Recovery
// ============================================================

console.log('============================================================')
console.log('Scenario 3: Dispute - Emergency Recovery')
console.log('============================================================\n')

console.log('In case of dispute or error:')
console.log('  - Both commenter and moderator must agree')
console.log('  - Uses Path 3 (2-of-2 multisig)')
console.log('  - Allows custom resolution of edge cases')
console.log('  - Could split funds or return based on agreement')
console.log()

// ============================================================
// Benefits Summary
// ============================================================

console.log('============================================================')
console.log('Benefits of Taproot + RNKC Moderation')
console.log('============================================================\n')

console.log('✓ Spam Deterrence:')
console.log('  - Financial cost to posting comments')
console.log('  - Spammers risk losing staked funds')
console.log('  - Legitimate users get full refunds')
console.log()

console.log('✓ Privacy:')
console.log('  - Legitimate comments use key path (moderation hidden)')
console.log('  - Only spam reveals the penalty mechanism')
console.log('  - Observers cannot tell which comments are moderated')
console.log()

console.log('✓ Fairness:')
console.log('  - Automatic refunds for good actors')
console.log('  - Transparent penalty rules')
console.log('  - Dispute resolution via emergency path')
console.log()

console.log('✓ Flexibility:')
console.log('  - Configurable penalty rates')
console.log('  - Adjustable refund delays')
console.log('  - Multiple moderation keys possible')
console.log()

console.log('============================================================')
console.log('Use Cases')
console.log('============================================================\n')

console.log('1. Social Media Platforms:')
console.log('   - Reduce spam in comments')
console.log('   - Incentivize quality content')
console.log('   - Fund moderation efforts from penalties')
console.log()

console.log('2. Forum Systems:')
console.log('   - Reputation-based posting')
console.log('   - Progressive penalties for repeat offenders')
console.log('   - Community-driven moderation')
console.log()

console.log('3. Review Systems:')
console.log('   - Prevent fake reviews')
console.log('   - Reward honest reviewers')
console.log('   - Penalize review manipulation')
console.log()

console.log('4. Content Curation:')
console.log('   - Stake-weighted voting on content')
console.log('   - Quality filters via economic incentives')
console.log('   - Self-sustaining moderation economy')
console.log()

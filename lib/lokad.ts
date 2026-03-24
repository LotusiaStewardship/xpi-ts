/**
 * Copyright 2025-2026 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */
import type { Buffer } from 'buffer/'
import { BufferUtil, Chunk, Opcode, Script } from './bitcore'
import {
  MAX_OP_RETURN_DATA,
  RNKC_MIN_DATA_LENGTH,
  RNKC_MIN_FEE_RATE,
} from '../utils/constants.js'
import { toHex } from '../utils/string'

// ==============================================
// Types
// ==============================================
/** LOKAD protocol identifiers as UTF-8 strings */
export type ScriptChunkLokadUTF8 = 'RANK' | 'RNKC' | 'RNKE'
/** RANK/RNKC platform identifiers as UTF-8 strings */
export type ScriptChunkPlatformUTF8 = 'lotusia' | 'twitter'
/** RANK sentiment values as UTF-8 strings */
export type ScriptChunkSentimentUTF8 = 'positive' | 'negative' | 'neutral'
/** Map of LOKAD integer values to UTF-8 protocol identifiers */
export type ScriptChunkLokadMap = Map<number, ScriptChunkLokadUTF8>
/** Map of platform integer values to UTF-8 platform identifiers */
export type ScriptChunkPlatformMap = Map<number, ScriptChunkPlatformUTF8>
/** Map of sentiment integer values to UTF-8 sentiment identifiers */
export type ScriptChunkSentimentMap = Map<number, ScriptChunkSentimentUTF8>
export type ScriptChunkField =
  | 'sentiment'
  | 'platform'
  | 'profileId'
  | 'postId'
  | 'comment'
  | 'postHash'
  | 'instanceId'
export type ScriptChunk = {
  /** Byte offset of the chunk in the output script */
  offset: number | null
  /** Byte length of the chunk in the output script */
  len: number | null
  /** Map of supported RANK script chunks */
  map?: ScriptChunkLokadMap | ScriptChunkPlatformMap | ScriptChunkSentimentMap
}
/** Required RNKC script chunks */
export type ScriptChunksRNKC = {
  [name in Exclude<
    ScriptChunkField,
    'sentiment' | 'postHash' | 'instanceId'
  >]: ScriptChunk
}
/** Required RANK script chunks */
export type ScriptChunksRANK = {
  [name in Exclude<
    ScriptChunkField,
    'comment' | 'postId' | 'postHash' | 'instanceId'
  >]: ScriptChunk
}
/** Optional RANK script chunks */
export type ScriptChunksOptionalRANK = {
  [name in Extract<
    ScriptChunkField,
    'postId' | 'postHash' | 'instanceId'
  >]: ScriptChunk
}
/** OP_RETURN \<RANK\> \<sentiment\> \<profileId\> [\<postId\> \<postHash\> [\<instanceId\>]] */
export type TransactionOutputRANK = {
  /** positive or negative sentiment (can support more) */
  sentiment: ScriptChunkSentimentUTF8
  /** e.g. Twitter/X.com, etc. */
  platform: ScriptChunkPlatformUTF8
  /** who the ranking is for */
  profileId: string
  /** optional post ID if ranking specific content */
  postId?: string
  /** optional hash of the post content (required if postId is provided) */
  //postHash?: string
  /** ID of the registered extension instance */
  //instanceId?: string
}
/** OP_RETURN \<RNKC\> \<platform\> \<profileId\> \<postId\> */
export type TransactionOutputRNKC = {
  /** outIdx 1 and 2 concatenated as comment data in UTF-8 encoding */
  data: Uint8Array
  /** Minimum fee rate for accepting RNKC transaction, in satoshis per byte */
  feeRate: number
  /** e.g. Twitter/X.com, etc. */
  inReplyToPlatform: ScriptChunkPlatformUTF8
  /** who the comment is replying to */
  inReplyToProfileId?: string
  /** ID of the post being replied to */
  inReplyToPostId?: string
}
/** Transaction data for the backend indexer */
export type Transaction = {
  txid: string
  outIdx: number // index of the output that contains the RANK data
  sats: bigint
  firstSeen: bigint // time first seen by indexer, only for new mempool transactions
  scriptPayload: string
  instanceId?: string
  height?: number // undefined if mempool
  timestamp?: bigint // unix timestamp
}
/** RANK transaction data for the backend indexer */
export type TransactionRANK = TransactionOutputRANK & Transaction
/** RNKC transaction data for the backend indexer */
export type TransactionRNKC = TransactionOutputRNKC & Transaction
/**
 * Target entity being ranked by a RANK transaction, commented on by an
 * RNKC transaction, etc. (e.g. Profile, Post, etc.)
 */
export type TargetEntity = {
  id: string // profileId, postId, etc
  platform: string
  ranking: bigint
  ranks: Omit<TransactionRANK, 'profileId' | 'platform'>[] // omit the database relation fields
  comments: Omit<TransactionRNKC, 'inReplyToProfileId' | 'inReplyToPlatform'>[] // omit the database relation fields
  satsPositive: bigint
  satsNegative: bigint
  votesPositive: number
  votesNegative: number
}
/**
 * `IndexedTransactionRANK` objects are converted to a `ProfileMap` for database ops
 *
 * `string` is `profileId`
 */
export type ProfileMap = Map<string, Profile>
export type PostMap = Map<string, Post>
/**
 * Profile entity that can be ranked and contains associated posts
 * @extends TargetEntity
 */
export interface Profile extends TargetEntity {
  /** Map of posts associated with this profile, keyed by post ID */
  posts?: PostMap
}
/**
 * Post entity that can be ranked and commented on
 * @extends TargetEntity
 */
export interface Post extends TargetEntity {
  /** The profile ID that owns this post */
  profileId: string
  /** If this post is a RNKC transaction, this contains the comment data for establishing relation to `RankComment` */
  data?: Uint8Array
}

/**
 * Platform parameters for configuring profile and post ID validation
 * @property profileId - Configuration for profile ID validation
 * @property profileId.len - Maximum length of the profile ID in bytes
 * @property profileId.regex - Regular expression for validating profile ID format
 * @property postId - Configuration for post ID validation
 * @property postId.len - Maximum length of the post ID in bytes
 * @property postId.regex - Regular expression for validating post ID format
 * @property postId.type - The type used to represent the post ID value
 */
export interface PlatformParameters {
  profileId: {
    len: number
    regex: RegExp
  }
  postId: {
    len: number
    regex: RegExp
    type: 'BigInt' | 'Number' | 'String'
  }
}

// ==============================================
// Constants
// ==============================================
/** Map of LOKAD protocol byte values to their UTF-8 string identifiers */
export const LOKAD_PREFIX_RANK = 0x52414e4b // RANK v1
export const LOKAD_PREFIX_RNKC = 0x524e4b43 // RANK Comment
export const LOKAD_PREFIX_RNKE = 0x524e4b45 // RANK Edit (for editing RNKC comments)
/** LOKAD chunk map */
export const SCRIPT_CHUNK_LOKAD: ScriptChunkLokadMap = new Map()
SCRIPT_CHUNK_LOKAD.set(LOKAD_PREFIX_RANK, 'RANK') // RANK v1
SCRIPT_CHUNK_LOKAD.set(LOKAD_PREFIX_RNKC, 'RNKC') // RANK Comment
SCRIPT_CHUNK_LOKAD.set(LOKAD_PREFIX_RNKE, 'RNKE') // RNKC Edit (for editing RNKC comments)
/** Sentiment value for neutral ranking (OP_16) */
export const RANK_SENTIMENT_NEUTRAL = Opcode.OP_16
/** Sentiment value for positive ranking (OP_1) */
export const RANK_SENTIMENT_POSITIVE = Opcode.OP_1
/** Sentiment value for negative ranking (OP_0) */
export const RANK_SENTIMENT_NEGATIVE = Opcode.OP_0
/** Sentiment chunk map */
export const SCRIPT_CHUNK_SENTIMENT: ScriptChunkSentimentMap = new Map()
SCRIPT_CHUNK_SENTIMENT.set(RANK_SENTIMENT_NEUTRAL, 'neutral')
SCRIPT_CHUNK_SENTIMENT.set(RANK_SENTIMENT_POSITIVE, 'positive')
SCRIPT_CHUNK_SENTIMENT.set(RANK_SENTIMENT_NEGATIVE, 'negative')
/** Sentiment op code map */
export const RANK_SENTIMENT_OP_CODES: Map<ScriptChunkSentimentUTF8, string> =
  new Map()
RANK_SENTIMENT_OP_CODES.set('neutral', 'OP_16')
RANK_SENTIMENT_OP_CODES.set('positive', 'OP_1')
RANK_SENTIMENT_OP_CODES.set('negative', 'OP_0')
/** Platform chunk map */
export const SCRIPT_CHUNK_PLATFORM: ScriptChunkPlatformMap = new Map()
//SCRIPT_CHUNK_PLATFORM.set(0x00, 'web_url') // any URL; the PROFILE script chunk is not necessary
SCRIPT_CHUNK_PLATFORM.set(0x00, 'lotusia') // Lotusia Explorer/dashboard
SCRIPT_CHUNK_PLATFORM.set(0x01, 'twitter') // twitter.com/x.com
/** Required RANK Comment script chunks */
export const ScriptChunksRNKCMap: Map<keyof ScriptChunksRNKC, ScriptChunk> =
  new Map()
ScriptChunksRNKCMap.set('platform', {
  offset: 7, // 0x01 push op at offset 6, then 1-byte platform begins at offset 7
  len: 1,
  map: SCRIPT_CHUNK_PLATFORM,
})
ScriptChunksRNKCMap.set('profileId', {
  offset: 9, // variable-length push op, then profileId begins at offset 9
  len: null, // specified in PlatformParameters
})
ScriptChunksRNKCMap.set('postId', {
  offset: null, // Comment data begins after OP_RETURN byte
  len: null, // specified in PlatformParameters
})
ScriptChunksRNKCMap.set('comment', {
  offset: null, // Comment data begins after OP_RETURN byte in outIdx 1 and 2
  len: null, // specified in PlatformParameters
})
/** Length of the required RANK script chunks in bytes */
export const RANK_SCRIPT_REQUIRED_LENGTH = 10
/** Required RANK script chunks */
export const ScriptChunksRANKMap: Map<keyof ScriptChunksRANK, ScriptChunk> =
  new Map()
ScriptChunksRANKMap.set('sentiment', {
  offset: 6, // OP_0 through OP_16 push number directly to stack; no push op
  len: 1,
  map: SCRIPT_CHUNK_SENTIMENT,
})
ScriptChunksRANKMap.set('platform', {
  offset: 8, // 0x01 push op at offset 7, then 1-byte platform begins at offset 8
  len: 1,
  map: SCRIPT_CHUNK_PLATFORM,
})
ScriptChunksRANKMap.set('profileId', {
  offset: 10, // variable-length push op, then profileId begins at offset 10
  len: null, // specified in PlatformParameters
})
/**
 * Optional RANK script chunks for extended functionality
 * These chunks are not required for basic RANK transactions but enable
 * additional features like ranking specific posts or tracking extension instances
 */
export const ScriptChunksOptionalRANKMap: Map<
  keyof ScriptChunksOptionalRANK,
  ScriptChunk
> = new Map()
ScriptChunksOptionalRANKMap.set('postId', {
  offset: null,
  len: null,
})
ScriptChunksOptionalRANKMap.set('instanceId', {
  offset: null,
  len: null,
})
/**
 * Platform configuration map for RANK protocol
 *
 * Maps platform identifiers to their validation parameters for profile IDs and post IDs.
 * Each platform has specific requirements for ID formats, lengths, and types.
 *
 * @example
 * ```typescript
 * const lotusiaConfig = PlatformConfiguration.get('lotusia')
 * // { profileId: { len: 33, regex: /^[0-9a-fA-F]{40,66}$/ }, postId: { len: 32, regex: /^[0-9a-f]{64}$/, type: 'String' } }
 * ```
 *
 * @see {@link PlatformParameters} for the structure of platform configuration
 * @see {@link ScriptChunkPlatformUTF8} for supported platform identifiers
 */
export const PlatformConfiguration: Map<
  ScriptChunkPlatformUTF8,
  PlatformParameters
> = new Map()
PlatformConfiguration.set('lotusia', {
  profileId: {
    len: 33, // 33-byte P2TR commitment (also supports 20-byte P2PKH for backward compatibility)
    regex: /^[0-9a-fA-F]{40,66}$/, // 20 bytes (P2PKH) or 33 bytes (P2TR)
  },
  postId: {
    len: 32, // 32-byte sha256 hash
    regex: /^[0-9a-f]{64}$/,
    type: 'String',
  },
})
PlatformConfiguration.set('twitter', {
  profileId: {
    len: 16,
    regex: /^[a-z0-9_]{1,16}$/,
  },
  postId: {
    len: 8, // 64-bit uint: https://developer.x.com/en/docs/x-ids
    regex: /^[0-9]+$/,
    type: 'BigInt',
  },
})

// ==============================================
// Functions
// ==============================================

/**
 * Check provided script for OP_RETURN op code
 * @param script - The script to check, as a `Buffer` or hex `string`
 * @returns true if the output is an OP_RETURN, false otherwise
 */
export function isOpReturn(script: Buffer | string): boolean {
  if (typeof script === 'string') {
    script = BufferUtil.from(script, 'hex')
  }
  return script.readUInt8(0) === Opcode.OP_RETURN
}

/**
 * Convert the profile ID to a buffer
 * @param platform - The platform to convert the profile ID for
 * @param profileId - The profile ID to convert
 * @returns The profile ID buffer
 */
export function toProfileIdBuf(
  platform: ScriptChunkPlatformUTF8,
  profileId: string,
): Buffer | null {
  const platformSpec = PlatformConfiguration.get(platform)
  if (!platformSpec) {
    return null
  }
  const profileIdSpec = platformSpec.profileId
  if (!profileIdSpec) {
    return null
  }

  if (profileIdSpec.regex && !profileIdSpec.regex.test(profileId)) {
    return null
  }

  switch (platform) {
    case 'lotusia': {
      const profileIdHex = BufferUtil.from(profileId, 'hex')
      const actualLen = profileIdHex.length

      // Support both P2PKH (20 bytes) and P2TR (33 bytes)
      if (actualLen !== 20 && actualLen !== 33) {
        return null
      }

      // Use the actual length of the scriptPayload, not the max length
      // P2PKH: 20 bytes, P2TR: 33 bytes
      const profileBuf = BufferUtil.alloc(actualLen)
      profileIdHex.copy(profileBuf, 0)
      return profileBuf
    }
    case 'twitter': {
      const profileBuf = BufferUtil.alloc(profileIdSpec.len)
      BufferUtil.from(profileId, 'utf8').copy(
        profileBuf,
        profileIdSpec.len - profileId.length,
      )
      return profileBuf
    }
    default:
      return null
  }
}
/**
 * Convert the `OP_RETURN` profile name back to UTF-8 with null bytes removed
 * @param profileIdBuf - The profile ID buffer to convert, padded with null bytes
 * @returns The UTF-8 profile ID
 */
export function toProfileIdUTF8(profileIdBuf: Buffer) {
  return new TextDecoder('utf-8').decode(
    profileIdBuf.filter(byte => byte != 0x00),
  )
}
/**
 * Convert the post ID to a buffer
 * @param platform - The platform to convert the post ID for
 * @param postId - The post ID to convert
 * @returns The post ID buffer
 */
export function toPostIdBuf(
  platform: ScriptChunkPlatformUTF8,
  postId: string,
): Buffer | undefined {
  switch (platform) {
    case 'lotusia':
      return BufferUtil.from(postId, 'hex')
    case 'twitter':
      return BufferUtil.from(BigInt(postId).toString(16), 'hex')
    default:
      return undefined
  }
}
/**
 * Convert the UTF-8 platform name to the defined 1-byte platform hex code
 * @param platform
 * @returns
 */
export function toPlatformBuf(
  platform: ScriptChunkPlatformUTF8,
): Buffer | undefined {
  for (const [byte, platformName] of SCRIPT_CHUNK_PLATFORM) {
    if (platformName == platform) {
      return BufferUtil.from([byte])
    }
  }
}
/**
 * Convert the defined 1-byte platform hex code to the UTF-8 platform name
 * @param platformBuf
 */
export function toPlatformUTF8(
  platformBuf: Buffer,
): ScriptChunkPlatformUTF8 | undefined {
  return SCRIPT_CHUNK_PLATFORM.get(platformBuf.readUInt8(0))
}
/**
 * Convert the UTF-8 sentiment name to the defined 1-byte OP code
 * @param sentiment
 * @returns
 */
export function toSentimentOpCode(sentiment: ScriptChunkSentimentUTF8) {
  return RANK_SENTIMENT_OP_CODES.get(sentiment)
}
/**
 * Convert the defined 1-byte sentiment OP code to the UTF-8 sentiment name
 * @param sentimentBuf
 */
export function toSentimentUTF8(
  sentimentBuf: Buffer,
): ScriptChunkSentimentUTF8 | undefined {
  return SCRIPT_CHUNK_SENTIMENT.get(sentimentBuf.readUInt8(0))
}
/**
 * Convert the comment buffer to a UTF-8 string
 * @param commentBuf - The comment buffer to convert
 * @returns The UTF-8 string
 */
export function toCommentUTF8(
  commentBuf: Buffer | Uint8Array,
): string | undefined {
  return new TextDecoder('utf-8').decode(commentBuf)
}

/**
 * Check if a script chunk contains a valid LOKAD identifier
 * @param scriptChunk - The script chunk to validate
 * @param lokadType - Optional specific LOKAD type to validate against
 * @returns `true` if the chunk contains a valid 4-byte LOKAD identifier, `false` otherwise
 */
export function isValidLokad(
  scriptChunk: Chunk,
  lokadType?: ScriptChunkLokadUTF8,
): boolean {
  let result =
    scriptChunk.buf !== undefined &&
    scriptChunk.buf.length === 4 &&
    SCRIPT_CHUNK_LOKAD.has(scriptChunk.buf.readUInt32BE(0))

  if (lokadType) {
    result =
      result &&
      scriptChunk.buf !== undefined &&
      SCRIPT_CHUNK_LOKAD.get(scriptChunk.buf?.readUInt32BE(0)) === lokadType
  }

  return result
}

/**
 * Parse a RANK script buffer into a structured TransactionOutputRANK object
 *
 * Decodes the RANK protocol script format:
 * OP_RETURN <RANK> <sentiment> <platform> <profileId> [<postId>]
 *
 * @param scriptBuf - The script buffer or hex string to parse
 * @returns The parsed RANK transaction output data
 * @throws Error if the script is not a valid OP_RETURN
 * @throws Error if the LOKAD identifier is invalid or not RANK
 * @throws Error if sentiment, platform, or profileId chunks are invalid
 * @throws Error if profileId doesn't match the platform's regex pattern
 * @throws Error if postId is present but invalid for the platform
 *
 * @example
 * ```typescript
 * const rankData = fromScriptRANK(scriptBuffer)
 * console.log(rankData.sentiment) // 'positive'
 * console.log(rankData.platform)  // 'lotusia'
 * console.log(rankData.profileId) // '0x...'
 * console.log(rankData.postId)    // optional
 * ```
 */
export function fromScriptRANK(
  scriptBuf: Buffer | string,
): TransactionOutputRANK {
  const script =
    typeof scriptBuf === 'string'
      ? Script.fromString(scriptBuf)
      : Script.fromBuffer(scriptBuf)

  // make sure script is OP_RETURN
  if (!script.isDataOut()) {
    throw new Error('Script is not OP_RETURN')
  }

  // process LOKAD chunk
  if (!isValidLokad(script.chunks[1], 'RANK')) {
    throw new Error('LOKAD chunk is either invalid or unsupported')
  }

  // process sentiment chunk
  const sentiment = SCRIPT_CHUNK_SENTIMENT.get(script.chunks[2].opcodenum)
  if (!sentiment) {
    throw new Error('Invalid sentiment chunk')
  }

  // process platform chunk
  const platform = SCRIPT_CHUNK_PLATFORM.get(
    script.chunks[3].buf?.readUInt8(0) as number,
  )
  if (!platform) {
    throw new Error('Invalid platform chunk')
  }

  const platformSpec = PlatformConfiguration.get(platform)
  if (!platformSpec) {
    throw new Error('Invalid platform spec')
  }

  const profileIdChunk = script.chunks[4]
  if (
    profileIdChunk.buf === undefined ||
    profileIdChunk.buf.length !== platformSpec.profileId.len
  ) {
    throw new Error(
      `Invalid profileId chunk (profileId chunk missing or length does not match platform ${platform})`,
    )
  }
  const profileId = toProfileIdUTF8(profileIdChunk.buf)

  // validate profileId regex
  if (!platformSpec.profileId.regex.test(profileId)) {
    throw new Error(
      `Invalid profileId "${profileId}" (regex does not match for platform ${platform})`,
    )
  }

  // Set up return data structure for required chunks
  const data: TransactionOutputRANK = {
    sentiment,
    platform,
    profileId,
  }

  // if we have optional chunks, process them
  if (script.chunks.length > 5) {
    // next chunk is postId
    const postIdChunk = script.chunks[5]
    if (postIdChunk.buf === undefined) {
      throw new Error('Invalid postId chunk (postId chunk missing)')
    }

    // Convert postId based on platform type
    if (platformSpec.postId?.type === 'BigInt') {
      // For platforms like twitter that use BigInt post IDs
      data.postId = postIdChunk.buf.readBigUInt64BE(0).toString()
    } else {
      // For platforms like lotusia that use hex string post IDs
      data.postId = postIdChunk.buf.toString('hex')
    }

    // Validate postId against platform regex if specified
    if (
      platformSpec.postId?.regex &&
      !platformSpec.postId.regex.test(data.postId)
    ) {
      throw new Error(
        `Invalid postId "${data.postId}" (regex does not match for platform ${platform})`,
      )
    }
  }

  return data
}

/**
 * Create a hex-encoded RANK script from the given parameters
 *
 * The RANK script follows the format:
 * OP_RETURN <RANK> <sentiment> <platform> <profileId> [<postId>]
 *
 * @param sentiment - The sentiment to express: 'positive', 'negative', or 'neutral'
 * @param platform - The platform identifier: 'lotusia' or 'twitter'
 * @param profileId - The profile ID to rank (script payload for lotusia, username for twitter)
 * @param postId - Optional post ID to rank a specific post instead of the profile
 * @returns The hex-encoded RANK script as a `Buffer`
 * @throws Error if sentiment, platform, or profileId is not specified
 * @throws Error if the platform specification is not defined
 * @throws Error if postId is provided but the platform doesn't support post ranking
 */
export function toScriptRANK(
  sentiment: ScriptChunkSentimentUTF8,
  platform: ScriptChunkPlatformUTF8,
  profileId: string,
  postId?: string,
): Buffer {
  // validate sentiment and platform
  if (!sentiment || !platform || !profileId) {
    throw new Error('Must specify sentiment, platform, and profileId')
  }
  const platformSpec = PlatformConfiguration.get(platform)
  if (!platformSpec || !platformSpec.profileId) {
    throw new Error(`RANK outputs for platform ${platform} are not supported`)
  }
  // create the script (OP_RETURN + LOKAD prefix)
  const script = Script.empty()
    .add(Opcode.OP_RETURN)
    // Add LOKAD prefix as buffer from hex to get PUSHDATA opcode
    .add(BufferUtil.from(toHex(LOKAD_PREFIX_RANK), 'hex'))
  // Append the sentiment op code
  switch (sentiment) {
    case 'neutral':
      script.add(RANK_SENTIMENT_NEUTRAL)
      break
    case 'positive':
      script.add(RANK_SENTIMENT_POSITIVE)
      break
    case 'negative':
      script.add(RANK_SENTIMENT_NEGATIVE)
      break
  }
  // Append the push op and platform byte
  script.add(toPlatformBuf(platform)!)
  // Append the push op for profileId length (variable: 20 for P2PKH, 33 for P2TR)
  const profileIdBuf = toProfileIdBuf(platform, profileId)!
  script.add(profileIdBuf)
  // If postId is provided, append the postId according to the platform specification
  if (postId) {
    if (!platformSpec.postId) {
      throw new Error(
        'Post ID provided, but no platform post specification defined',
      )
    }
    // Append the postId
    script.add(toPostIdBuf(platform, postId)!)
  }
  return script.toBuffer()
}

/**
 * Parse a RNKC script buffer into a structured TransactionOutputRNKC object
 *
 * Decodes the RNKC protocol script format:
 * OP_RETURN <RNKC> <platform> <profileId> [<postId>]
 * OP_RETURN <comment_data_part1>
 * [OP_RETURN <comment_data_part2>]
 *
 * @param scriptBuf - The main RNKC script buffer or hex string (output index 0)
 * @param supplementalScriptBufs - Additional OP_RETURN scripts containing comment data
 * @param burnedSats - The amount of satoshis burned for this transaction
 * @param options - Optional validation parameters
 * @param options.minDataLength - Minimum required comment data length (default: RNKC_MIN_DATA_LENGTH)
 * @param options.minFeeRate - Minimum required fee rate per byte (default: RNKC_MIN_FEE_RATE)
 * @returns The parsed RNKC transaction output data
 * @throws Error if the script is not a valid OP_RETURN
 * @throws Error if the LOKAD chunk is invalid or unsupported
 * @throws Error if the platform is invalid or unsupported
 * @throws Error if the profileId format is invalid for the platform
 * @throws Error if the postId format is invalid for the platform
 * @throws Error if no comment data is found in supplemental scripts
 * @throws Error if comment data length is below minimum
 * @throws Error if fee rate is too low
 */
export function fromScriptRNKC(
  scriptBuf: Buffer | string,
  supplementalScriptBufs: (Buffer | string)[],
  burnedSats: number | bigint,
  options?: { minDataLength: number; minFeeRate: number },
): TransactionOutputRNKC {
  // Parse the main RNKC script
  const script =
    typeof scriptBuf === 'string'
      ? Script.fromString(scriptBuf)
      : Script.fromBuffer(scriptBuf)

  // Validate script is OP_RETURN
  if (!script.isDataOut()) {
    throw new Error('Script is not OP_RETURN')
  }

  // Validate LOKAD identifier is RNKC
  if (!isValidLokad(script.chunks[1], 'RNKC')) {
    throw new Error('LOKAD chunk is either invalid or unsupported')
  }

  // Parse supplemental scripts containing comment data
  const supplementalScripts = supplementalScriptBufs.map(s =>
    typeof s === 'string' ? Script.fromString(s) : Script.fromBuffer(s),
  )

  // Extract and validate platform from chunk 2
  const platform = SCRIPT_CHUNK_PLATFORM.get(
    script.chunks[2].buf?.readUInt8(0) as number,
  )
  if (!platform) {
    throw new Error('Invalid platform chunk')
  }

  const platformSpec = PlatformConfiguration.get(platform)
  if (!platformSpec) {
    throw new Error('Platform configuration not found')
  }

  // Extract and validate profileId from chunk 3
  const profileIdChunk = script.chunks[3]
  if (!profileIdChunk?.buf) {
    throw new Error('Invalid profileId chunk')
  }
  const profileId = toProfileIdUTF8(profileIdChunk.buf)
  if (!platformSpec.profileId.regex.test(profileId)) {
    throw new Error('Invalid profileId format for platform')
  }

  // Extract and validate optional postId from chunk 4
  let postId: string | undefined
  if (script.chunks.length > 4 && script.chunks[4]?.buf) {
    if (!platformSpec.postId) {
      throw new Error('Post ID found but platform does not support post IDs')
    }
    postId = script.chunks[4].buf.toString('utf8')
    if (!platformSpec.postId.regex.test(postId)) {
      throw new Error('Invalid postId format for platform')
    }
  }

  // Concatenate comment data from supplemental OP_RETURN scripts
  let commentBuf: Buffer = BufferUtil.alloc(0)
  for (const supplementalScript of supplementalScripts) {
    if (!supplementalScript.isDataOut()) {
      break
    }
    const chunks = supplementalScript.chunks
    if (chunks.length < 2 || !chunks[1]?.buf) {
      break
    }
    commentBuf = BufferUtil.concat([commentBuf, chunks[1].buf])
  }

  if (commentBuf.length === 0) {
    throw new Error('No comment data found in supplemental scripts')
  }

  // Validate comment data length against minimum requirements
  const minDataLength = options?.minDataLength ?? RNKC_MIN_DATA_LENGTH
  const minFeeRate = options?.minFeeRate ?? RNKC_MIN_FEE_RATE

  if (commentBuf.length < minDataLength) {
    throw new Error(
      `Comment data length ${commentBuf.length} is below minimum ${minDataLength}`,
    )
  }

  // Validate fee rate meets minimum requirement
  const burnedSatsNum =
    typeof burnedSats === 'bigint' ? Number(burnedSats) : burnedSats
  if (burnedSatsNum < minFeeRate * commentBuf.length) {
    throw new Error(
      `Fee rate too low: ${Math.floor(burnedSatsNum / commentBuf.length)} < ${minFeeRate}`,
    )
  }

  // Construct and return the parsed RNKC output
  const result: TransactionOutputRNKC = {
    data: new Uint8Array(commentBuf),
    feeRate: Math.floor(burnedSatsNum / commentBuf.length),
    inReplyToPlatform: platform,
    inReplyToProfileId: profileId,
    inReplyToPostId: postId,
  }

  if (!result) {
    throw new Error('Failed to process RNKC script')
  }

  return result
}

/**
 * Create hex-encoded RANK Comment (RNKC) scripts from the given parameters
 *
 * RNKC is used to post comments on ranked content. The protocol requires
 * multiple output scripts: the first contains the RNKC header with platform,
 * profile, and optional post identifiers, while subsequent outputs contain
 * the comment data (split across 1-2 outputs if needed).
 *
 * The RNKC script format is:
 * Output 0: OP_RETURN <RNKC> <platform> <profileId> [<postId>]
 * Output 1: OP_RETURN <comment_part1>
 * Output 2 (optional): OP_RETURN <comment_part2>
 *
 * @param platform - The platform identifier: 'lotusia' or 'twitter'
 * @param profileId - The profile ID to comment on (script payload for lotusia, username for twitter)
 * @param postId - Optional post ID to comment on a specific post
 * @param comment - The comment text (UTF-8 encoded, max 2x MAX_OP_RETURN_DATA bytes)
 * @returns Array of hex-encoded RNKC scripts as `Buffer` objects
 * @throws Error if platform or profileId is not specified
 * @throws Error if the platform specification is not defined
 * @throws Error if profileId doesn't match the platform's regex pattern
 * @throws Error if postId is provided but doesn't match the platform's regex pattern
 * @throws Error if comment length is outside valid range (1 to MAX_OP_RETURN_DATA * 2 bytes)
 *
 * @example
 * ```typescript
 * const scripts = toScriptRNKC({
 *   platform: 'twitter',
 *   profileId: 'username',
 *   postId: '1234567890',
 *   comment: 'Great post!'
 * })
 * // Returns array of Buffer objects for each output script
 * ```
 *
 * @see {@link toScriptRANK} for ranking without comments
 * @see {@link ScriptProcessor.processScriptRNKC} for parsing RNKC scripts
 */
export function toScriptRNKC({
  platform,
  profileId,
  postId,
  comment,
}: {
  platform: ScriptChunkPlatformUTF8
  profileId: string
  postId?: string
  comment: string
}): Buffer[] {
  // validate platform and profileId
  if (!platform || !profileId) {
    throw new Error('Must specify platform and profileId')
  }
  const platformSpec = PlatformConfiguration.get(platform)
  if (!platformSpec || !platformSpec.profileId) {
    throw new Error(`RNKC outputs for platform ${platform} are not supported`)
  }
  // validate profileId
  if (!platformSpec.profileId.regex.test(profileId)) {
    throw new Error(`Invalid profileId: ${profileId}`)
  }
  // validate postId, if available
  if (postId && !platformSpec.postId.regex.test(postId)) {
    throw new Error(`Invalid postId: ${postId}`)
  }
  const commentBuf = BufferUtil.from(comment, 'utf8')
  if (commentBuf.length < 1 || commentBuf.length > MAX_OP_RETURN_DATA * 2) {
    throw new Error(
      `Comment must be between 1 and ${MAX_OP_RETURN_DATA * 2} bytes`,
    )
  }
  // Array to hold the output scripts
  // [0] = RNKC header, [1] = comment part 1, [2] = optional comment part 2
  const scriptBufs: Buffer[] = []
  // create the RNKC script (OP_RETURN + push op + LOKAD prefix)
  const script0 = Script.empty()
    .add(Opcode.OP_RETURN)
    // Add LOKAD prefix as buffer from hex to get PUSHDATA opcode
    .add(BufferUtil.from(toHex(LOKAD_PREFIX_RNKC), 'hex'))
    // Append the platform byte
    .add(toPlatformBuf(platform)!)
    // Append the profileId
    .add(toProfileIdBuf(platform, profileId)!)

  // Append the postId, if available
  if (postId) {
    script0.add(toPostIdBuf(platform, postId)!)
  }
  // Add the RNKC header script to the array
  scriptBufs.push(script0.toBuffer())

  // get max OP_RETURN data for comment and create the first comment script
  const commentBuf1 = commentBuf.slice(0, MAX_OP_RETURN_DATA)
  const script1 = Script.empty().add(Opcode.OP_RETURN).add(commentBuf1)
  // Add the first comment script to the array
  scriptBufs.push(script1.toBuffer())

  // create the second comment script if necessary
  if (commentBuf.length > MAX_OP_RETURN_DATA) {
    const commentBuf2 = commentBuf.slice(MAX_OP_RETURN_DATA)
    const script2 = Script.empty().add(Opcode.OP_RETURN).add(commentBuf2)
    // Add the second comment script to the array
    scriptBufs.push(script2.toBuffer())
  }

  return scriptBufs
}

/**
 * Processor for defined LOKAD protocols (RANK, RNKC, etc.)
 * @param script - The script to process, as a `Buffer`
 * @deprecated Use the individual LOKAD `from` functions instead (e.g. `fromScriptRANK`, `fromScriptRNKC`, etc.)
 */
export class ScriptProcessor {
  private chunks: Map<ScriptChunkField, ScriptChunk> | null = null
  /** The script to process, as a `Buffer` */
  private script: Buffer
  /** Supplemental scripts, e.g. outIdx 1 and/or 2 for RNKC */
  private supplementalScripts: Buffer[] = []

  constructor(script: Buffer) {
    // Accept the script for further processing
    this.script = script
    // Set chunk definitions based on LOKAD type
    switch (this.lokadType) {
      case 'RANK':
        this.chunks = ScriptChunksRANKMap
        break
      case 'RNKC':
        this.chunks = ScriptChunksRNKCMap
        break
    }
  }

  /**
   * Add a supplemental OP_RETURN script to the processor
   * @param script - The script to add, as a `Buffer`
   * @returns true if the script was added, false otherwise
   */
  addScript(script: string | Buffer): boolean {
    if (!BufferUtil.isBuffer(script)) {
      script = BufferUtil.from(script as string, 'hex')
    }
    if (!isOpReturn(script)) {
      return false
    }
    this.supplementalScripts.push(script)
    return true
  }

  /**
   * Get the LOKAD type from the script
   * @returns The LOKAD type or undefined if invalid
   */
  get lokadType(): ScriptChunkLokadUTF8 | undefined {
    return this.processLokad()
  }
  /**
   * Process the LOKAD chunk
   * @returns The LOKAD value or undefined if invalid
   */
  private processLokad(): ScriptChunkLokadUTF8 | undefined {
    // LOKAD is 4 bytes at offset 2 (OP_RETURN <PUSH OP> <4-byte LOKAD>)
    const lokadBuf = this.script.slice(2, 6)
    const lokad = SCRIPT_CHUNK_LOKAD.get(lokadBuf.readUInt32BE(0))
    if (!lokad) {
      return undefined
    }
    return lokad
  }

  /**
   * Process the sentiment chunk (RANK)
   * @returns The sentiment value or undefined if invalid
   */
  private processSentiment(): ScriptChunkSentimentUTF8 | undefined {
    const chunk = this.chunks?.get('sentiment')
    if (!chunk || chunk.offset === null) {
      return undefined
    }
    const sentimentBuf = this.script.slice(
      chunk.offset!,
      chunk.offset! + chunk.len!,
    )
    return SCRIPT_CHUNK_SENTIMENT.get(sentimentBuf.readUInt8(0))
  }

  /**
   * Process the platform chunk
   * @returns The platform value or undefined if invalid
   */
  private processPlatform(): ScriptChunkPlatformUTF8 | undefined {
    const chunk = this.chunks?.get('platform')
    if (!chunk || chunk.offset === null) {
      return undefined
    }
    const platformBuf = this.script.slice(
      chunk.offset!,
      chunk.offset! + chunk.len!,
    )
    const platform = SCRIPT_CHUNK_PLATFORM.get(platformBuf.readUInt8(0))
    if (!platform) {
      return undefined
    }
    return platform
  }

  /**
   * Process the profileId chunk
   * @returns The profileId value or undefined if invalid
   */
  private processProfileId(
    platform: ScriptChunkPlatformUTF8,
  ): string | undefined {
    const chunk = this.chunks?.get('profileId')
    if (!chunk || chunk.offset === null) {
      return undefined
    }

    const platformSpec = PlatformConfiguration.get(platform)
    if (!platformSpec || !platformSpec.profileId) {
      return undefined
    }

    // Read the actual length from the push opcode byte (1 byte before chunk.offset)
    const pushOpOffset = chunk.offset - 1
    if (pushOpOffset < 0 || pushOpOffset >= this.script.length) {
      return undefined
    }
    const actualLen = this.script.readUInt8(pushOpOffset)

    // For Lotusia platform, support both P2PKH (20 bytes) and P2TR (33 bytes)
    if (platform === 'lotusia' && actualLen !== 20 && actualLen !== 33) {
      return undefined
    }

    const profileIdBuf = this.script.slice(
      chunk.offset,
      chunk.offset + actualLen,
    )

    // Validate buffer length matches push opcode
    if (profileIdBuf.length !== actualLen) {
      return undefined
    }

    switch (platform) {
      case 'lotusia':
        return toHex(profileIdBuf)
      case 'twitter':
        return toProfileIdUTF8(profileIdBuf)
      default:
        return undefined
    }
  }

  /**
   * Process the postId chunk
   * @returns The postId value or undefined if invalid
   */
  private processPostId(platform: ScriptChunkPlatformUTF8): string | undefined {
    if (!platform) {
      return undefined
    }

    const platformSpec = PlatformConfiguration.get(platform)
    if (!platformSpec || !platformSpec.postId || !platformSpec.profileId) {
      return undefined
    }

    const profileIdChunk = this.chunks?.get('profileId')
    if (!profileIdChunk?.offset) {
      return undefined
    }

    // Read the actual profileId length from the push opcode byte
    const profileIdPushOpOffset = profileIdChunk.offset - 1
    if (
      profileIdPushOpOffset < 0 ||
      profileIdPushOpOffset >= this.script.length
    ) {
      return undefined
    }
    const actualProfileIdLen = this.script.readUInt8(profileIdPushOpOffset)

    // Calculate postId offset: profileId offset + actual profileId length + push opcode (1 byte)
    const postIdSpec = platformSpec.postId
    const postIdOffset = profileIdChunk.offset + actualProfileIdLen + 1

    // Validate that the script has enough data for the postId
    // If not, this is a top-level post without a postId (not a reply)
    if (postIdOffset + postIdSpec.len > this.script.length) {
      return undefined
    }

    // Also validate that there's a push opcode at the expected position
    const postIdPushOpOffset = postIdOffset - 1
    if (postIdPushOpOffset >= this.script.length) {
      return undefined
    }
    const postIdPushOp = this.script.readUInt8(postIdPushOpOffset)
    if (postIdPushOp !== postIdSpec.len) {
      return undefined
    }

    const postIdBuf = this.script.slice(
      postIdOffset,
      postIdOffset + postIdSpec.len,
    )

    try {
      switch (platform) {
        case 'lotusia':
          return postIdBuf.toString('hex')
        case 'twitter':
          return postIdBuf.readBigUInt64BE(0).toString()
        default:
          return undefined
      }
    } catch (e) {
      return undefined
    }
  }

  /**
   * Process the RNKC comment chunks (outIdx 1 and 2)
   * @param scripts - outIdx 1 and 2 scripts, if outIdx 0 is RNKC
   * @returns The comment value or null if invalid
   */
  private processComment(scripts: Buffer[]): Uint8Array | null {
    // If there are 3 scripts, concatenate outIdx 1 and 2, otherwise just use outIdx 1
    let commentBuf: Buffer = BufferUtil.alloc(0)
    for (let i = 0; i < scripts.length; i++) {
      const script = scripts[i]
      // OP_RETURN must be followed by OP_PUSHDATA1 (1 byte)
      if (script.readUInt8(1) !== Opcode.OP_PUSHDATA1) {
        break
      }
      // OP_PUSHDATA1 must be followed by the data size (1 byte)
      const dataSize = script.readUInt8(2)
      if (isNaN(dataSize) || dataSize > MAX_OP_RETURN_DATA) {
        break
      }
      // Concatenate the comment buffer with the script data
      commentBuf = BufferUtil.concat([
        commentBuf,
        script.slice(3, 3 + dataSize),
      ])
    }
    if (!commentBuf) {
      return null
    }
    return new Uint8Array(commentBuf)
  }

  /**
   * Validate the required RANK chunks and store the processed output
   * @returns true if all required chunks are valid, false otherwise
   */
  processScriptRANK(): TransactionOutputRANK | null {
    // Check sentiment (positive/negative)
    const sentiment = this.processSentiment()
    if (!sentiment) {
      return null
    }

    // Check platform (twitter, etc)
    const platform = this.processPlatform()
    if (!platform) {
      return null
    }

    // Check profileId (must exist and be valid for the platform)
    const profileId = this.processProfileId(platform)
    if (!profileId) {
      return null
    }

    // Store the processed output for future use
    const output = {
      sentiment,
      platform,
      profileId,
    } as TransactionOutputRANK

    // Process postId and set it in the output if it exists
    const postId = this.processPostId(platform)
    if (postId) {
      output.postId = postId
    }

    return output
  }
  /**
   * Validate the required RNKC chunks and store the processed output
   * @returns true if all required chunks are valid, false otherwise
   */
  processScriptRNKC(
    burnedSats: number | bigint,
    options?: { minDataLength: number; minFeeRate: number },
  ): TransactionOutputRNKC | null {
    if (typeof burnedSats === 'bigint') {
      burnedSats = Number(burnedSats)
    }
    // RNKC must have 1 or 2 supplemental scripts
    if (
      this.supplementalScripts.length === 0 ||
      this.supplementalScripts.length > 2
    ) {
      // throw new Error(
      //   'RNKC must have 1 or 2 supplemental OP_RETURN scripts (outIdx 1 and/or 2)',
      // )
      return null
    }
    // Check platform (twitter, etc)
    const inReplyToPlatform = this.processPlatform()
    if (!inReplyToPlatform) {
      return null
    }

    // Process comment and set it in the output if it exists
    const data = this.processComment(this.supplementalScripts)
    if (!data) {
      return null
    }

    // Validate the comment length of the RNKC transaction
    // If the comment length is too short, return null
    if (data.length < (options?.minDataLength ?? RNKC_MIN_DATA_LENGTH)) {
      return null
    }

    // Validate the fee rate of the RNKC transaction
    // If the fee rate is too low, return null
    if (burnedSats < (options?.minFeeRate ?? RNKC_MIN_FEE_RATE) * data.length) {
      return null
    }

    // Store the processed output for future use
    const output: TransactionOutputRNKC = {
      data,
      feeRate: Math.floor(burnedSats / data.length),
      inReplyToPlatform,
      inReplyToProfileId: undefined,
      inReplyToPostId: undefined,
    }

    // Check profileId (must exist and be valid for the platform)
    const profileId = this.processProfileId(inReplyToPlatform)
    if (profileId) {
      output.inReplyToProfileId = profileId
      // Check for postId (only valid if profileId is valid)
      const postId = this.processPostId(inReplyToPlatform)
      if (postId) {
        output.inReplyToPostId = postId
      }
    }

    return output
  }
}

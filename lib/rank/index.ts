/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */
import {
  MAX_OP_RETURN_DATA,
  RNKC_MIN_DATA_LENGTH,
  RNKC_MIN_FEE_RATE,
} from '../../utils/constants.js'
import { toHex } from '../../utils/string.js'
import OpCode from './opcode.js'
import { isOpReturn } from './script.js'
// RANK script types
export type ScriptChunkLokadUTF8 = 'RANK' | 'RNKC'
export type ScriptChunkPlatformUTF8 = 'lotusia' | 'twitter'
export type ScriptChunkSentimentUTF8 = 'positive' | 'negative' | 'neutral'
export type ScriptChunkLokadMap = Map<number, ScriptChunkLokadUTF8>
export type ScriptChunkPlatformMap = Map<number, ScriptChunkPlatformUTF8>
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
/** Target entity being ranked by a RANK transaction, commented on by an RNKC transaction, etc. (e.g. Profile, Post, etc.) */
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
/**  */
export type Profile = TargetEntity & {
  posts?: PostMap
}
/**  */
export type Post = TargetEntity & {
  profileId: string
  /** If this post is a RNKC transaction, this is set for establishing relation to `RankComment` */
  data?: Uint8Array
}

/** Platform parameters */
export type PlatformParameters = {
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

/** LOKAD chunk map */
export const LOKAD_PREFIX_RANK = 0x52414e4b // RANK v1
export const LOKAD_PREFIX_RNKC = 0x524e4b43 // RANK Comment
export const SCRIPT_CHUNK_LOKAD: ScriptChunkLokadMap = new Map()
SCRIPT_CHUNK_LOKAD.set(LOKAD_PREFIX_RANK, 'RANK') // RANK v1
SCRIPT_CHUNK_LOKAD.set(LOKAD_PREFIX_RNKC, 'RNKC') // RANK Comment
// SCRIPT_CHUNK_LOKAD.set(0x524e4b32, 'RNK2') // RANK v2
export const RANK_SENTIMENT_NEUTRAL = OpCode.OP_16
export const RANK_SENTIMENT_POSITIVE = OpCode.OP_1
export const RANK_SENTIMENT_NEGATIVE = OpCode.OP_0
/** Sentiment chunk map */
export const SCRIPT_CHUNK_SENTIMENT: ScriptChunkSentimentMap = new Map()
SCRIPT_CHUNK_SENTIMENT.set(RANK_SENTIMENT_NEUTRAL, 'neutral')
SCRIPT_CHUNK_SENTIMENT.set(RANK_SENTIMENT_POSITIVE, 'positive')
SCRIPT_CHUNK_SENTIMENT.set(RANK_SENTIMENT_NEGATIVE, 'negative')
/** Sentiment OP code map */
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
export const ScriptChunksOptionalRANKMap: Map<
  keyof ScriptChunksOptionalRANK,
  ScriptChunk
> = new Map()
ScriptChunksOptionalRANKMap.set('postId', {
  offset: null,
  len: null,
})
ScriptChunksOptionalRANKMap.set('postHash', {
  offset: null,
  len: null,
})
ScriptChunksOptionalRANKMap.set('instanceId', {
  offset: null,
  len: null,
})
/** Platform configuration */
export const PlatformConfiguration: Map<
  ScriptChunkPlatformUTF8,
  PlatformParameters
> = new Map()
PlatformConfiguration.set('lotusia', {
  profileId: {
    len: 20, // 20-byte P2PKH address
    regex: /^[0-9a-fA-F]{40}$/,
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

/**
 * RANK script utilities
 */

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
  const profileBuf = Buffer.alloc(profileIdSpec.len)
  switch (platform) {
    case 'lotusia': {
      const profileIdHex = Buffer.from(profileId, 'hex')
      profileBuf.write(
        profileId,
        profileIdSpec.len - profileIdHex.length,
        'hex',
      )
      break
    }
    case 'twitter':
      profileBuf.write(profileId, profileIdSpec.len - profileId.length, 'utf8')
      break
    default:
      return null
  }
  return profileBuf
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
      return Buffer.from(postId, 'hex')
    case 'twitter':
      return Buffer.from(BigInt(postId).toString(16), 'hex')
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
      return Buffer.from([byte])
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
  return SCRIPT_CHUNK_PLATFORM.get(platformBuf.readUint8())
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
  return SCRIPT_CHUNK_SENTIMENT.get(sentimentBuf.readUInt8())
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
 * Create a hex-encoded RANK script from the given parameters
 * @param sentiment - The sentiment to use
 * @param platform - The platform to use
 * @param profileId - The profile ID to use
 * @param postId - The post ID to use
 * @returns The hex-encoded RANK script, as `Buffer`
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
    throw new Error('No platform profileId specification defined')
  }
  // create the script (OP_RETURN + push op + LOKAD prefix)
  const OP_RETURN = toHex(OpCode.OP_RETURN)
  const LOKAD_PREFIX = toHex(LOKAD_PREFIX_RANK)
  let script = OP_RETURN + toHex(4) + LOKAD_PREFIX
  // Append the sentiment op code
  switch (sentiment) {
    case 'neutral':
      script += toHex(RANK_SENTIMENT_NEUTRAL)
      break
    case 'positive':
      script += toHex(RANK_SENTIMENT_POSITIVE)
      break
    case 'negative':
      script += toHex(RANK_SENTIMENT_NEGATIVE)
      break
  }
  // Append the push op and platform byte
  script += toHex(1) + toHex(toPlatformBuf(platform)!)
  // Append the push op for profileId length
  script += toHex(platformSpec.profileId.len)
  // Append the padded profileId
  script += toHex(toProfileIdBuf(platform, profileId)!) // push profileId
  // If postId is provided, append the postId according to the platform specification
  if (postId) {
    if (!platformSpec.postId) {
      throw new Error(
        'Post ID provided, but no platform post specification defined',
      )
    }
    // Append the push op for postId length
    script += toHex(platformSpec.postId.len)
    // Append the postId
    script += toHex(toPostIdBuf(platform, postId)!)
  }
  return Buffer.from(script, 'hex')
}

/**
 * Create a hex-encoded RANK Comment script from the given parameters
 *
 * RNKC requires 2 output scripts at minimum, so we return output scripts in an
 * array of `Buffer` objects according to outIdx.
 * @param platform - The platform to use
 * @param profileId - The profile ID to use
 * @param postId - The post ID to use
 * @param comment - The comment to use
 * @returns The hex-encoded RANK Comment script
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
    throw new Error('No platform profileId specification defined')
  }
  // validate profileId
  if (!platformSpec.profileId.regex.test(profileId)) {
    throw new Error(`Invalid profileId: ${profileId}`)
  }
  // validate postId, if available
  if (postId && !platformSpec.postId.regex.test(postId)) {
    throw new Error(`Invalid postId: ${postId}`)
  }
  const commentBuf = Buffer.from(comment, 'utf8')
  if (commentBuf.length < 1 || commentBuf.length > MAX_OP_RETURN_DATA * 2) {
    throw new Error(
      `Comment must be between 1 and ${MAX_OP_RETURN_DATA * 2} bytes`,
    )
  }
  const scriptBufs: Buffer[] = []
  // create the script (OP_RETURN + push op + LOKAD prefix)
  const OP_RETURN = toHex(OpCode.OP_RETURN)
  const OP_PUSHDATA1 = toHex(OpCode.OP_PUSHDATA1)
  const LOKAD_PREFIX = toHex(LOKAD_PREFIX_RNKC)
  let scriptRNKC = OP_RETURN + toHex(4) + LOKAD_PREFIX
  // Append the push op and platform byte
  scriptRNKC += toHex(1) + toHex(toPlatformBuf(platform)!)
  // Append the push op for profileId length
  scriptRNKC += toHex(platformSpec.profileId.len)
  // Append the padded profileId
  scriptRNKC += toHex(toProfileIdBuf(platform, profileId)!)
  // Append the postId, if available
  if (postId) {
    // Append the push op for postId length
    scriptRNKC += toHex(platformSpec.postId.len)
    scriptRNKC += toHex(toPostIdBuf(platform, postId)!)
  }
  scriptBufs.push(Buffer.from(scriptRNKC, 'hex'))

  // create the comment script(s)
  const commentBuf1 = commentBuf.subarray(0, MAX_OP_RETURN_DATA)
  // create the first comment script
  let scriptComment = OP_RETURN + OP_PUSHDATA1
  // Append the push op for comment length
  scriptComment += toHex(commentBuf1.length)
  // Append the comment
  scriptComment += toHex(commentBuf1)
  scriptBufs.push(Buffer.from(scriptComment, 'hex'))

  // create the second comment script if necessary
  if (commentBuf.length > MAX_OP_RETURN_DATA) {
    const commentBuf2 = commentBuf.subarray(MAX_OP_RETURN_DATA)
    let scriptComment2 = OP_RETURN + OP_PUSHDATA1
    // Append the push op for comment length
    scriptComment2 += toHex(commentBuf2.length)
    // Append the comment
    scriptComment2 += toHex(commentBuf2)
    scriptBufs.push(Buffer.from(scriptComment2, 'hex'))
  }

  return scriptBufs
}

/**
 * Processor for defined LOKAD protocols (RANK, RNKC, etc.)
 * @param script - The script to process, as a `Buffer`
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
    if (!(script instanceof Buffer)) {
      script = Buffer.from(script as string, 'hex')
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
    const lokadBuf = this.script.subarray(2, 6)
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
    const sentimentBuf = this.script.subarray(
      chunk.offset!,
      chunk.offset! + chunk.len!,
    )
    return SCRIPT_CHUNK_SENTIMENT.get(sentimentBuf.readUInt8())
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
    const platformBuf = this.script.subarray(
      chunk.offset!,
      chunk.offset! + chunk.len!,
    )
    const platform = SCRIPT_CHUNK_PLATFORM.get(platformBuf.readUInt8())
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

    const profileIdSpec = platformSpec.profileId
    const profileIdBuf = this.script.subarray(
      chunk.offset,
      chunk.offset + profileIdSpec.len,
    )

    // profileId chunk must be padded to required length
    if (profileIdBuf.length < profileIdSpec.len) {
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

    // Calculate postId offset: profileId offset + profileId length + push opcode (1 byte)
    const postIdSpec = platformSpec.postId
    const postIdOffset = profileIdChunk.offset + platformSpec.profileId.len + 1
    const postIdBuf = this.script.subarray(
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
    let commentBuf: Buffer = Buffer.alloc(0)
    for (let i = 0; i < scripts.length; i++) {
      const script = scripts[i]
      // OP_RETURN must be followed by OP_PUSHDATA1 (1 byte)
      if (script.readUInt8(1) !== OpCode.OP_PUSHDATA1) {
        break
      }
      // OP_PUSHDATA1 must be followed by the data size (1 byte)
      const dataSize = script.readUInt8(2)
      if (isNaN(dataSize) || dataSize > MAX_OP_RETURN_DATA) {
        break
      }
      // Concatenate the comment buffer with the script data
      commentBuf = Buffer.concat([commentBuf, script.subarray(3, 3 + dataSize)])
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

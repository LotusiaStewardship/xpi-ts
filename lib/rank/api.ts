export type InstanceData = {
  instanceId: string
  runtimeId: string
  startTime: string
  nonce: number
}
export type AuthorizationData = {
  instanceId: string
  scriptPayload: string
  blockhash: string
  blockheight: string
}
/** */
export type PostMeta = {
  hasWalletUpvoted: boolean
  hasWalletDownvoted: boolean
  txidsUpvoted: string[]
  txidsDownvoted: string[]
}
/** Transaction data returned from RANK backend API */
export type TransactionAPI = {
  txid: string
  outIdx: number
  sats: string
  firstSeen: string
  scriptPayload: string
  instanceId?: string
  height?: number
  timestamp?: string
}
export type TransactionRANKAPI = TransactionAPI & {
  sentiment: string
  platform: string
  profileId: string
  postId?: string
}
/** Comment data returned from RANK backend API */
export type TransactionRNKCAPI = TransactionAPI & {
  data: string
  feeRate: number
  platform: string
  inReplyToProfileId?: string
  inReplyToPostId?: string
  repliedProfile?: ProfileAPI
  repliedPost?: PostAPI
}
/** */
export type ParametersAPI = {
  platform: string
  profileId: string
}
/** Profile ranking returned from RANK backend API */
export type ProfileAPI = ParametersAPI & {
  ranking: string
  satsPositive: string
  satsNegative: string
  votesPositive: number
  votesNegative: number
  /** RANK transactions associated with the profile */
  ranks?: TransactionRANKAPI[]
  /** Comments associated with the profile */
  comments?: TransactionRNKCAPI[]
  /** Posts associated with the profile */
  posts?: PostAPI[]
}
/** Post ranking returned from RANK backend API */
export type PostAPI = ParametersAPI & {
  ranking: string
  satsPositive: string
  satsNegative: string
  votesPositive: number
  votesNegative: number
  profile: ProfileAPI
  postId: string
  /** RANK transactions associated with the post */
  ranks?: TransactionRANKAPI[]
  /** Comments associated with the post */
  comments?: TransactionRNKCAPI[]
  /** Comment data as a UTF-8 string, if available */
  data?: string
  postMeta?: PostMeta
}

/** Authentication header parameters provided to client for authorization to API */
export const AuthenticateHeader = {
  scheme: 'BlockDataSig',
  param: ['blockhash', 'blockheight'],
}

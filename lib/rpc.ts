/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */
import { encodeBase64 } from '../utils/string.js'

/**
 * Individual JSON-RPC result types
 */
type JSONRPCResult =
  | string
  | string[]
  | number
  | NetworkInfo
  | MiningInfo
  | MempoolInfo
  | PeerInfo[]
  | BlockStats
  | BlockInfo
  | RawTransaction
/**
 * Raw JSON-RPC response from the RPC daemon
 */
type JSONRPCResponse = {
  result: JSONRPCResult
  error: null | {
    code: number
    message: string
  }
  id: number
}
/**
 * RPC daemon configuration
 */
export interface RPCConfig {
  /** Username for RPC authentication */
  user: string
  /** Password for RPC authentication */
  password: string
  /** RPC daemon address (hostname or IP) */
  address: string
  /** RPC daemon port number */
  port: number
}
/**
 * Network information returned by the RPC daemon
 */
export interface NetworkInfo {
  /** Subversion string */
  subversion: string
  /** Whether local relay is enabled */
  localrelay: boolean
  /** Number of connections */
  connections: number
  /** Number of inbound connections */
  connections_in: number
  /** Network warnings if any */
  warnings: string
}

/**
 * Mining information returned by the RPC daemon
 */
export interface MiningInfo {
  /** Current block height */
  blocks: number
  /** Current network difficulty */
  difficulty: number
  /** Network hash rate in hashes per second */
  networkhashps: number
  /** Number of transactions in the mempool */
  pooledtx: number
  /** Blockchain name (e.g., "main", "test", "regtest") */
  chain: string
  /** Network warnings if any */
  warnings: string
}

/**
 * Mempool information returned by the RPC daemon
 */
export interface MempoolInfo {
  /** Whether the mempool is loaded */
  loaded: boolean
  /** Number of transactions in mempool */
  size: number
  /** Total size of mempool in bytes */
  bytes: number
  /** Memory usage in bytes */
  usage: number
  /** Maximum mempool size in bytes */
  maxmempool: number
  /** Minimum fee rate for mempool transactions */
  mempoolminfee: number
  /** Minimum relay fee rate */
  minrelaytxfee: number
  /** Number of unbroadcast transactions */
  unbroadcastcount: number
}

/**
 * Peer connection information returned by the RPC daemon
 */
export interface PeerInfo {
  /** Peer address and port */
  addr: string
  /** Peer services as hex string */
  services: string
  /** Array of service names */
  servicesnames: Array<string>
  /** Whether peer relays transactions */
  relaytxes: boolean
  /** Timestamp of last sent message */
  lastsend: number
  /** Timestamp of last received message */
  lastrecv: number
  /** Timestamp of last transaction */
  last_transaction: number
  /** Timestamp of last proof */
  last_proof: number
  /** Timestamp of last block */
  last_block: number
  /** Total bytes sent to peer */
  bytessent: number
  /** Total bytes received from peer */
  bytesrecv: number
  /** Connection time timestamp */
  conntime: number
  /** Time offset in seconds */
  timeoffset: number
  /** Current ping time in seconds */
  pingtime: number
  /** Minimum ping time in seconds */
  minping: number
  /** Protocol version */
  version: number
  /** User agent string */
  subver: string
  /** Whether connection is inbound */
  inbound: boolean
  /** Starting block height */
  startingheight: number
  /** Number of synced headers */
  synced_headers: number
  /** Number of synced blocks */
  synced_blocks: number
  /** GeoIP data */
  geoip?: {
    country: string
    city: string
  }
}

/**
 * Block statistics returned by the RPC daemon
 */
export interface BlockStats {
  /** Average fee in the block */
  avgfee: number
  /** Average fee rate in the block */
  avgfeerate: number
  /** Average transaction size in the block */
  avgtxsize: number
  /** Block hash */
  blockhash: string
  /** Fee rate percentiles */
  feerate_percentiles: Array<number>
  /** Block height */
  height: number
  /** Number of inputs */
  ins: number
  /** Maximum fee in the block */
  maxfee: number
  /** Maximum fee rate in the block */
  maxfeerate: number
  /** Maximum transaction size in the block */
  maxtxsize: number
  /** Median fee in the block */
  medianfee: number
  /** Median fee rate in the block */
  medianfeerate: number
  /** Median transaction size in the block */
  mediantxsize: number
  /** Minimum fee rate in the block */
  minfeerate: number
  /** Minimum transaction size in the block */
  mintxsize: number
  /** Number of outputs */
  notx: number
  /** Number of outputs */
  outs: number
  /** Block subsidy */
  subsidy: number
  /** Block timestamp */
  time: number
  /** Total output value */
  total_out: number
  /** Total block size */
  total_size: number
  /** Total fees in the block */
  totalfee: number
  /** Number of transactions */
  txs: number
  /** UTXO increase count */
  utxo_increase: number
  /** UTXO size increase */
  utxo_size_inc: number
}

/**
 * Block information returned by the RPC daemon
 */
export interface BlockInfo {
  /** Block hash */
  hash: string
  /** Number of confirmations */
  confirmations: number
  /** Block size in bytes */
  size: number
  /** Block height */
  height: number
  /** Array of transaction IDs */
  tx: Array<string>
  /** Block timestamp */
  time: number
  /** Block difficulty */
  difficulty: number
  /** Number of transactions */
  nTx: number
  /** Previous block hash */
  previousblockhash: string
  /** Next block hash */
  nextblockhash: string
}

/**
 * Transaction input information
 */
export interface TransactionInput {
  /** Transaction ID */
  txid: string
  /** Output index */
  vout: number
  /** Coinbase transaction data (for coinbase inputs) */
  coinbase?: string
}

/**
 * Transaction output information
 */
export interface TransactionOutput {
  /** Output value in coins */
  value: number
  /** Script public key information */
  scriptPubKey: {
    /** Array of addresses */
    addresses: Array<string>
    /** Script type */
    type: string
    /** Assembly representation */
    asm: string
  }
}

/**
 * Raw transaction information returned by the RPC daemon
 */
export interface RawTransaction {
  /** Transaction ID */
  txid: string
  /** Transaction size in bytes */
  size: number
  /** Array of transaction inputs */
  vin: TransactionInput[]
  /** Array of transaction outputs */
  vout: TransactionOutput[]
  /** Transaction timestamp */
  time?: number
  /** Block timestamp */
  blocktime?: number
  /** Block hash containing this transaction */
  blockhash?: string
  /** Number of confirmations */
  confirmations?: number
}

export class RPCClient {
  config: RPCConfig

  constructor(config: RPCConfig) {
    this.config = config
  }

  /**
   * Sends an RPC request to the Lotus daemon
   * @param method - The RPC method to call
   * @param params - Array of parameters to pass to the RPC method
   * @returns Promise that resolves to the JSON response from the RPC daemon
   */
  private async sendRPCRequest(
    method: string,
    params: unknown[],
  ): Promise<JSONRPCResult> {
    const response = await fetch(
      `http://${this.config.address}:${this.config.port}`,
      {
        method: 'POST',
        body: JSON.stringify({ method, params }),
        credentials: 'include',
        headers: new Headers({
          Authorization: `Basic ${encodeBase64(`${this.config.user}:${this.config.password}`)}`,
        }),
      },
    )
    const json = (await response.json()) as JSONRPCResponse
    if (json.error) {
      throw new Error(
        `JSON-RPC error: ${json.error.message} (code: ${json.error.code})`,
      )
    }
    return json.result
  }

  /**
   * RPC command - `getmininginfo`
   * @returns {Promise<MiningInfo>} Raw mining information
   */
  async getMiningInfo(): Promise<MiningInfo> {
    const result = await this.sendRPCRequest('getmininginfo', [])
    return result as MiningInfo
  }

  /**
   * RPC command - `getnetworkinfo`
   * @returns {Promise<NetworkInfo>} Network information
   */
  async getNetworkInfo(): Promise<NetworkInfo> {
    const result = await this.sendRPCRequest('getnetworkinfo', [])
    return result as NetworkInfo
  }

  /**
   * RPC command - `getpeerinfo`
   * @returns {Promise<PeerInfo[]>} Array of peer connection information
   */
  async getPeerInfo(): Promise<PeerInfo[]> {
    const result = await this.sendRPCRequest('getpeerinfo', [])
    return result as PeerInfo[]
  }

  /**
   * RPC command - `getblockcount`
   * @returns {Promise<number>} Current block count
   */
  async getBlockCount(): Promise<number> {
    const result = await this.sendRPCRequest('getblockcount', [])
    return result as number
  }

  /**
   * RPC command - `getblockhash`
   * @param {number} height - Block height
   * @returns {Promise<string>} Block hash for the given height
   */
  async getBlockHash(height: number): Promise<string> {
    const result = await this.sendRPCRequest('getblockhash', [height])
    return result as string
  }

  /**
   * RPC command - `getblockstats`
   * @param {string} hash - Block hash
   * @returns {Promise<BlockStats>} Block statistics
   */
  async getBlockStats(hash: string): Promise<BlockStats> {
    const result = await this.sendRPCRequest('getblockstats', [hash])
    return result as BlockStats
  }

  /**
   * RPC command - `getblock`
   * @param {string} hash - Block hash
   * @returns {Promise<BlockInfo>} Block information
   */
  async getBlock(hash: string): Promise<BlockInfo> {
    const result = await this.sendRPCRequest('getblock', [hash])
    return result as BlockInfo
  }

  /**
   * RPC command - `getrawtransaction`
   * @param {string} txid - Transaction ID
   * @returns {Promise<RawTransaction>} Raw transaction information
   */
  async getRawTransaction(txid: string): Promise<RawTransaction> {
    const result = await this.sendRPCRequest('getrawtransaction', [txid, true])
    return result as RawTransaction
  }

  /**
   * RPC command - `getrawmempool`
   * @returns {Promise<string[]>} Array of transaction IDs in mempool
   */
  async getRawMemPool(): Promise<string[]> {
    const result = await this.sendRPCRequest('getrawmempool', [])
    return result as string[]
  }

  /**
   * RPC command - `getmempoolinfo`
   * @returns {Promise<MempoolInfo>} Mempool information
   */
  async getMempoolInfo(): Promise<MempoolInfo> {
    const result = await this.sendRPCRequest('getmempoolinfo', [])
    return result as MempoolInfo
  }
}

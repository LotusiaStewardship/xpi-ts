/**
 * Network definitions for Lotus
 * Migrated from bitcore-lib-xpi with ESM support
 */

function prefixToArray(prefix: string): number[] {
  const result: number[] = []
  for (let i = 0; i < prefix.length; i++) {
    result.push(prefix.charCodeAt(i) & 31)
  }
  return result
}

/**
 * Configuration options for defining a blockchain network.
 */
export interface NetworkConfig {
  /** The canonical name of the network (e.g., 'livenet', 'testnet'). */
  name: string
  /** An alternative or friendly name for the network (e.g., 'mainnet', 'regtest'). */
  alias: string
  /** Prefix for P2PKH (Pay-to-Public-Key-Hash/legacy address) encoding. */
  pubkeyhash: number
  /** Prefix for WIF (Wallet Import Format) private key encoding. */
  privatekey: number
  /** Prefix for P2SH (Pay-to-Script-Hash) address encoding. */
  scripthash: number
  /** Prefix for Bech32 (CashAddr/XAddress) encoding. */
  bech32prefix?: string
  /** Prefix for extended public key (xpub) in BIP32 serialization. */
  xpubkey: number
  /** Prefix for extended private key (xpriv) in BIP32 serialization. */
  xprivkey: number
  /** Magic bytes used to identify the network in peer-to-peer messages. */
  networkMagic: Buffer
  /** Default port for peer-to-peer connections on this network. */
  port: number
  /** Array of DNS seeds for peer discovery on the network. */
  dnsSeeds: string[]
  /** Optional human-readable prefix for addresses (e.g., in CashAddr/XAddress format). */
  prefix?: string
  /** Optional array of numeric values derived from the prefix, used for address formatting. */
  prefixArray?: number[]
  /** Optional network identifier used in address encoding (e.g., '_' for mainnet). */
  networkbyte?: string
}

export class Network {
  readonly name: string
  readonly alias: string
  readonly pubkeyhash: number
  readonly privatekey: number
  readonly scripthash: number
  readonly xpubkey: number
  readonly xprivkey: number
  readonly networkMagic: Buffer
  readonly port: number
  readonly dnsSeeds: string[]
  readonly prefix?: string
  readonly prefixArray?: number[]
  readonly networkbyte?: string

  constructor(config: NetworkConfig) {
    this.name = config.name
    this.alias = config.alias
    this.pubkeyhash = config.pubkeyhash
    this.privatekey = config.privatekey
    this.scripthash = config.scripthash
    this.xpubkey = config.xpubkey
    this.xprivkey = config.xprivkey
    this.networkMagic = config.networkMagic
    this.port = config.port
    this.dnsSeeds = config.dnsSeeds
    this.prefix = config.prefix
    this.prefixArray = config.prefixArray
    this.networkbyte = config.networkbyte
  }

  toString(): string {
    return this.name
  }
}

// Network definitions
export const livenet = new Network({
  name: 'livenet',
  alias: 'mainnet',
  prefix: 'bitcoincash',
  networkbyte: '_',
  pubkeyhash: 0,
  privatekey: 0x80,
  scripthash: 5,
  xpubkey: 0x0488b21e,
  xprivkey: 0x0488ade4,
  networkMagic: Buffer.from('ece7eff3', 'hex'),
  port: 10605,
  dnsSeeds: ['seed.lotusia.org'],
  prefixArray: prefixToArray('bitcoincash'),
})

export const testnet = new Network({
  name: 'testnet',
  alias: 'test',
  prefix: 'bchtest',
  networkbyte: 'T',
  pubkeyhash: 0x6f,
  privatekey: 0xef,
  scripthash: 0xc4,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394,
  networkMagic: Buffer.from('ecf4f3f4', 'hex'),
  port: 11605,
  dnsSeeds: ['seed.lotusia.org'],
  prefixArray: prefixToArray('bchtest'),
})

export const regtest = new Network({
  name: 'regtest',
  alias: 'reg',
  prefix: 'bchreg',
  networkbyte: 'R',
  pubkeyhash: 0x6f,
  privatekey: 0xef,
  scripthash: 0xc4,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394,
  networkMagic: Buffer.from('ecf2e5e7', 'hex'),
  port: 12605,
  dnsSeeds: [],
  prefixArray: prefixToArray('bchreg'),
})

export const networks = [livenet, testnet, regtest]
export const networkMaps: Record<string, Network> = {}

// Build network maps
networks.forEach(network => {
  networkMaps[network.name] = network
  networkMaps[network.alias] = network
  networkMaps[network.pubkeyhash] = network
  networkMaps[network.privatekey] = network
  networkMaps[network.scripthash] = network
  networkMaps[network.xpubkey] = network
  networkMaps[network.xprivkey] = network
})

export const defaultNetwork = livenet

export function get(
  arg: string | number | Network,
  keys?: string | string[],
): Network | undefined {
  if (networks.includes(arg as Network)) {
    return arg as Network
  }

  if (keys) {
    const keyArray = Array.isArray(keys) ? keys : [keys]
    for (const network of networks) {
      const filteredNet = keyArray.reduce(
        (acc, key) => {
          acc[key] = (network as unknown as Record<string, unknown>)[key]
          return acc
        },
        {} as Record<string, unknown>,
      )
      const netValues = Object.values(filteredNet)
      if (netValues.includes(arg)) {
        return network
      }
    }
    return undefined
  }

  return networkMaps[arg as string]
}

export function add(data: NetworkConfig): Network {
  const network = new Network(data)
  networks.push(network)

  // Index the network by its properties
  networkMaps[network.name] = network
  networkMaps[network.alias] = network
  networkMaps[network.pubkeyhash] = network
  networkMaps[network.privatekey] = network
  networkMaps[network.scripthash] = network
  networkMaps[network.xpubkey] = network
  networkMaps[network.xprivkey] = network

  return network
}

export function remove(network: Network): void {
  const index = networks.indexOf(network)
  if (index !== -1) {
    networks.splice(index, 1)

    // Remove from network maps
    Object.keys(networkMaps).forEach(key => {
      if (networkMaps[key] === network) {
        delete networkMaps[key]
      }
    })
  }
}

// Networks namespace export
export const Networks = {
  add,
  remove,
  get,
  defaultNetwork,
  livenet,
  mainnet: livenet, // Alias for livenet as shown in TypeScript definitions
  testnet,
  regtest,
}

/**
 * Error handling module
 * Migrated from bitcore-lib-xpi with ESM support and TypeScript
 */

function format(message: string, args: unknown[]): string {
  return message
    .replace('{0}', String(args[0] || ''))
    .replace('{1}', String(args[1] || ''))
    .replace('{2}', String(args[2] || ''))
}

function traverseNode(
  parent: Function,
  errorDefinition: ErrorDefinition,
): Function {
  const NodeError = function (this: any, ...args: unknown[]) {
    if (typeof errorDefinition.message === 'string') {
      this.message = format(errorDefinition.message, args)
    } else if (typeof errorDefinition.message === 'function') {
      this.message = errorDefinition.message.apply(null, args)
    } else {
      throw new Error('Invalid error definition for ' + errorDefinition.name)
    }
    this.stack = this.message + '\n' + new Error().stack
  }
  NodeError.prototype = Object.create(parent.prototype)
  NodeError.prototype.name = parent.prototype.name + errorDefinition.name
  ;(parent as any)[errorDefinition.name] = NodeError
  if (errorDefinition.errors) {
    childDefinitions(NodeError, errorDefinition.errors)
  }
  return NodeError
}

function childDefinitions(
  parent: Function,
  childDefinitions: ErrorDefinition[],
): void {
  childDefinitions.forEach(childDefinition => {
    traverseNode(parent, childDefinition)
  })
}

function traverseRoot(
  parent: Function,
  errorsDefinition: ErrorDefinition[],
): Function {
  childDefinitions(parent, errorsDefinition)
  return parent
}

interface ErrorDefinition {
  name: string
  message: string | ((...args: unknown[]) => string)
  errors?: ErrorDefinition[]
}

const docsURL = 'http://bitcore.io/'

const errorSpec: ErrorDefinition[] = [
  {
    name: 'InvalidB58Char',
    message: 'Invalid Base58 character: {0} in {1}',
  },
  {
    name: 'InvalidB58Checksum',
    message: 'Invalid Base58 checksum for {0}',
  },
  {
    name: 'InvalidNetwork',
    message: 'Invalid version for network: got {0}',
  },
  {
    name: 'InvalidState',
    message: 'Invalid state: {0}',
  },
  {
    name: 'NotImplemented',
    message: 'Function {0} was not implemented yet',
  },
  {
    name: 'InvalidNetworkArgument',
    message: 'Invalid network: must be "livenet" or "testnet", got {0}',
  },
  {
    name: 'AbstractMethodInvoked',
    message: 'Abstract Method Invocation: {0}',
  },
  {
    name: 'Precondition',
    message: 'Precondition Failed: {0}',
    errors: [
      {
        name: 'InvalidState',
        message: 'Invalid state: {0}',
      },
      {
        name: 'InvalidArgument',
        message: function () {
          return (
            'Invalid Argument' +
            (arguments[0] ? ': ' + arguments[0] : '') +
            (arguments[1] ? ' Documentation: ' + docsURL + arguments[1] : '')
          )
        },
      },
      {
        name: 'InvalidArgumentType',
        message: function () {
          return (
            'Invalid Argument for ' +
            arguments[2] +
            ', expected ' +
            arguments[1] +
            ' but got ' +
            typeof arguments[0]
          )
        },
      },
    ],
  },
  {
    name: 'Unit',
    message: 'Internal Error on Unit {0}',
    errors: [
      {
        name: 'UnknownCode',
        message: 'Unrecognized unit code: {0}',
      },
      {
        name: 'InvalidRate',
        message: 'Invalid exchange rate: {0}',
      },
    ],
  },
  {
    name: 'MerkleBlock',
    message: 'Internal Error on MerkleBlock {0}',
    errors: [
      {
        name: 'InvalidMerkleTree',
        message: 'This MerkleBlock contain an invalid Merkle Tree',
      },
    ],
  },
  {
    name: 'Transaction',
    message: 'Internal Error on Transaction {0}',
    errors: [
      {
        name: 'Input',
        message: 'Internal Error on Input {0}',
        errors: [
          {
            name: 'MissingScript',
            message: 'Need a script to create an input',
          },
          {
            name: 'UnsupportedScript',
            message: 'Unsupported input script type: {0}',
          },
          {
            name: 'MissingPreviousOutput',
            message: 'No previous output information.',
          },
          {
            name: 'BlockHeightOutOfRange',
            message: 'Block Height can only be between 0 and 65535',
          },
          {
            name: 'LockTimeRange',
            message: 'Seconds needs to be more that 0 and less that 33553920',
          },
        ],
      },
      {
        name: 'NeedMoreInfo',
        message: '{0}',
      },
      {
        name: 'InvalidSorting',
        message:
          'The sorting function provided did not return the change output as one of the array elements',
      },
      {
        name: 'InvalidOutputAmountSum',
        message: '{0}',
      },
      {
        name: 'MissingSignatures',
        message: 'Some inputs have not been fully signed',
      },
      {
        name: 'InvalidIndex',
        message: 'Invalid index: {0} is not between 0, {1}',
      },
      {
        name: 'UnableToVerifySignature',
        message: 'Unable to verify signature: {0}',
      },
      {
        name: 'DustOutputs',
        message: 'Dust amount detected in one output',
      },
      {
        name: 'InvalidSatoshis',
        message: 'Output satoshis are invalid',
      },
      {
        name: 'FeeError',
        message: 'Internal Error on Fee {0}',
        errors: [
          {
            name: 'TooSmall',
            message: 'Fee is too small: {0}',
          },
          {
            name: 'TooLarge',
            message: 'Fee is too large: {0}',
          },
          {
            name: 'Different',
            message: 'Unspent value is different from specified fee: {0}',
          },
        ],
      },
      {
        name: 'ChangeAddressMissing',
        message: 'Change address is missing',
      },
      {
        name: 'BlockHeightTooHigh',
        message: 'Block Height can be at most 2^32 -1',
      },
      {
        name: 'NLockTimeOutOfRange',
        message: 'Block Height can only be between 0 and 499 999 999',
      },
      {
        name: 'LockTimeTooEarly',
        message: "Lock Time can't be earlier than UNIX date 500 000 000",
      },
    ],
  },
  {
    name: 'Script',
    message: 'Internal Error on Script {0}',
    errors: [
      {
        name: 'UnrecognizedAddress',
        message: 'Expected argument {0} to be an address',
      },
      {
        name: 'CantDeriveAddress',
        message:
          "Can't derive address associated with script {0}, needs to be p2pkh in, p2pkh out, p2sh in, or p2sh out.",
      },
      {
        name: 'InvalidBuffer',
        message:
          "Invalid script buffer: can't parse valid script from given buffer {0}",
      },
      {
        name: 'InvalidScriptString',
        message: 'Invalid script string: {0}',
      },
    ],
  },
  {
    name: 'HDPrivateKey',
    message: 'Internal Error on HDPrivateKey {0}',
    errors: [
      {
        name: 'InvalidDerivationArgument',
        message:
          'Invalid derivation argument {0}, expected string, or number and boolean',
      },
      {
        name: 'InvalidEntropyArgument',
        message:
          'Invalid entropy: must be an hexa string or binary buffer, got {0}',
        errors: [
          {
            name: 'TooMuchEntropy',
            message:
              'Invalid entropy: more than 512 bits is non standard, got "{0}"',
          },
          {
            name: 'NotEnoughEntropy',
            message: 'Invalid entropy: at least 128 bits needed, got "{0}"',
          },
        ],
      },
      {
        name: 'InvalidLength',
        message: 'Invalid length for xprivkey string in {0}',
      },
      {
        name: 'InvalidPath',
        message: 'Invalid derivation path: {0}',
      },
      {
        name: 'UnrecognizedArgument',
        message:
          'Invalid argument: creating a HDPrivateKey requires a string, buffer, json or object, got "{0}"',
      },
    ],
  },
  {
    name: 'HDPublicKey',
    message: 'Internal Error on HDPublicKey {0}',
    errors: [
      {
        name: 'ArgumentIsPrivateExtended',
        message: 'Argument is an extended private key: {0}',
      },
      {
        name: 'InvalidDerivationArgument',
        message: 'Invalid derivation argument: got {0}',
      },
      {
        name: 'InvalidLength',
        message: 'Invalid length for xpubkey: got "{0}"',
      },
      {
        name: 'InvalidPath',
        message:
          'Invalid derivation path, it should look like: "m/1/100", got "{0}"',
      },
      {
        name: 'InvalidIndexCantDeriveHardened',
        message:
          'Invalid argument: creating a hardened path requires an HDPrivateKey',
      },
      {
        name: 'MustSupplyArgument',
        message: 'Must supply an argument to create a HDPublicKey',
      },
      {
        name: 'UnrecognizedArgument',
        message:
          'Invalid argument for creation, must be string, json, buffer, or object',
      },
    ],
  },
]

export class BitcoreError extends Error {
  constructor(message?: string) {
    super(message || 'Internal error')
    this.name = 'bitcore.Error'
    this.stack = this.message + '\n' + new Error().stack
  }

  static extend(spec: ErrorDefinition): Function {
    return traverseNode(BitcoreError, spec)
  }

  // Type declarations for dynamically added error types
  static NotImplemented: new (message?: string) => BitcoreError
  static Script: {
    InvalidBuffer: new (buffer: string) => BitcoreError
    UnrecognizedAddress: new (address: unknown) => BitcoreError
    CantDeriveAddress: new (script: string) => BitcoreError
    InvalidScriptString: new (script: string) => BitcoreError
  }
  static Precondition: {
    InvalidState: new (message: string) => BitcoreError
    InvalidArgument: new (
      argumentName: string,
      message?: string,
      docsPath?: string,
    ) => BitcoreError
    InvalidArgumentType: new (
      argument: unknown,
      type: string | Function,
      argumentName?: string,
    ) => BitcoreError
  }
  static Transaction: {
    Input: {
      MissingScript: new () => BitcoreError
    }
  }
}

// Initialize the error hierarchy
traverseRoot(BitcoreError, errorSpec)

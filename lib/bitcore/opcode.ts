/**
 * Opcode implementation for Lotus
 * Migrated from bitcore-lib-xpi with ESM support
 */

import { Preconditions } from './util/preconditions.js'
import { JSUtil } from './util/js.js'

export interface OpcodeData {
  num: number
}

export class Opcode {
  readonly num!: number

  constructor(num: number | string) {
    if (typeof num === 'number') {
      JSUtil.defineImmutable(this, { num })
    } else if (typeof num === 'string') {
      const value = Opcode.map[num as keyof typeof Opcode.map]
      if (value === undefined) {
        throw new Error(`Unknown opcode: ${num}`)
      }
      JSUtil.defineImmutable(this, { num: value })
    } else {
      throw new TypeError(`Unrecognized num type: "${typeof num}" for Opcode`)
    }
  }

  static fromBuffer(buf: Buffer): Opcode {
    Preconditions.checkArgument(Buffer.isBuffer(buf), 'buf', 'Must be a Buffer')
    Preconditions.checkArgument(buf.length > 0, 'buf', 'Buffer cannot be empty')
    return new Opcode(buf[0])
  }

  toBuffer(): Buffer {
    return Buffer.from([this.num])
  }

  toString(): string {
    return this.num.toString()
  }

  // Opcode constants

  /** Push empty vector onto stack */
  static readonly OP_0 = 0
  /** Alias for OP_0 */
  static readonly OP_FALSE = 0
  /** Next byte contains number of bytes to push onto stack */
  static readonly OP_PUSHDATA1 = 76
  /** Next two bytes contain number of bytes to push onto stack */
  static readonly OP_PUSHDATA2 = 77
  /** Next four bytes contain number of bytes to push onto stack */
  static readonly OP_PUSHDATA4 = 78
  /** Push -1 onto stack */
  static readonly OP_1NEGATE = 79
  /** Reserved (invalid opcode) */
  static readonly OP_RESERVED = 80
  /** Push value 1 onto stack */
  static readonly OP_1 = 81
  /** Alias for OP_1 */
  static readonly OP_TRUE = 81
  /** Push value 2 onto stack */
  static readonly OP_2 = 82
  /** Push value 3 onto stack */
  static readonly OP_3 = 83
  /** Push value 4 onto stack */
  static readonly OP_4 = 84
  /** Push value 5 onto stack */
  static readonly OP_5 = 85
  /** Push value 6 onto stack */
  static readonly OP_6 = 86
  /** Push value 7 onto stack */
  static readonly OP_7 = 87
  /** Push value 8 onto stack */
  static readonly OP_8 = 88
  /** Push value 9 onto stack */
  static readonly OP_9 = 89
  /** Push value 10 onto stack */
  static readonly OP_10 = 90
  /** Push value 11 onto stack */
  static readonly OP_11 = 91
  /** Push value 12 onto stack */
  static readonly OP_12 = 92
  /** Push value 13 onto stack */
  static readonly OP_13 = 93
  /** Push value 14 onto stack */
  static readonly OP_14 = 94
  /** Push value 15 onto stack */
  static readonly OP_15 = 95
  /** Push value 16 onto stack */
  static readonly OP_16 = 96

  // Control

  /** Do nothing */
  static readonly OP_NOP = 97
  /** Marker for advanced script types (Lotus Taproot) */
  static readonly OP_SCRIPTTYPE = 98
  /** Version byte for scripts (deprecated in BCH/Lotus) */
  static readonly OP_VER = 98
  /** If next value is true, execute following statements */
  static readonly OP_IF = 99
  /** If next value is false, execute following statements */
  static readonly OP_NOTIF = 100
  /** Execute statements only if version byte is true (unassigned) */
  static readonly OP_VERIF = 101
  /** Execute statements only if version byte is false (unassigned) */
  static readonly OP_VERNOTIF = 102
  /** Else branch in conditional execution */
  static readonly OP_ELSE = 103
  /** End of conditional execution block */
  static readonly OP_ENDIF = 104
  /** Mark transaction invalid if top stack value is false */
  static readonly OP_VERIFY = 105
  /** Mark transaction as invalid/unspendable */
  static readonly OP_RETURN = 106

  // Stack ops

  /** Move top stack value to alt stack */
  static readonly OP_TOALTSTACK = 107
  /** Move top alt stack value to main stack */
  static readonly OP_FROMALTSTACK = 108
  /** Drop top two stack values */
  static readonly OP_2DROP = 109
  /** Duplicate top two stack values */
  static readonly OP_2DUP = 110
  /** Duplicate top three stack values */
  static readonly OP_3DUP = 111
  /** Copy 3rd and 4th values to top of stack */
  static readonly OP_2OVER = 112
  /** Move fifth and sixth values to top of stack */
  static readonly OP_2ROT = 113
  /** Swap top two pairs of values */
  static readonly OP_2SWAP = 114
  /** Duplicate if top of stack is not 0 */
  static readonly OP_IFDUP = 115
  /** Push stack depth onto stack */
  static readonly OP_DEPTH = 116
  /** Drop top value from stack */
  static readonly OP_DROP = 117
  /** Duplicate top stack value */
  static readonly OP_DUP = 118
  /** Remove second-to-top stack value */
  static readonly OP_NIP = 119
  /** Copy second-to-top value to top */
  static readonly OP_OVER = 120
  /** Copy stack value at index to top */
  static readonly OP_PICK = 121
  /** Move stack value at index to top */
  static readonly OP_ROLL = 122
  /** Rotate top three stack values */
  static readonly OP_ROT = 123
  /** Swap top two stack values */
  static readonly OP_SWAP = 124
  /** Duplicate second-to-top value to top */
  static readonly OP_TUCK = 125

  // Splice ops

  /** Concatenate two byte arrays */
  static readonly OP_CAT = 126
  /** Split byte array at position */
  static readonly OP_SPLIT = 127
  /** Convert number to binary with specific size */
  static readonly OP_NUM2BIN = 128
  /** Convert binary to number */
  static readonly OP_BIN2NUM = 129
  /** Push size of top item onto stack */
  static readonly OP_SIZE = 130

  // Bit logic

  /** Bitwise NOT */
  static readonly OP_INVERT = 131
  /** Bitwise AND */
  static readonly OP_AND = 132
  /** Bitwise OR */
  static readonly OP_OR = 133
  /** Bitwise XOR */
  static readonly OP_XOR = 134
  /** Test for equality */
  static readonly OP_EQUAL = 135
  /** Test for equality and verify */
  static readonly OP_EQUALVERIFY = 136
  /** Reserved (invalid opcode) */
  static readonly OP_RESERVED1 = 137
  /** Reserved (invalid opcode) */
  static readonly OP_RESERVED2 = 138

  // Numeric

  /** Add 1 to top value */
  static readonly OP_1ADD = 139
  /** Subtract 1 from top value */
  static readonly OP_1SUB = 140
  /** Multiply by 2 */
  static readonly OP_2MUL = 141
  /** Divide by 2 */
  static readonly OP_2DIV = 142
  /** Negate number */
  static readonly OP_NEGATE = 143
  /** Absolute value */
  static readonly OP_ABS = 144
  /** Boolean NOT */
  static readonly OP_NOT = 145
  /** Return 1 if top value is not 0, else 0 */
  static readonly OP_0NOTEQUAL = 146
  /** Add two top stack values */
  static readonly OP_ADD = 147
  /** Subtract two top stack values */
  static readonly OP_SUB = 148
  /** Multiply two top stack values */
  static readonly OP_MUL = 149
  /** Divide top value by next value */
  static readonly OP_DIV = 150
  /** Modulo (remainder) */
  static readonly OP_MOD = 151
  /** Left shift */
  static readonly OP_LSHIFT = 152
  /** Right shift */
  static readonly OP_RSHIFT = 153
  /** Boolean AND */
  static readonly OP_BOOLAND = 154
  /** Boolean OR */
  static readonly OP_BOOLOR = 155
  /** Numeric equality */
  static readonly OP_NUMEQUAL = 156
  /** Numeric equality and verify */
  static readonly OP_NUMEQUALVERIFY = 157
  /** Numeric inequality */
  static readonly OP_NUMNOTEQUAL = 158
  /** Less than */
  static readonly OP_LESSTHAN = 159
  /** Greater than */
  static readonly OP_GREATERTHAN = 160
  /** Less than or equal */
  static readonly OP_LESSTHANOREQUAL = 161
  /** Greater than or equal */
  static readonly OP_GREATERTHANOREQUAL = 162
  /** Minimum of two numbers */
  static readonly OP_MIN = 163
  /** Maximum of two numbers */
  static readonly OP_MAX = 164
  /** Check if a value is within a specified range */
  static readonly OP_WITHIN = 165

  // Crypto

  /** RIPEMD-160 hash */
  static readonly OP_RIPEMD160 = 166
  /** SHA-1 hash */
  static readonly OP_SHA1 = 167
  /** SHA-256 hash */
  static readonly OP_SHA256 = 168
  /** RIPEMD-160(SHA-256(x)) hash */
  static readonly OP_HASH160 = 169
  /** SHA-256(SHA-256(x)) hash */
  static readonly OP_HASH256 = 170
  /** Code separator for signature hashing */
  static readonly OP_CODESEPARATOR = 171
  /** Check ECDSA signature */
  static readonly OP_CHECKSIG = 172
  /** Check ECDSA signature and verify */
  static readonly OP_CHECKSIGVERIFY = 173
  /** Check multisignature (M-of-N) */
  static readonly OP_CHECKMULTISIG = 174
  /** Check multisignature (M-of-N) and verify */
  static readonly OP_CHECKMULTISIGVERIFY = 175

  // Expansion

  /** No operation (NOP) */
  static readonly OP_NOP1 = 176
  /** Check locktime and set spendable height */
  static readonly OP_CHECKLOCKTIMEVERIFY = 177
  /** Alias for OP_CHECKLOCKTIMEVERIFY (NOP2) */
  static readonly OP_NOP2 = 177
  /** Check relative locktime and set spendable sequence */
  static readonly OP_CHECKSEQUENCEVERIFY = 178
  /** Alias for OP_CHECKSEQUENCEVERIFY (NOP3) */
  static readonly OP_NOP3 = 178
  /** No operation (NOP4) */
  static readonly OP_NOP4 = 179
  /** No operation (NOP5) */
  static readonly OP_NOP5 = 180
  /** No operation (NOP6) */
  static readonly OP_NOP6 = 181
  /** No operation (NOP7) */
  static readonly OP_NOP7 = 182
  /** No operation (NOP8) */
  static readonly OP_NOP8 = 183
  /** No operation (NOP9) */
  static readonly OP_NOP9 = 184
  /** No operation (NOP10) */
  static readonly OP_NOP10 = 185

  // More crypto

  /** Check Schnorr or ECDSA signature against arbitrary message */
  static readonly OP_CHECKDATASIG = 186
  /** Check Schnorr or ECDSA signature against message and verify */
  static readonly OP_CHECKDATASIGVERIFY = 187
  /** Reverse bytes of top stack item */
  static readonly OP_REVERSEBYTES = 188
  // NOTE: When adding more op codes after OP_REVERSEBYTES, the lotus-lib AND lotusd
  // script interpreter classes MUST be updated to EXCLUDE the new op code from disabled
  // op code checks!

  // Opcode map for string lookup
  static readonly map = {
    OP_0: 0,
    OP_FALSE: 0,
    OP_PUSHDATA1: 76,
    OP_PUSHDATA2: 77,
    OP_PUSHDATA4: 78,
    OP_1NEGATE: 79,
    OP_RESERVED: 80,
    OP_1: 81,
    OP_TRUE: 81,
    OP_2: 82,
    OP_3: 83,
    OP_4: 84,
    OP_5: 85,
    OP_6: 86,
    OP_7: 87,
    OP_8: 88,
    OP_9: 89,
    OP_10: 90,
    OP_11: 91,
    OP_12: 92,
    OP_13: 93,
    OP_14: 94,
    OP_15: 95,
    OP_16: 96,
    OP_NOP: 97,
    OP_SCRIPTTYPE: 98,
    OP_IF: 99,
    OP_NOTIF: 100,
    OP_VERIF: 101,
    OP_VERNOTIF: 102,
    OP_ELSE: 103,
    OP_ENDIF: 104,
    OP_VERIFY: 105,
    OP_RETURN: 106,
    OP_TOALTSTACK: 107,
    OP_FROMALTSTACK: 108,
    OP_2DROP: 109,
    OP_2DUP: 110,
    OP_3DUP: 111,
    OP_2OVER: 112,
    OP_2ROT: 113,
    OP_2SWAP: 114,
    OP_IFDUP: 115,
    OP_DEPTH: 116,
    OP_DROP: 117,
    OP_DUP: 118,
    OP_NIP: 119,
    OP_OVER: 120,
    OP_PICK: 121,
    OP_ROLL: 122,
    OP_ROT: 123,
    OP_SWAP: 124,
    OP_TUCK: 125,
    OP_CAT: 126,
    OP_SPLIT: 127,
    OP_NUM2BIN: 128,
    OP_BIN2NUM: 129,
    OP_SIZE: 130,
    OP_INVERT: 131,
    OP_AND: 132,
    OP_OR: 133,
    OP_XOR: 134,
    OP_EQUAL: 135,
    OP_EQUALVERIFY: 136,
    OP_RESERVED1: 137,
    OP_RESERVED2: 138,
    OP_1ADD: 139,
    OP_1SUB: 140,
    OP_2MUL: 141,
    OP_2DIV: 142,
    OP_NEGATE: 143,
    OP_ABS: 144,
    OP_NOT: 145,
    OP_0NOTEQUAL: 146,
    OP_ADD: 147,
    OP_SUB: 148,
    OP_MUL: 149,
    OP_DIV: 150,
    OP_MOD: 151,
    OP_LSHIFT: 152,
    OP_RSHIFT: 153,
    OP_BOOLAND: 154,
    OP_BOOLOR: 155,
    OP_NUMEQUAL: 156,
    OP_NUMEQUALVERIFY: 157,
    OP_NUMNOTEQUAL: 158,
    OP_LESSTHAN: 159,
    OP_GREATERTHAN: 160,
    OP_LESSTHANOREQUAL: 161,
    OP_GREATERTHANOREQUAL: 162,
    OP_MIN: 163,
    OP_MAX: 164,
    OP_WITHIN: 165,
    OP_RIPEMD160: 166,
    OP_SHA1: 167,
    OP_SHA256: 168,
    OP_HASH160: 169,
    OP_HASH256: 170,
    OP_CODESEPARATOR: 171,
    OP_CHECKSIG: 172,
    OP_CHECKSIGVERIFY: 173,
    OP_CHECKMULTISIG: 174,
    OP_CHECKMULTISIGVERIFY: 175,
    OP_NOP1: 176,
    OP_CHECKLOCKTIMEVERIFY: 177,
    OP_NOP2: 177,
    OP_CHECKSEQUENCEVERIFY: 178,
    OP_NOP3: 178,
    OP_NOP4: 179,
    OP_NOP5: 180,
    OP_NOP6: 181,
    OP_NOP7: 182,
    OP_NOP8: 183,
    OP_NOP9: 184,
    OP_NOP10: 185,
    OP_CHECKDATASIG: 186,
    OP_CHECKDATASIGVERIFY: 187,
    OP_REVERSEBYTES: 188,
  } as const
}

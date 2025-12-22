/**
 * Opcode definitions
 * @see https://en.bitcoin.it/wiki/Script
 */
enum OpCode {
  OP_RETURN = 0x6a,
  OP_PUSHDATA1 = 0x4c,
  // RANK sentiments
  OP_0 = 0x00, // negative
  OP_1 = 0x51, // positive
  OP_2 = 0x52,
  OP_3 = 0x53,
  OP_4 = 0x54,
  OP_5 = 0x55,
  OP_6 = 0x56,
  OP_7 = 0x57,
  OP_8 = 0x58,
  OP_9 = 0x59,
  OP_10 = 0x5a,
  OP_11 = 0x5b,
  OP_12 = 0x5c,
  OP_13 = 0x5d,
  OP_14 = 0x5e,
  OP_15 = 0x5f,
  OP_16 = 0x60, // neutral
}

export default OpCode

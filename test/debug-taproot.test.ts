import { describe, it } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'buffer/'
import {
  PrivateKey,
  Script,
  Opcode,
  buildScriptPathTaproot,
  Hash,
  Networks,
  createControlBlock,
  TAPROOT_SIZE_WITH_STATE,
} from '../lib/bitcore/index.js'

describe('Debug Taproot State', () => {
  it('should debug script size', () => {
    const privateKey = new PrivateKey(undefined, Networks.regtest)
    const publicKey = privateKey.publicKey

    const state = Hash.sha256(Buffer.from('Test NFT Metadata', 'utf8'))
    console.log('State length:', state.length)

    const tapscript = new Script().add(Opcode.OP_1)
    console.log('Tapscript length:', tapscript.toBuffer().length)

    const tree = { script: tapscript }
    const result = buildScriptPathTaproot(publicKey, tree, state)

    const scriptBuf = result.script.toBuffer()
    console.log('Script buffer length:', scriptBuf.length)
    console.log('Expected:', TAPROOT_SIZE_WITH_STATE)
    console.log('Script hex:', scriptBuf.toString('hex'))

    // Check chunks
    console.log('Number of chunks:', result.script.chunks.length)
    result.script.chunks.forEach((chunk, i) => {
      console.log(
        `Chunk ${i}: opcodenum=${chunk.opcodenum}, buf length=${chunk.buf?.length || 0}`,
      )
    })

    assert.strictEqual(scriptBuf.length, TAPROOT_SIZE_WITH_STATE)
  })
})

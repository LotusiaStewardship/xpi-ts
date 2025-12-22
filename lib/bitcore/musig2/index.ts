/**
 * Copyright 2025 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 */

/**
 * MuSig2 High-Level API
 *
 * This module provides simplified, developer-friendly wrappers for common
 * MuSig2 operations, making it easier for new developers to implement
 * multi-signature functionality.
 *
 * @module MuSig2
 */

export {
  MuSig2Signer,
  createMuSig2Signer,
  type MuSig2SignerConfig,
  type MuSig2PrepareResult,
  type MuSig2SignResult,
  type MuSig2TaprootSignResult,
} from './signer.js'

export {
  MuSigSessionManager,
  MuSigSessionPhase,
  type MuSigSession,
} from './session.js'

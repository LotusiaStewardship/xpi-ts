# Coinbase Parsing Implementation Status

## Overview

Implementation of coinbase transaction parsing to extract miner/pool identification data from coinbase transactions.

## Timeline

| Phase                         | Status      | Start Date | End Date   |
| ----------------------------- | ----------- | ---------- | ---------- |
| Phase 1 — Core Implementation | ✅ Complete | 2026-05-04 | 2026-05-04 |
| Phase 2 — Tests and Examples  | ⚪ Pending  | —          | —          |

## Phase Status

### Phase 1 — Core Implementation

**Status:** ✅ Complete

**Deliverables:**

- [x] `CoinbaseScriptSigData` interface
- [x] `CoinbaseData` interface
- [x] `getCoinbaseData()` method
- [x] `_parseCoinbaseScriptSig()` helper
- [x] `_tryDecodeString()` helper
- [x] `_identifyPoolTag()` helper
- [x] `_parseCoinbaseHeight()` helper
- [x] Type exports in `lib/bitcore/transaction/index.ts`
- [x] Type exports in `lib/bitcore/index.ts`

**Exit Criteria:**

- [x] Code compiles without errors
- [x] Existing tests pass
- [x] ESLint/Prettier pass
- [x] All imports use `.js` extensions (ESM compatibility)

### Phase 2 — Tests and Examples

**Status:** ⚪ Pending

**Deliverables:**

- [ ] Unit tests (`test/transaction/coinbase.test.ts`)
- [ ] Usage examples (`examples/coinbase-example.ts`)
- [ ] Test fixtures (`test/fixtures/coinbase-fixtures.json`)

**Exit Criteria:**

- [ ] All unit tests pass
- [ ] Example runs without errors
- [ ] Test coverage includes edge cases

## Technical Decisions

### Decision 1: Use Existing Script Parser

**Context:** Coinbase scriptSig must be parsed as Bitcoin script opcodes.

**Decision:** Use existing `Script.fromBuffer()` rather than re-implementing opcode parsing.

**Rationale:**

- Existing implementation is well-tested
- Handles all opcode variants (OP_0, direct push, OP_PUSHDATA1/2/4)
- Consistent with rest of codebase

### Decision 2: UTF-8 Support for Pool Names

**Context:** Modern pools embed UTF-8 strings including emoji (e.g., "Lotusia Pool 🪷").

**Decision:** Decode pushed data as UTF-8 with fallback to null for non-printable data.

**Rationale:**

- Required for real-world pool identification
- Graceful degradation for binary data

### Decision 3: Reuse Existing ScriptNum Class

**Context:** lotusd encodes extra nonce as `CScriptNum`.

**Decision:** Use existing `ScriptNum.fromBuffer()` class rather than re-implementing.

**Rationale:**

- Codebase already has well-tested `ScriptNum` class
- Matches `lotusd/src/script/script.h` encoding
- Reduces code duplication and maintenance burden

## Known Issues

None yet.

## Open Questions

1. **Should we maintain a pool identification database?**
   - Out of scope for this implementation
   - Could be added as separate utility module

2. **Should we parse stratum extranonce structure?**
   - Requires knowledge of pool-specific extranonce sizes
   - Out of scope; can be added if needed

## References

- `docs/plans/coinbase-parsing/OVERVIEW.md`
- `docs/plans/coinbase-parsing/PHASE-1-IMPLEMENTATION.md`
- `docs/plans/coinbase-parsing/PHASE-2-TESTS.md`
- `lotusd/src/miner.cpp` — Coinbase construction
- `lotusd/src/consensus/consensus.h` — `COINBASE_PREFIX`
- `lotusd/src/script/script.h` — `CScriptNum` encoding

## Change Log

| Date       | Change                          | Author |
| ---------- | ------------------------------- | ------ |
| 2026-05-04 | Phase 1 implementation complete | —      |
| 2026-05-04 | Initial plan created            | —      |

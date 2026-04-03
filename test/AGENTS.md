# AGENTS.md — Test Directory

Guidelines for writing and maintaining tests in the xpi-ts test suite.

---

## Test Framework

- **Runner**: Node.js native test runner (`node:test`)
- **Assertions**: `node:assert` (strict mode)
- **No Jest**: This project migrated from Jest to Node.js native test runner

---

## File Conventions

- **Naming**: `*.test.ts`
- **Location**: Mirror `lib/` structure when possible
  - `lib/bitcore/crypto/` → `test/crypto/`
  - `lib/bitcore/script/` → `test/script/`
  - `lib/bitcore/block/` → `test/block/`
- **Top-level tests**: For cross-cutting concerns (e.g., `hdprivatekey.test.ts`, `taproot-script-path-state.test.ts`)

---

## Test Structure

```typescript
import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert'
import { Buffer } from 'buffer/'
import { SomeModule } from '../lib/bitcore/index.js'

describe('ModuleName', () => {
  describe('methodName', () => {
    it('should do something specific', () => {
      // Arrange
      const input = ...

      // Act
      const result = SomeModule.method(input)

      // Assert
      assert.strictEqual(result, expected)
    })
  })
})
```

---

## Import Patterns

```typescript
// Always import Buffer from 'buffer/'
import { Buffer } from 'buffer/'

// Import from the barrel export when testing public API
import { PrivateKey, PublicKey, Script } from '../lib/bitcore/index.js'

// Import directly from source file when testing internal modules
import { muSig2KeyAgg } from '../../lib/bitcore/crypto/musig2.js'

// Use relative paths with .js extension (ESM modules)
```

---

## Assertion Guidelines

| Use Case                       | Method                                       |
| ------------------------------ | -------------------------------------------- |
| Equality                       | `assert.strictEqual(actual, expected)`       |
| Deep equality (objects/arrays) | `assert.deepStrictEqual(actual, expected)`   |
| Truthy                         | `assert.ok(value)`                           |
| Falsy                          | `assert.ok(!value)`                          |
| TypeError/throws               | `assert.throws(() => fn(), /error pattern/)` |
| Buffer equality                | `assert.ok(buf1.equals(buf2))`               |
| Type check                     | `assert.ok(value instanceof SomeClass)`      |

---

## Running Tests

```bash
# All tests
npm test

# Single test file
npx tsx --test test/crypto/musig2.test.ts

# Single test file with Node test runner
node --import tsx test/crypto/musig2.test.ts

# Watch mode
npm run test:watch

# Coverage
npm run test:coverage
```

---

## Writing New Tests

1. **Happy path first**: Test normal usage before edge cases
2. **Error cases**: Test invalid inputs, boundary conditions, error throwing
3. **Edge cases**: Empty arrays, zero values, maximum sizes
4. **Roundtrip tests**: Serialize → deserialize should preserve data
5. **Cross-reference lotusd**: When possible, reference `lotusd/src/test/` for test vectors

---

## Test Data

- Use real block/transaction hex data from the Lotus blockchain when available
- Reference block height in comments (e.g., "block 1000000")
- For cryptographic tests, use deterministic seeds or known test vectors
- Mark console.log usage clearly — these are for debugging, not assertions

---

## Common Patterns

### Setup with beforeEach

```typescript
describe('Module', () => {
  let privateKey: PrivateKey
  let publicKey: PublicKey

  beforeEach(() => {
    privateKey = new PrivateKey(undefined, Networks.regtest)
    publicKey = privateKey.publicKey
  })

  it('should use the keys', () => {
    // test code
  })
})
```

### Helper Functions

Define helpers at the top of the file, below imports:

```typescript
// ─── Test Helpers ────────────────────────────────────────────────

function makeMetrics(): ScriptExecutionMetrics {
  return { sigChecks: 0 }
}
```

### File Header

```typescript
/**
 * Module Name Unit Tests
 *
 * Tests for X covering:
 * - Feature A
 * - Feature B
 * - Edge cases
 *
 * Reference: lotusd/src/path/to/reference.cpp
 */
```

---

## What NOT to Do

- Do not use `console.log` for assertions — use `assert` methods
- Do not skip tests with `.skip` without a TODO comment explaining why
- Do not use `any` type — use proper TypeScript types
- Do not mock cryptographic primitives — use real implementations
- Do not commit test files that only contain debugging output (see `debug-taproot.test.ts` as an exception that should eventually be removed)

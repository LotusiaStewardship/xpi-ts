// @ts-check

import eslintJs from '@eslint/js'
import tseslint, { configs as tseslintConfigs } from 'typescript-eslint'

export default tseslint.config(
  {
    ignores: [
      'node_modules/**',
      'dist/**',
      'coverage/**',
      '**/*.d.ts',
      '**/*.js',
    ],
  },
  eslintJs.configs.recommended,
  ...tseslintConfigs.recommended,
  {
    languageOptions: {
      globals: {
        Buffer: 'readonly',
        process: 'readonly',
        global: 'readonly',
      },
    },
  },
  {
    rules: {
      '@typescript-eslint/no-unused-vars': 'off',
      'no-empty': 'warn',
    },
  },
  {
    // Test fixtures construct partial and bitcore-shaped objects on purpose.
    files: ['test/**'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  {
    // Legacy bitcore-compatible modules use `any`, `Function` and `arguments`
    // to mirror the upstream API. Tightening them is a separate refactor.
    files: [
      'lib/bitcore/errors.ts',
      'lib/bitcore/crypto/point.ts',
      'lib/bitcore/script/interpreter/interpreter.ts',
      'lib/bitcore/util/buffer.ts',
    ],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-function-type': 'off',
      'prefer-rest-params': 'off',
    },
  },
)

// @ts-check

import { configs as eslintConfigs } from '@eslint/js'
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
  eslintConfigs.recommended,
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
)

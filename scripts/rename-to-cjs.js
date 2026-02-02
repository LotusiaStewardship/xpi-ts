/**
 * Copyright 2026 The Lotusia Stewardship
 * Github: https://github.com/LotusiaStewardship
 * License: MIT
 *
 * Script to rename .js files to .cjs in the CommonJS build directory
 * This is necessary because the package has "type": "module" but we need
 * CommonJS output for compatibility with CommonJS consumers.
 */

import { readdir, rename } from 'fs/promises'
import { join, extname } from 'path'

async function* walkDir(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  for (const entry of entries) {
    const fullPath = join(dir, entry.name)
    if (entry.isDirectory()) {
      yield* walkDir(fullPath)
    } else {
      yield fullPath
    }
  }
}

async function renameJsToCjs(dir) {
  console.log(`Renaming .js files to .cjs in ${dir}...`)

  for await (const filePath of walkDir(dir)) {
    if (extname(filePath) === '.js') {
      const newPath = filePath.replace(/\.js$/, '.cjs')
      await rename(filePath, newPath)
      console.log(`  Renamed: ${filePath} -> ${newPath}`)
    }
  }

  console.log('Done!')
}

const cjsDir = './dist/cjs'
renameJsToCjs(cjsDir).catch(err => {
  console.error('Error:', err)
  process.exit(1)
})

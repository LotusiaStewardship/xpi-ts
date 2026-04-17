const { series, parallel, watch } = require('gulp')
const { spawn } = require('node:child_process')
const { access, mkdir, readFile, rm, writeFile } = require('node:fs/promises')
const path = require('node:path')

const DIST_DIR = 'dist'
const ESM_DIR = path.join(DIST_DIR, 'esm')
const CJS_DIR = path.join(DIST_DIR, 'cjs')
const TYPES_DIR = path.join(DIST_DIR, 'types')

const SOURCE_GLOBS = ['index.ts', 'lib/**/*.ts', 'utils/**/*.ts', 'types/**/*.d.ts']

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: 'inherit',
      shell: process.platform === 'win32',
      ...options,
    })

    child.on('error', reject)
    child.on('close', code => {
      if (code === 0) {
        resolve()
        return
      }
      reject(
        new Error(
          `${command} ${args.join(' ')} exited with non-zero status ${code}`,
        ),
      )
    })
  })
}

async function clean() {
  await rm(DIST_DIR, { recursive: true, force: true })
}

function buildTypes() {
  return run('npx', ['tsc', '-p', 'tsconfig.types.json'])
}


function transpileEsm() {
  return run('npx', ['tsc', '--outDir', ESM_DIR])
}

async function writeEsmPackageJson() {
  await mkdir(ESM_DIR, { recursive: true })
  await writeFile(
    path.join(ESM_DIR, 'package.json'),
    `${JSON.stringify({ type: 'module' }, null, 2)}\n`,
  )
}

const buildEsm = series(transpileEsm, writeEsmPackageJson)

function buildCjs() {
  return run('npx', ['tsc', '-p', 'tsconfig.cjs.json'])
}

async function validateOutputFiles(paths) {
  await Promise.all(
    paths.map(async outputPath => {
      await access(outputPath)
    }),
  )
}

async function validateExports() {
  const pkgRaw = await readFile(path.resolve('package.json'), 'utf8')
  const pkg = JSON.parse(pkgRaw)

  const required = [pkg.main, pkg.module, pkg.types]

  for (const target of required) {
    await access(target)
  }

  const exportEntries = Object.values(pkg.exports ?? {})
  const exportChecks = []

  for (const entry of exportEntries) {
    if (!entry || typeof entry !== 'object') {
      continue
    }

    for (const field of ['types', 'import', 'require']) {
      const candidate = entry[field]
      if (typeof candidate !== 'string') {
        continue
      }

      if (candidate.includes('*')) {
        const baseDir = path.dirname(candidate.split('*')[0])
        exportChecks.push(access(baseDir))
      } else {
        exportChecks.push(access(candidate))
      }
    }
  }

  await Promise.all(exportChecks)
}

async function validate() {
  await validateOutputFiles([
    path.join(ESM_DIR, 'index.js'),
    path.join(ESM_DIR, 'package.json'),
    path.join(CJS_DIR, 'index.js'),
    path.join(TYPES_DIR, 'index.d.ts'),
  ])

  await validateExports()
}

const build = series(clean, parallel(buildTypes, buildEsm, buildCjs), validate)

function buildWatch() {
  return watch(
    SOURCE_GLOBS,
    { ignoreInitial: false },
    series(buildTypes, buildEsm, buildCjs),
  )
}

exports.clean = clean
exports['build:types'] = buildTypes
exports['build:esm'] = buildEsm
exports['build:cjs'] = buildCjs
exports.validate = validate
exports.build = build
exports.watch = buildWatch
exports.default = build


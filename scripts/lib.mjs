/**
 * Shared helpers for the AI-NIDS dev tooling.
 *
 * Deliberately dependency-free: only Node's standard library is used, so the
 * repository needs nothing installed before `npm run dev` can bootstrap itself.
 */

import { spawn, spawnSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url))
export const ROOT = path.resolve(SCRIPT_DIR, '..')
export const BACKEND_DIR = path.join(ROOT, 'backend')
export const FRONTEND_DIR = path.join(ROOT, 'frontend')
export const VENV_DIR = path.join(ROOT, '.venv')
export const MODEL_FILE = path.join(BACKEND_DIR, 'app', 'ml', 'random_forest_model.joblib')

export const IS_WINDOWS = process.platform === 'win32'
export const NPM = IS_WINDOWS ? 'npm.cmd' : 'npm'

// --------------------------------------------------------------------------- #
// pretty console output
// --------------------------------------------------------------------------- #
const COLOR = {
  reset: '\u001b[0m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
  red: '\u001b[31m',
  green: '\u001b[32m',
  yellow: '\u001b[33m',
  blue: '\u001b[34m',
  magenta: '\u001b[35m',
  cyan: '\u001b[36m',
}

export const paint = Object.fromEntries(
  Object.entries(COLOR).map(([name, code]) => [name, (text) => `${code}${text}${COLOR.reset}`]),
)

export const log = {
  step: (text) => console.log(`${paint.cyan('▸')} ${text}`),
  ok: (text) => console.log(`${paint.green('✓')} ${text}`),
  warn: (text) => console.log(`${paint.yellow('!')} ${text}`),
  error: (text) => console.log(`${paint.red('✗')} ${text}`),
  info: (text) => console.log(`${paint.dim(text)}`),
  blank: () => console.log(''),
}

export function banner(title, lines = []) {
  const width = Math.max(title.length + 4, ...lines.map((l) => l.length + 4), 54)
  console.log(paint.cyan(`╭${'─'.repeat(width)}╮`))
  console.log(paint.cyan('│ ') + paint.bold(title.padEnd(width - 3)) + paint.cyan('│'))
  for (const line of lines) console.log(paint.cyan('│ ') + line.padEnd(width - 3) + paint.cyan('│'))
  console.log(paint.cyan(`╰${'─'.repeat(width)}╯`))
}

/** Prefix every line of a child process' output so two servers stay readable. */
export function prefixStream(stream, label, color) {
  let buffer = ''
  stream.setEncoding('utf8')
  stream.on('data', (chunk) => {
    buffer += chunk
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      const trimmed = line.replace(/\s+$/, '')
      if (trimmed.length === 0) continue
      console.log(`${paint[color](`[${label}]`)} ${trimmed}`)
    }
  })
  return () => {
    if (buffer.trim().length > 0) console.log(`${paint[color](`[${label}]`)} ${buffer.trim()}`)
  }
}

// --------------------------------------------------------------------------- #
// process helpers
// --------------------------------------------------------------------------- #
export function run(command, args, options = {}) {
  const shell = IS_WINDOWS && command.toLowerCase().endsWith('.cmd')
  return spawnSync(command, args, { stdio: 'inherit', cwd: ROOT, shell, ...options })
}

export function runQuiet(command, args, options = {}) {
  return spawnSync(command, args, { encoding: 'utf8', cwd: ROOT, ...options })
}

export function spawnStreaming(command, args, { cwd, label, color, env } = {}) {
  const shell = IS_WINDOWS && command.toLowerCase().endsWith('.cmd')
  const child = spawn(command, args, {
    cwd,
    env: { ...process.env, ...(env ?? {}) },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    shell,
  })
  const flushOut = prefixStream(child.stdout, label, color)
  const flushErr = prefixStream(child.stderr, label, color)
  child.on('exit', (code, signal) => {
    flushOut()
    flushErr()
    if (signal !== 'SIGTERM' && signal !== 'SIGINT') {
      log.warn(`${label} exited (${signal ?? `code ${code}`})`)
    }
  })
  return child
}

export function isPortOpen(port, host = '127.0.0.1', timeout = 700) {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    const done = (result) => {
      socket.destroy()
      resolve(result)
    }
    socket.setTimeout(timeout)
    socket.once('connect', () => done(true))
    socket.once('timeout', () => done(false))
    socket.once('error', () => done(false))
    socket.connect(port, host)
  })
}

export async function waitForHttp(url, { timeoutMs = 90_000, intervalMs = 700 } = {}) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2500) })
      if (response.ok) return true
    } catch {
      /* not up yet */
    }
    await sleep(intervalMs)
  }
  return false
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

// --------------------------------------------------------------------------- #
// Python discovery + dependency bootstrap
// --------------------------------------------------------------------------- #
/** Modules the API cannot start without. */
const REQUIRED_MODULES = ['fastapi', 'uvicorn', 'sqlalchemy', 'jwt', 'bcrypt', 'sklearn', 'pandas', 'numpy', 'joblib']

function pythonCandidates() {
  const venvPython = IS_WINDOWS
    ? path.join(VENV_DIR, 'Scripts', 'python.exe')
    : path.join(VENV_DIR, 'bin', 'python')
  return [
    process.env.AINIDS_PYTHON,
    venvPython,
    IS_WINDOWS ? 'py' : null,
    'python3',
    'python',
  ].filter(Boolean)
}

function pythonWorks(command) {
  const result = runQuiet(command, ['-c', 'import sys; print(sys.version_info[:2])'])
  return result.status === 0
}

export function findPython() {
  for (const candidate of pythonCandidates()) {
    if (candidate.includes(path.sep) && !existsSync(candidate)) continue
    if (pythonWorks(candidate)) return candidate
  }
  return null
}

export function missingPythonModules(python) {
  const check = `import importlib.util as u, sys; sys.exit(0 if all(u.find_spec(m) for m in ${JSON.stringify(REQUIRED_MODULES)}) else 1)`
  return runQuiet(python, ['-c', check]).status !== 0
}

export function createVenv(python) {
  log.step('creating a project virtual environment (.venv)…')
  return run(python, ['-m', 'venv', VENV_DIR]).status === 0
}

export function pipInstall(python) {
  log.step('installing Python dependencies (first run only, ~1 minute)…')
  const upgraded = run(python, ['-m', 'pip', 'install', '--upgrade', 'pip', '--quiet'])
  if (upgraded.status !== 0) log.warn('could not upgrade pip, continuing anyway')
  return run(python, ['-m', 'pip', 'install', '-r', path.join('backend', 'requirements.txt')]).status === 0
}

/**
 * Make sure a Python interpreter with the backend dependencies exists.
 * Returns { python, installed } or throws with an actionable message.
 */
export function ensurePython() {
  let python = findPython()
  if (!python) {
    throw new Error(
      'Python 3.10+ was not found on your PATH.\n' +
        '  Install it from https://www.python.org/downloads/ (tick "Add python.exe to PATH"), then run npm run dev again.',
    )
  }

  if (!missingPythonModules(python)) return { python, installed: false }

  const inVenv = python.startsWith(VENV_DIR)
  if (!inVenv) {
    // Prefer an isolated environment: system Pythons are often "externally managed".
    if (createVenv(python) && pythonWorks(venvPythonPath())) python = venvPythonPath()
    else log.warn('could not create a virtual environment, installing into the current interpreter')
  }

  if (pipInstall(python) && !missingPythonModules(python)) return { python, installed: true }

  throw new Error(
    'Could not install the backend dependencies automatically.\n' +
      '  Run this once by hand and then retry npm run dev:\n' +
      `    ${python} -m pip install -r backend/requirements.txt`,
  )
}

function venvPythonPath() {
  return IS_WINDOWS ? path.join(VENV_DIR, 'Scripts', 'python.exe') : path.join(VENV_DIR, 'bin', 'python')
}

// --------------------------------------------------------------------------- #
// Node / frontend bootstrap, env file
// --------------------------------------------------------------------------- #
export function frontendDepsMissing() {
  return !existsSync(path.join(FRONTEND_DIR, 'node_modules', 'vite')) || !existsSync(path.join(FRONTEND_DIR, 'node_modules', 'react'))
}

export function installFrontendDeps({ quiet = false } = {}) {
  log.step('installing frontend dependencies (first run only)…')
  return run(NPM, ['install', '--no-fund', '--no-audit'], { cwd: FRONTEND_DIR, stdio: quiet ? 'ignore' : 'inherit' }).status === 0
}

export function ensureFrontendDeps() {
  if (!frontendDepsMissing()) return false
  if (!installFrontendDeps()) throw new Error('npm install failed in frontend/. Run it manually and retry.')
  return true
}

/** Create .env from .env.example, with a freshly generated JWT secret. */
export function ensureEnvFile() {
  const envPath = path.join(ROOT, '.env')
  const examplePath = path.join(ROOT, '.env.example')
  if (existsSync(envPath)) return { created: false, envPath }
  if (!existsSync(examplePath)) return { created: false, envPath: null }

  copyFileSync(examplePath, envPath)
  let contents = readFileSync(envPath, 'utf8')
  const secret = randomSecret()
  contents = contents.replace(/^JWT_SECRET=.*$/m, `JWT_SECRET=${secret}`)
  writeFileSync(envPath, contents)
  return { created: true, envPath }
}

export function randomSecret() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  const bytes = new Uint8Array(56)
  globalThis.crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

export function modelArtifactsReady() {
  return existsSync(MODEL_FILE)
}

export function nodeVersionOk() {
  const major = Number(process.versions.node.split('.')[0])
  return major >= 18
}

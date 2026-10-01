#!/usr/bin/env node
/**
 * AI-NIDS one-command development launcher.
 *
 *   npm run dev            # from the repository root
 *   npm run dev            # from frontend/ as well (it finds the root itself)
 *
 * What it does, in order — and everything it installs, it installs once:
 *   1. verifies Node/Python are present,
 *   2. creates .env from .env.example with a generated JWT secret (first run),
 *   3. installs backend Python dependencies into .venv (first run),
 *   4. installs frontend npm dependencies (first run),
 *   5. starts the FastAPI backend and the Vite dev server side by side,
 *      prefixing every log line with [api] / [web],
 *   6. waits until both answer, prints the URLs + demo credentials, and shuts
 *      both down cleanly on Ctrl+C.
 *
 * Already-running services are reused instead of started twice, so running
 * `npm run dev` again in a second terminal is harmless.
 */

import { existsSync } from 'node:fs'
import path from 'node:path'
import {
  BACKEND_DIR,
  FRONTEND_DIR,
  NPM,
  ROOT,
  banner,
  ensureEnvFile,
  ensureFrontendDeps,
  ensurePython,
  isPortOpen,
  log,
  modelArtifactsReady,
  nodeVersionOk,
  paint,
  sleep,
  spawnStreaming,
  waitForHttp,
} from './lib.mjs'

const API_PORT = Number(process.env.AINIDS_API_PORT || 8000)
const WEB_PORT = Number(process.env.AINIDS_WEB_PORT || 5173)
const API_URL = `http://localhost:${API_PORT}`
const WEB_URL = `http://localhost:${WEB_PORT}`

const children = []
let shuttingDown = false

function shutdown(code = 0) {
  if (shuttingDown) return
  shuttingDown = true
  log.blank()
  log.step('shutting down…')
  for (const child of children) {
    try {
      child.kill('SIGTERM')
    } catch {
      /* already gone */
    }
  }
  setTimeout(() => {
    for (const child of children) {
      try {
        child.kill('SIGKILL')
      } catch {
        /* already gone */
      }
    }
    process.exit(code)
  }, 700)
}

async function main() {
  banner('AI-NIDS — starting the whole project', [
    `root       ${ROOT}`,
    'backend    FastAPI + Random Forest (loads the trained model)',
    'frontend   React + TypeScript dashboard',
  ])
  log.blank()

  if (!nodeVersionOk()) {
    log.error(`Node 18+ is required (found ${process.versions.node}). Please upgrade Node and retry.`)
    process.exit(1)
  }

  // 1 — configuration ------------------------------------------------------- #
  const env = ensureEnvFile()
  if (env.created) log.ok(`created .env with a freshly generated JWT secret (${path.relative(ROOT, env.envPath)})`)
  else log.ok('.env found')

  // 2 — dependencies -------------------------------------------------------- #
  const { python } = ensurePython()
  log.ok(`Python ready (${python.replace(ROOT + path.sep, '')})`)

  ensureFrontendDeps()
  log.ok('frontend dependencies ready')

  if (!modelArtifactsReady()) {
    log.warn('trained model artifacts are missing — the API will refuse to start.')
    log.warn('run:  npm run train     (then npm run dev again)')
    process.exit(1)
  }
  log.ok('trained Random Forest artifacts found')

  // 3 — services ------------------------------------------------------------ #
  const apiRunning = await isPortOpen(API_PORT)
  if (apiRunning) {
    log.warn(`port ${API_PORT} is already in use — reusing the running backend`)
  } else {
    log.step('starting the API…')
    children.push(
      spawnStreaming(python, ['-m', 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', String(API_PORT)], {
        cwd: BACKEND_DIR,
        label: 'api',
        color: 'cyan',
      }),
    )
  }

  // Give the API a head start so the UI's first request does not 502 through the proxy.
  if (!apiRunning) {
    const healthy = await waitForHttp(`${API_URL}/api/health`, { timeoutMs: 60_000 })
    if (healthy) log.ok(`API ready on ${API_URL}`)
    else log.warn(`API did not report healthy within 60s — check the [api] log lines above`)
  }

  const webRunning = await isPortOpen(WEB_PORT)
  if (webRunning) {
    log.warn(`port ${WEB_PORT} is already in use — reusing the running dev server`)
  } else {
    log.step('starting the dashboard…')
    children.push(
      spawnStreaming(NPM, ['run', 'dev:vite', '--', '--port', String(WEB_PORT)], {
        cwd: FRONTEND_DIR,
        label: 'web',
        color: 'magenta',
      }),
    )
    await waitForHttp(WEB_URL, { timeoutMs: 45_000 }).catch(() => false)
  }

  const apiOpen = await isPortOpen(API_PORT)
  const webOpen = await isPortOpen(WEB_PORT)

  log.blank()
  banner('AI-NIDS is running', [
    `dashboard   ${WEB_URL}`,
    `API docs    ${API_URL}/docs`,
    `health      ${API_URL}/api/health`,
    '',
    'sign in     analyst@ainids.dev / Analyst@123',
    '            admin@ainids.dev   / Admin@1234',
    '',
    'Ctrl+C stops both servers.',
  ])
  if (!apiOpen) log.warn('the API port is not answering — see the [api] log lines above')
  if (!webOpen) log.warn('the dashboard port is not answering — see the [web] log lines above')
  log.blank()
}

process.on('SIGINT', () => shutdown(0))
process.on('SIGTERM', () => shutdown(0))
process.on('uncaughtException', (error) => {
  log.error(error instanceof Error ? error.message : String(error))
  shutdown(1)
})
process.on('unhandledRejection', (error) => {
  log.error(error instanceof Error ? error.message : String(error))
  shutdown(1)
})

main().catch((error) => {
  log.blank()
  log.error(error instanceof Error ? error.message : String(error))
  log.blank()
  shutdown(1)
})

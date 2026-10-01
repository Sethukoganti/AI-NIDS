#!/usr/bin/env node
/**
 * AI-NIDS setup — everything needed before `npm run dev`:
 *   npm run setup      (also runs automatically as the root postinstall hook)
 *
 * Safe to run repeatedly: each step is skipped when it is already satisfied.
 */

import path from 'node:path'
import {
  ROOT,
  banner,
  ensureEnvFile,
  ensureFrontendDeps,
  ensurePython,
  log,
  modelArtifactsReady,
  nodeVersionOk,
  spawnStreaming,
} from './lib.mjs'

async function main() {
  banner('AI-NIDS — one-time setup', [
    'checks Node, Python and the trained model artifacts,',
    'installs whatever is missing, then you only need: npm run dev',
  ])
  log.blank()

  if (!nodeVersionOk()) {
    log.error(`Node 18+ is required (found ${process.versions.node}).`)
    process.exit(1)
  }
  log.ok(`Node ${process.versions.node}`)

  const env = ensureEnvFile()
  log.ok(env.created ? 'created .env (generated JWT secret)' : '.env already present')

  const { python } = ensurePython()
  log.ok(`Python dependencies ready (${python.replace(ROOT + path.sep, '')})`)

  ensureFrontendDeps()
  log.ok('frontend dependencies ready')

  if (modelArtifactsReady()) {
    log.ok('trained model artifacts present')
  } else {
    log.warn('model artifacts are missing — training now (takes about a minute)')
    const status = await new Promise((resolve) => {
      const child = spawnStreaming(python, ['ml/train_model.py'], { cwd: ROOT, label: 'train', color: 'yellow' })
      child.on('exit', (code) => resolve(code ?? 1))
    })
    if (status === 0 && modelArtifactsReady()) log.ok('model trained and exported')
    else {
      log.error('training did not complete. Run "npm run train" and watch the output.')
      process.exit(1)
    }
  }

  log.blank()
  banner('Setup complete', ['run:  npm run dev', 'then open the dashboard URL it prints'])
  log.blank()
}

main().catch((error) => {
  log.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
})

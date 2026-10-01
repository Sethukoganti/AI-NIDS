#!/usr/bin/env node
/** Runs both test suites: backend (pytest) and frontend (vitest). */
import path from 'node:path'
import { BACKEND_DIR, FRONTEND_DIR, NPM, ROOT, banner, ensurePython, findPython, log } from './lib.mjs'
import { spawnSync } from 'node:child_process'

const run = (cmd, args, cwd) => spawnSync(cmd, args, { cwd, stdio: 'inherit' }).status ?? 1

banner('AI-NIDS — test suites', ['backend  pytest      (API + ML contract)', 'frontend vitest      (client + pages)'])
log.blank()

const python = findPython()
log.step('backend tests…')
const backend = python ? run(python, ['-m', 'pytest'], path.join(ROOT, 'backend')) : 1
if (!python) log.error('no Python interpreter found')

log.blank()
log.step('frontend tests…')
const frontend = run(NPM, ['run', 'test'], FRONTEND_DIR)

log.blank()
if (backend === 0 && frontend === 0) log.ok('all suites passed')
else log.error(`failures — backend: ${backend === 0 ? 'pass' : 'fail'}, frontend: ${frontend === 0 ? 'pass' : 'fail'}`)
process.exit(backend === 0 && frontend === 0 ? 0 : 1)

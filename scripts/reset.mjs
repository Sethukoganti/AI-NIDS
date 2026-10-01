#!/usr/bin/env node
/**
 * Wipes the local development database and uploads, so the next `npm run dev`
 * re-seeds the demo accounts, the sample dataset and the bootstrap analysis.
 */
import { existsSync, rmSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { ROOT, log } from './lib.mjs'

const dbFiles = ['ainids.db', 'ainids.db-wal', 'ainids.db-shm']
let removed = 0
for (const name of dbFiles) {
  const file = path.join(ROOT, 'data', name)
  if (existsSync(file)) { rmSync(file); removed += 1 }
}

const uploads = path.join(ROOT, 'data', 'uploads')
if (existsSync(uploads)) {
  for (const entry of readdirSync(uploads)) rmSync(path.join(uploads, entry), { recursive: true, force: true })
}

log.ok(`removed ${removed} database file(s) and cleared data/uploads`)
log.info('restart the app (Ctrl+C, then npm run dev) to re-seed the demo data')

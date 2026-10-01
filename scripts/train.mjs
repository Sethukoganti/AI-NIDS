#!/usr/bin/env node
/** Trains / refreshes the Random Forest artifacts, then copies them into the API. */
import { ROOT, banner, ensurePython, log } from './lib.mjs'
import { spawnSync } from 'node:child_process'

banner('AI-NIDS — model training', [
  'rebuilds ml/artifacts/* and backend/app/ml/* from the cleaned CICIDS2017 table',
  'you only need this if you want to regenerate the model',
])
log.blank()
const { python } = ensurePython()
const code = spawnSync(python, ['ml/train_model.py', ...process.argv.slice(2)], { cwd: ROOT, stdio: 'inherit' }).status ?? 1
process.exit(code)

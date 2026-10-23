#!/usr/bin/env node
// The compiled command line. `npm run build` makes dist/ (npm runs it on install from git).
import { main } from '../dist/cli.js'

process.exitCode = await main(process.argv.slice(2))

#!/usr/bin/env node

/**
 * bolt11-cli – Decode & validate BOLT11 Lightning payment invoices.
 *
 * This file is the CLI entry point compiled from src/cli.ts.
 * During development, use `tsx bin/bolt11.ts` or build first via `npm run build`.
 */

import { run } from '../dist/cli.js';

const argv = process.argv.slice(2);

run(argv).catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Fatal error: ${message}\n`);
  process.exit(1);
});

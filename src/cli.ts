/**
 * bolt11-cli – Commander CLI entry point.
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { decodeInvoice } from './decoder.js';
import { prettyPrint, printJson } from './formatter.js';
import type { DecodedInvoice } from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const require = createRequire(import.meta.url);
const { version } = require('../package.json');

/**
 * Read invoice string from argument, file, or stdin.
 */
async function readInvoice(
  invoiceArg: string | undefined,
  filePath: string | undefined,
): Promise<string> {
  if (invoiceArg) {
    return invoiceArg;
  }

  if (filePath) {
    return readFileSync(filePath, 'utf-8').trim();
  }

  // Read from stdin (piped input)
  const stdin = await readStdin();
  if (stdin.trim()) {
    return stdin.trim();
  }

  throw new Error('No invoice provided. Pass as argument, pipe to stdin, or use --file.');
}

/** Read all of stdin */
function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    if (process.stdin.isTTY) {
      resolve('');
      return;
    }

    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    process.stdin.resume();
  });
}

/**
 * Process an invoice: decode and display.
 */
async function processInvoice(
  invoiceStr: string,
  options: { json: boolean; verbose: boolean; silent?: boolean },
): Promise<{
  invoice: DecodedInvoice;
  code: number;
}> {
  const invoice = decodeInvoice(invoiceStr);

  if (options.json) {
    printJson(invoice);
  } else if (options.verbose) {
    // Verbose mode: show minimal output
    if (invoice.signatureValid === true) {
      process.stdout.write('✓ Valid signature\n');
    } else if (invoice.signatureValid === false) {
      process.stdout.write('✗ Invalid signature\n');
    }
    if (invoice.expired) {
      process.stdout.write(`✗ Expired (${invoice.expiryDescription})\n`);
    }
  } else if (!options.silent) {
    prettyPrint(invoice);
  }

  // Determine exit code
  let code = 0;
  if (invoice.expired) {
    code = 2;
  }
  if (invoice.signatureValid === false) {
    code = 3;
  }

  return { invoice, code };
}

// ---------------------------------------------------------------------------
// CLI Definition
// ---------------------------------------------------------------------------

const program = new Command();

program
  .name('bolt11')
  .description('Decode and validate Bitcoin Lightning BOLT11 payment invoices')
  .version(version, '-v, --version', 'Output the current version');

// Default (decode) command
program
  .command('decode')
  .description('Decode and display a BOLT11 invoice (default)')
  .argument('[invoice]', 'BOLT11 invoice string starting with lnbc, lntb, etc.')
  .option('-f, --file <path>', 'Read invoice from file')
  .option('-j, --json', 'Output as structured JSON')
  .action(async (invoiceArg: string | undefined, opts: { file?: string; json?: boolean }) => {
    try {
      const invoiceStr = await readInvoice(invoiceArg, opts.file);
      const result = await processInvoice(invoiceStr, {
        json: opts.json ?? false,
        verbose: false,
      });
      process.exitCode = result.code;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Error: ${message}\n`);
      process.exitCode = 1;
    }
  });

// Validate command
program
  .command('validate')
  .description('Validate a BOLT11 invoice (exit 0 = valid, 1 = error, 2 = expired, 3 = invalid signature)')
  .argument('[invoice]', 'BOLT11 invoice string')
  .option('-f, --file <path>', 'Read invoice from file')
  .option('-j, --json', 'Output as structured JSON')
  .option('-V, --verbose', 'Show validation details')
  .action(async (invoiceArg: string | undefined, opts: { file?: string; json?: boolean; verbose?: boolean }) => {
    try {
      const invoiceStr = await readInvoice(invoiceArg, opts.file);
      const result = await processInvoice(invoiceStr, {
        json: opts.json ?? false,
        verbose: opts.verbose ?? false,
        silent: !(opts.verbose ?? false),
      });
      process.exitCode = result.code;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (opts.verbose) {
        process.stderr.write(`Error: ${message}\n`);
      }
      process.exitCode = 1;
    }
  });

// If no command is given, default to "decode"
// We need to handle this by making decode the default action
// When no command matches, run decode
const originalAction = program.action.bind(program);

// Parse and run
export async function run(argv: string[]): Promise<void> {
  // Check if first non-option argument is a command we know
  const knownCommands = ['decode', 'validate', 'help', '--help', '-h', '--version', '-v'];

  // If no args or first arg is an option that's not a command, default to decode
  const firstArg = argv.find((a) => !a.startsWith('-'));
  if (firstArg && !knownCommands.includes(firstArg)) {
    // Treat as invoice argument to decode command
    // Insert 'decode' before it
    argv.splice(0, 0, 'decode');
  } else if (argv.length === 0 || argv.every((a) => a.startsWith('-'))) {
    // No positional args at all
    // Only if not asking for help or version
    const hasHelpFlag = argv.some((a) => a === '--help' || a === '-h');
    const hasVersionFlag = argv.some((a) => a === '--version' || a === '-v');
    if (!hasHelpFlag && !hasVersionFlag) {
      argv.splice(0, 0, 'decode');
    }
  }

  await program.parseAsync(argv, { from: 'user' });
}

/**
 * bolt11-cli – Commander CLI entry point.
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { decodeInvoice, recoverPubkey } from './decoder.js';
import { prettyPrint, printJson, printWhois, printWhoisJson, printAudit, printAuditJson } from './formatter.js';
import { lookupNode } from './known-nodes.js';
import type { DecodedInvoice, WhoisResult, AuditResult, AuditFinding, FindingSeverity } from './types.js';

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

// ---------------------------------------------------------------------------
// Whois logic
// ---------------------------------------------------------------------------

/**
 * Perform a whois lookup on a decoded invoice.
 */
export function whoisInvoice(invoice: DecodedInvoice, invoiceStr: string): WhoisResult {
  const recoveredKey = recoverPubkey(invoiceStr) ?? invoice.recoveredPayeeNodeKey ?? '';
  const payeeNodeKey = invoice.payeeNodeKey;

  // Try to look up the recovered key in known nodes
  const node = recoveredKey ? lookupNode(recoveredKey) : null;

  // Check for route hints → LSP detection
  let lsp: { pubkey: string; alias: string; type: string } | undefined;
  let behindLsp = false;

  if (invoice.routeHints.length > 0) {
    behindLsp = true;
    // First route hint's pubkey is typically the LSP
    const lspPubkey = invoice.routeHints[0].pubkey;
    const lspNode = lookupNode(lspPubkey);
    if (lspNode) {
      lsp = { pubkey: lspPubkey, alias: lspNode.alias, type: lspNode.type };
    } else {
      lsp = { pubkey: lspPubkey, alias: 'Unknown LSP', type: 'lsp' };
    }
  }

  // Build classification
  let classification: string;
  if (node) {
    classification = `Payee identified: ${node.alias} (${node.type})`;
    if (behindLsp && lsp) {
      classification += ` via ${lsp.alias} (LSP)`;
    }
  } else if (behindLsp && lsp) {
    classification = `Private node behind LSP: ${lsp.alias}`;
  } else if (behindLsp) {
    classification = 'Private node behind an unknown LSP';
  } else if (recoveredKey) {
    classification = 'Unknown public node (not in bundled dataset)';
  } else {
    classification = 'Could not determine payee';
  }

  return {
    recoveredKey,
    payeeNodeKey,
    node: node ?? undefined,
    lsp,
    behindLsp,
    classification,
  };
}

// ---------------------------------------------------------------------------
// Audit logic
// ---------------------------------------------------------------------------

/**
 * Determine the highest severity from a list of findings.
 */
export function highestSeverity(findings: AuditFinding[]): FindingSeverity {
  const order: FindingSeverity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  let maxIdx = 0;
  for (const f of findings) {
    const idx = order.indexOf(f.severity);
    if (idx > maxIdx) maxIdx = idx;
  }
  return order[maxIdx];
}

/**
 * Perform a structured privacy + security audit on a decoded invoice.
 */
export function auditInvoice(invoice: DecodedInvoice, invoiceStr: string): AuditResult {
  const findings: AuditFinding[] = [];

  // -- Privacy checks --

  // 1. Payee identifiable
  const w = whoisInvoice(invoice, invoiceStr);
  if (w.node) {
    findings.push({
      category: 'privacy',
      severity: 'MEDIUM',
      title: 'Payee Identified',
      detail: `The invoice payee was identified as "${w.node.alias}" (${w.node.type}). Your payment counterparty is known.`,
    });
  }

  // 2. Route hint SCID leak (unannounced channel SCIDs can leak on-chain UTXOs)
  if (invoice.routeHints.length > 0) {
    for (const rh of invoice.routeHints) {
      findings.push({
        category: 'privacy',
        severity: 'HIGH',
        title: 'Route Hint SCID Leak',
        detail: `Route hint contains short_channel_id ${rh.short_channel_id}. If this is an unannounced channel, the SCID may reveal on-chain UTXO information.`,
      });
    }
  }

  // 3. LSP pubkey exposure
  if (w.lsp) {
    findings.push({
      category: 'privacy',
      severity: 'MEDIUM',
      title: 'LSP Pubkey Exposure',
      detail: `The invoice is routed through LSP "${w.lsp.alias}" (${w.lsp.pubkey}). The LSP's identity is exposed in the route hints.`,
    });
  }

  // -- Security checks --

  // 1. Invalid signature
  if (invoice.signatureValid === false) {
    findings.push({
      category: 'security',
      severity: 'CRITICAL',
      title: 'Invalid Signature',
      detail: 'The invoice signature does not match the recovered payee key. The invoice may be tampered with.',
    });
  } else if (invoice.signatureValid === 'unverified') {
    findings.push({
      category: 'security',
      severity: 'LOW',
      title: 'Signature Unverified',
      detail: 'No `n` tag present in the invoice. The recovered key could not be cross-checked against an explicit payee key.',
    });
  }

  // 2. Expired / near expiry
  if (invoice.expired) {
    findings.push({
      category: 'security',
      severity: 'MEDIUM',
      title: 'Invoice Expired',
      detail: `This invoice expired ${invoice.expiryDescription}. Expired invoices should not be paid.`,
    });
  } else {
    const nearExpiryThreshold = 600; // 10 minutes
    if (invoice.expiryDeltaSeconds < nearExpiryThreshold) {
      findings.push({
        category: 'security',
        severity: 'LOW',
        title: 'Invoice Nearing Expiry',
        detail: `This invoice expires in ${invoice.expiryDescription}. Consider requesting a fresh invoice.`,
      });
    }
  }

  // 3. Amount vs description sanity
  if (invoice.description && invoice.amount.millisatoshis !== null) {
    const millisats = Number(invoice.amount.millisatoshis);
    if (millisats === 0) {
      findings.push({
        category: 'security',
        severity: 'LOW',
        title: 'Zero-Amount Invoice with Description',
        detail: `The invoice has a description ("${invoice.description}") but zero amount specified. The payer MUST supply an amount, which is a phishing risk.`,
      });
    }
  }

  // 4. Missing payment_secret (probing/MPP risk)
  if (!invoice.paymentSecret) {
    findings.push({
      category: 'security',
      severity: 'HIGH',
      title: 'Missing Payment Secret',
      detail: 'No `payment_secret` field. This invoice is vulnerable to probing attacks and cannot be used with multi-path payments (MPP). Keysend/payments without secret are risky.',
    });
  }

  // 5. Unknown required feature bits
  const featureBits = invoice.featureBits as Record<string, unknown>;
  if (featureBits.extra_bits && typeof featureBits.extra_bits === 'object') {
    const extra = featureBits.extra_bits as Record<string, unknown>;
    if (extra.has_required === true) {
      findings.push({
        category: 'security',
        severity: 'MEDIUM',
        title: 'Unknown Required Feature Bits',
        detail: 'The invoice has unknown feature bits marked as required. Your wallet may not support all required features.',
      });
    }
  }

  // 6. Fallback address network mismatch (check if fallback address network matches invoice network)
  if (invoice.fallbackAddresses.length > 0) {
    // Fallback addresses in BOLT11 use witness version + address hash; network mismatch
    // is hard to detect without parsing addresses, but we can flag their existence on testnet
    // as a potential risk
    findings.push({
      category: 'info',
      severity: 'INFO',
      title: 'Fallback Address Present',
      detail: `${invoice.fallbackAddresses.length} fallback address(es) present. Ensure the address network matches the invoice (${invoice.networkBech32}).`,
    });
  }

  // Summary
  const summary = {
    privacy: findings.filter(f => f.category === 'privacy').length,
    security: findings.filter(f => f.category === 'security').length,
    info: findings.filter(f => f.category === 'info').length,
  };
  const riskLevel = highestSeverity(findings);

  return { findings, riskLevel, summary };
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

/**
 * Process an invoice: decode and display.
 */
async function processInvoice(
  invoiceStr: string,
  options: { json: boolean; verbose: boolean; silent?: boolean; whois?: boolean },
): Promise<{
  invoice: DecodedInvoice;
  code: number;
}> {
  const invoice = decodeInvoice(invoiceStr);

  if (options.json) {
    printJson(invoice);
  } else if (options.verbose) {
    if (invoice.signatureValid === true) {
      process.stdout.write('✓ Valid signature\n');
    } else if (invoice.signatureValid === false) {
      process.stdout.write('✗ Invalid signature\n');
    } else if (invoice.signatureValid === 'unverified') {
      process.stdout.write('? Unverified signature (no n-tag)\n');
    }
    if (invoice.expired) {
      process.stdout.write(`✗ Expired (${invoice.expiryDescription})\n`);
    }
  } else if (!options.silent) {
    prettyPrint(invoice);
  }

  // Optional whois annotation on decode
  if (options.whois) {
    const w = whoisInvoice(invoice, invoiceStr);
    if (options.json) {
      const json = JSON.parse(JSON.stringify(invoice));
      (json as Record<string, unknown>).whois = w;
      process.stdout.write('\n' + JSON.stringify(json, null, 2) + '\n');
    } else {
      printWhois(w);
    }
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
  .description('Decode, validate, and audit Bitcoin Lightning BOLT11 payment invoices')
  .version(version, '-v, --version', 'Output the current version');

// Default (decode) command
program
  .command('decode')
  .description('Decode and display a BOLT11 invoice (default)')
  .argument('[invoice]', 'BOLT11 invoice string starting with lnbc, lntb, etc.')
  .option('-f, --file <path>', 'Read invoice from file')
  .option('-j, --json', 'Output as structured JSON')
  .option('-w, --whois', 'Append whois payee identification')
  .action(async (invoiceArg: string | undefined, opts: { file?: string; json?: boolean; whois?: boolean }) => {
    try {
      const invoiceStr = await readInvoice(invoiceArg, opts.file);
      const result = await processInvoice(invoiceStr, {
        json: opts.json ?? false,
        verbose: false,
        whois: opts.whois ?? false,
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

// Whois command
program
  .command('whois')
  .description('Identify the payee of a BOLT11 invoice (recover pubkey, look up known nodes)')
  .argument('[invoice]', 'BOLT11 invoice string')
  .option('-f, --file <path>', 'Read invoice from file')
  .option('-j, --json', 'Output as JSON')
  .action(async (invoiceArg: string | undefined, opts: { file?: string; json?: boolean }) => {
    try {
      const invoiceStr = await readInvoice(invoiceArg, opts.file);
      const invoice = decodeInvoice(invoiceStr);
      const whois = whoisInvoice(invoice, invoiceStr);

      if (opts.json) {
        printWhoisJson(whois);
      } else {
        printWhois(whois);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Error: ${message}\n`);
      process.exitCode = 1;
    }
  });

// Audit command
program
  .command('audit')
  .description('Perform a structured privacy + security audit on a BOLT11 invoice')
  .argument('[invoice]', 'BOLT11 invoice string')
  .option('-f, --file <path>', 'Read invoice from file')
  .option('-j, --json', 'Output as JSON')
  .action(async (invoiceArg: string | undefined, opts: { file?: string; json?: boolean }) => {
    try {
      const invoiceStr = await readInvoice(invoiceArg, opts.file);
      const invoice = decodeInvoice(invoiceStr);
      const audit = auditInvoice(invoice, invoiceStr);

      if (opts.json) {
        printAuditJson(audit);
      } else {
        printAudit(audit);
      }

      // Exit code 4 = audit findings present (beyond INFO)
      const hasFindings = audit.findings.some(f => f.severity !== 'INFO');
      if (hasFindings) {
        process.exitCode = 4;
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Error: ${message}\n`);
      process.exitCode = 1;
    }
  });

// If no command is given, default to "decode"
const knownCommands = ['decode', 'validate', 'whois', 'audit', 'help', '--help', '-h', '--version', '-v'];

// Parse and run
export async function run(argv: string[]): Promise<void> {
  const firstArg = argv.find((a) => !a.startsWith('-'));
  if (firstArg && !knownCommands.includes(firstArg)) {
    argv.splice(0, 0, 'decode');
  } else if (argv.length === 0 || argv.every((a) => a.startsWith('-'))) {
    const hasHelpFlag = argv.some((a) => a === '--help' || a === '-h');
    const hasVersionFlag = argv.some((a) => a === '--version' || a === '-v');
    if (!hasHelpFlag && !hasVersionFlag) {
      argv.splice(0, 0, 'decode');
    }
  }

  await program.parseAsync(argv, { from: 'user' });
}

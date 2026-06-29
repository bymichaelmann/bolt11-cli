/**
 * bolt11-cli – Pretty-print formatter with chalk.
 */

import chalk from 'chalk';
import type { DecodedInvoice, WhoisResult, AuditResult, AuditFinding, FindingSeverity } from './types.js';

/**
 * Big heading separator.
 */
function section(title: string): string {
  return chalk.bold.cyan(`\n ━━━ ${title} ━━━\n`);
}

/**
 * Key-value line with alignment.
 */
function kv(key: string, value: string): string {
  return `  ${chalk.yellow(key.padEnd(30))} ${value}`;
}

/**
 * Format a tag line (indented).
 */
function tag(key: string, value: string): string {
  return `    ${chalk.dim(key.padEnd(26))} ${value}`;
}

/**
 * Format a route hint entry (compact).
 */
function formatRouteHint(rh: { pubkey: string; short_channel_id: string; fee_base_msat: number; fee_proportional_millionths: number; cltv_expiry_delta: number }): string {
  const scid = rh.short_channel_id;
  const pubShort = `${rh.pubkey.slice(0, 16)}…${rh.pubkey.slice(-8)}`;
  const feeStr = `${rh.fee_base_msat} base + ${rh.fee_proportional_millionths} ppm`;
  return `    ${chalk.dim('•')} ${pubShort}  ${chalk.dim('scid:')} ${scid}  ${chalk.dim('fee:')} ${feeStr}  ${chalk.dim('cltv:')} ${rh.cltv_expiry_delta}`;
}

/**
 * Pretty-print a decoded invoice to the terminal.
 */
export function prettyPrint(invoice: DecodedInvoice): void {
  const lines: string[] = [];
  const { amount } = invoice;

  // ── Header ──────────────────────────────────────────────────
  lines.push('');
  lines.push(chalk.bold.magenta(' ⚡ BOLT11 Lightning Invoice'));
  lines.push(chalk.dim(` ${'─'.repeat(56)}`));

  // ── Overview ────────────────────────────────────────────────
  lines.push(section('Overview'));
  lines.push(kv('Currency', invoice.currency));
  lines.push(kv('Network', invoice.networkBech32));
  if (amount.millisatoshis !== null) {
    lines.push(kv('Amount', amount.formatted));
  } else {
    lines.push(kv('Amount', chalk.italic('Any (zero-amount invoice)')));
  }
  lines.push(kv('Complete', invoice.complete ? chalk.green('✓') : chalk.red('✗')));

  // ── Timestamps ──────────────────────────────────────────────
  lines.push(section('Timing'));
  lines.push(kv('Created', `${invoice.timestampString} (${invoice.timestamp})`));
  lines.push(kv('Expires', `${invoice.timeExpireDateString} (${invoice.timeExpireDate})`));
  lines.push(kv('Expiry Duration', `${invoice.expireTime}s`));

  const expiryColor = invoice.expired ? chalk.red : chalk.green;
  lines.push(kv('Status', invoice.expired
    ? chalk.red('✗ EXPIRED')
    : chalk.green(`✓ Valid (expires in ${invoice.expiryDescription})`)
  ));

  if (invoice.expired) {
    lines.push(kv('Overdue by', chalk.red(invoice.expiryDescription)));
  }

  // ── Payment Details ─────────────────────────────────────────
  lines.push(section('Payment Details'));
  lines.push(kv('Payment Hash', chalk.cyan(invoice.paymentHash)));
  if (invoice.paymentSecret) {
    lines.push(kv('Payment Secret', chalk.dim(invoice.paymentSecret)));
  }
  if (invoice.description) {
    lines.push(kv('Description', chalk.white(invoice.description)));
  }
  if (invoice.descriptionHash) {
    lines.push(kv('Description Hash', chalk.dim(invoice.descriptionHash)));
  }

  // ── Payee ───────────────────────────────────────────────────
  lines.push(section('Payee'));
  if (invoice.payeeNodeKey) {
    lines.push(kv('Node Pubkey', chalk.cyan(invoice.payeeNodeKey)));
  } else if (invoice.recoveredPayeeNodeKey) {
    lines.push(kv('Node Pubkey', chalk.dim('(recovered from signature)')));
  }
  if (invoice.recoveredPayeeNodeKey) {
    const label = invoice.payeeNodeKey ? 'Recovered Key' : 'Recovered Pubkey';
    const color = invoice.payeeNodeKey
      ? (invoice.payeeNodeKey === invoice.recoveredPayeeNodeKey ? chalk.green : chalk.red)
      : chalk.cyan;
    lines.push(kv(label, color(invoice.recoveredPayeeNodeKey)));
  }

  // ── Fallback Addresses ──────────────────────────────────────
  if (invoice.fallbackAddresses.length > 0) {
    lines.push(section('Fallback Addresses'));
    for (const fb of invoice.fallbackAddresses) {
      lines.push(`    ${chalk.dim('•')} ${chalk.cyan(fb.address)}  ${chalk.dim(`(code ${fb.code})`)}`);
    }
  }

  // ── Route Hints ─────────────────────────────────────────────
  if (invoice.routeHints.length > 0) {
    lines.push(section(`Route Hints (${invoice.routeHints.length})`));
    for (const rh of invoice.routeHints) {
      lines.push(formatRouteHint(rh));
    }
  }

  // ── CLTV ────────────────────────────────────────────────────
  lines.push(section('Settlement'));
  lines.push(kv('Min Final CLTV Expiry', String(invoice.minFinalCltvExpiry)));

  // ── Signature ───────────────────────────────────────────────
  lines.push(section('Cryptography'));
  lines.push(kv('Recovery Flag', String(invoice.recoveryFlag)));
  lines.push(kv('Signature', chalk.dim(invoice.signature)));

  if (invoice.signatureValid === true) {
    lines.push(kv('Signature Valid', chalk.green('✓ Valid signature')));
  } else if (invoice.signatureValid === false) {
    lines.push(kv('Signature Valid', chalk.red('✗ Invalid signature')));
  } else if (invoice.signatureValid === 'unverified') {
    lines.push(kv('Signature Valid', chalk.yellow('? Unverified (no n-tag to compare)')));
  } else {
    lines.push(kv('Signature Valid', chalk.yellow('? Could not verify')));
  }

  lines.push('');
  process.stdout.write(lines.join('\n'));
}

// ---------------------------------------------------------------------------
// Whois output
// ---------------------------------------------------------------------------

/**
 * Pretty-print a whois result.
 */
export function printWhois(whois: WhoisResult): void {
  const lines: string[] = [];
  lines.push('');
  lines.push(chalk.bold.magenta(' 🔍 Who Am I Paying?'));
  lines.push(chalk.dim(` ${'─'.repeat(56)}`));
  lines.push('');

  if (whois.node) {
    lines.push(`  ${chalk.bold('You are likely paying:')} ${chalk.cyan(whois.node.alias)}`);
    lines.push(`  ${chalk.dim('Type:')}                   ${chalk.yellow(whois.node.type)}`);
  } else {
    lines.push(`  ${chalk.bold('Payee:')} ${chalk.yellow('Unknown node — not in bundled dataset')}`);
  }

  if (whois.behindLsp && whois.lsp) {
    lines.push('');
    lines.push(`  ${chalk.dim('This invoice is routed through an LSP:')}`);
    lines.push(`    ${chalk.dim('LSP:')}   ${chalk.cyan(whois.lsp.alias)} (${chalk.yellow(whois.lsp.type)})`);
    lines.push(`    ${chalk.dim('Key:')}  ${chalk.dim(whois.lsp.pubkey)}`);
  }

  if (whois.behindLsp && !whois.lsp) {
    lines.push('');
    lines.push(`  ${chalk.yellow('Invoice uses route hints (likely behind an LSP)')}`);
  }

  lines.push('');
  lines.push(`  ${chalk.dim('Classification:')} ${chalk.white(whois.classification)}`);
  lines.push('');
  lines.push(`  ${chalk.dim('Recovered key:')}  ${chalk.cyan(whois.recoveredKey)}`);
  if (whois.payeeNodeKey && whois.payeeNodeKey !== whois.recoveredKey) {
    lines.push(`  ${chalk.dim('n-tag key:')}     ${chalk.red(whois.payeeNodeKey)}`);
  }
  lines.push('');
  process.stdout.write(lines.join('\n'));
}

/**
 * JSON output for a whois result.
 */
export function printWhoisJson(whois: WhoisResult): void {
  process.stdout.write(JSON.stringify(whois, null, 2) + '\n');
}

// ---------------------------------------------------------------------------
// Audit output
// ---------------------------------------------------------------------------

function severityColor(severity: FindingSeverity) {
  switch (severity) {
    case 'INFO':    return chalk.blue;
    case 'LOW':     return chalk.green;
    case 'MEDIUM':  return chalk.yellow;
    case 'HIGH':    return chalk.red;
    case 'CRITICAL': return chalk.bgRed.white.bold;
  }
}

const SEVERITY_ICON: Record<FindingSeverity, string> = {
  INFO:    'ℹ',
  LOW:     'ⓘ',
  MEDIUM:  '⚠',
  HIGH:    '✗',
  CRITICAL: '‼',
};

/**
 * Pretty-print an audit result.
 */
export function printAudit(audit: AuditResult): void {
  const lines: string[] = [];
  lines.push('');
  lines.push(chalk.bold.magenta(' 🛡  Invoice Privacy & Security Audit'));
  lines.push(chalk.dim(` ${'─'.repeat(56)}`));

  if (audit.findings.length === 0) {
    lines.push('');
    lines.push(`  ${chalk.green('✓ No findings — invoice looks clean.')}`);
    lines.push('');
    process.stdout.write(lines.join('\n'));
    return;
  }

  // Group by category
  const privacy = audit.findings.filter(f => f.category === 'privacy');
  const security = audit.findings.filter(f => f.category === 'security');
  const info = audit.findings.filter(f => f.category === 'info');

  if (privacy.length > 0) {
    lines.push(chalk.bold.cyan('\n ━━━ Privacy ━━━\n'));
    for (const f of privacy) {
      const sevColor = severityColor(f.severity);
      const icon = SEVERITY_ICON[f.severity];
      lines.push(`  ${sevColor(`${icon} [${f.severity}]`)} ${chalk.bold(f.title)}`);
      lines.push(`    ${chalk.dim(f.detail)}`);
    }
  }

  if (security.length > 0) {
    lines.push(chalk.bold.cyan('\n ━━━ Security ━━━\n'));
    for (const f of security) {
      const sevColor = severityColor(f.severity);
      const icon = SEVERITY_ICON[f.severity];
      lines.push(`  ${sevColor(`${icon} [${f.severity}]`)} ${chalk.bold(f.title)}`);
      lines.push(`    ${chalk.dim(f.detail)}`);
    }
  }

  if (info.length > 0) {
    lines.push(chalk.bold.cyan('\n ━━━ Info ━━━\n'));
    for (const f of info) {
      const sevColor = severityColor(f.severity);
      const icon = SEVERITY_ICON[f.severity];
      lines.push(`  ${sevColor(`${icon} [${f.severity}]`)} ${chalk.bold(f.title)}`);
      lines.push(`    ${chalk.dim(f.detail)}`);
    }
  }

  // Risk summary
  const riskColor = severityColor(audit.riskLevel);
  lines.push(chalk.bold.cyan('\n ━━━ Risk Summary ━━━\n'));
  lines.push(`  ${chalk.bold('Overall risk:')}  ${riskColor(audit.riskLevel)}`);
  lines.push(`  ${chalk.dim('Findings:')}    ${audit.summary.privacy} privacy, ${audit.summary.security} security, ${audit.summary.info} info`);
  lines.push('');
  process.stdout.write(lines.join('\n'));
}

/**
 * JSON output for an audit result.
 */
export function printAuditJson(audit: AuditResult): void {
  process.stdout.write(JSON.stringify(audit, null, 2) + '\n');
}

/**
 * JSON output for a decoded invoice.
 */
export function printJson(invoice: DecodedInvoice): void {
  const obj: Record<string, unknown> = {
    paymentRequest: invoice.paymentRequest,
    complete: invoice.complete,
    prefix: invoice.prefix,
    network: invoice.networkBech32,
    currency: invoice.currency,
    amount: {
      millisatoshis: invoice.amount.millisatoshis,
      satoshis: invoice.amount.satoshis,
      btc: invoice.amount.btc,
      formatted: invoice.amount.formatted,
    },
    timestamp: invoice.timestamp,
    timestampString: invoice.timestampString,
    timeExpireDate: invoice.timeExpireDate,
    timeExpireDateString: invoice.timeExpireDateString,
    paymentHash: invoice.paymentHash,
    paymentSecret: invoice.paymentSecret || null,
    description: invoice.description || null,
    descriptionHash: invoice.descriptionHash || null,
    expireTime: invoice.expireTime,
    payeeNodeKey: invoice.payeeNodeKey || null,
    recoveredPayeeNodeKey: invoice.recoveredPayeeNodeKey || null,
    signature: invoice.signature,
    recoveryFlag: invoice.recoveryFlag,
    fallbackAddresses: invoice.fallbackAddresses,
    routeHints: invoice.routeHints,
    minFinalCltvExpiry: invoice.minFinalCltvExpiry,
    featureBits: invoice.featureBits,
    expired: invoice.expired,
    expiryDeltaSeconds: invoice.expiryDeltaSeconds,
    expiryDescription: invoice.expiryDescription,
    signatureValid: invoice.signatureValid,
  };
  process.stdout.write(JSON.stringify(obj, null, 2) + '\n');
}

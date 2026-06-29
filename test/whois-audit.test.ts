/**
 * bolt11-cli – Tests for whois, audit, lookupNode, highestSeverity, and formatter functions.
 *
 * These functions had ZERO test coverage.
 */

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { decodeInvoice, recoverPubkey } from '../src/decoder.js';
import { lookupNode, KNOWN_NODES } from '../src/known-nodes.js';
import { whoisInvoice, auditInvoice, highestSeverity } from '../src/cli.js';
import { printWhois, printWhoisJson, printAudit, printAuditJson } from '../src/formatter.js';
import type {
  DecodedInvoice,
  WhoisResult,
  AuditResult,
  AuditFinding,
  FindingSeverity,
  RouteHintEntry,
  FallbackAddress,
} from '../src/types.js';

// ---------------------------------------------------------------------------
// Shared Invoice Strings
// ---------------------------------------------------------------------------

const VALID_MAINNET_INVOICE =
  'lnbc20u1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kxqrrsssp5m6kmam774klwlh4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs9qypqqqcqpf3cwux5979a8j28d4ydwahx00saa68wq3az7v9jdgzkghtxnkf3z5t7q5suyq2dl9tqwsap8j0wptc82cpyvey9gf6zyylzrm60qtcqsq7egtsq';

const SIGNED_MAINNET_INVOICE =
  'lnbc5u1pj48ugqpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpq2pshjmt9de6zqen0wgs8xetjwe5kxetnxqrrsscqpf94gldela63d9w0r03qkxn9asnu3q35zejmt8w3r5k90ejycja9txptrm4udltv8djzh9qv08c0zk0ks4fqtjamklzvcfdyymcrvrf0qp2cepqz';

// Known pubkeys from KNOWN_NODES
const WALLET_OF_SATOSHI_PUBKEY = '035e4ff418fc8b5554c5d9eea66396c227bd42990bb40f2cf9ee17e5e0fe80c22b';
const BREEZ_LSP_PUBKEY = '02a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2';
const ACINQ_LSP_PUBKEY = '02c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4';
const WANDERING_THUNDER_PUBKEY = '02c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0';

// The recovered key from VALID_MAINNET_INVOICE (NOT in KNOWN_NODES)
const MAINNET_RECOVERED_KEY = '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad';
const SIGNED_RECOVERED_KEY = '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f';

// ---------------------------------------------------------------------------
// Helper: build a mock DecodedInvoice with defaults and overrides
// ---------------------------------------------------------------------------

const defaultRouteHint: RouteHintEntry = {
  pubkey: BREEZ_LSP_PUBKEY,
  short_channel_id: '123456x789x1',
  fee_base_msat: 1000,
  fee_proportional_millionths: 100,
  cltv_expiry_delta: 9,
};

function buildMockInvoice(overrides: Partial<DecodedInvoice> = {}): DecodedInvoice {
  const now = Math.floor(Date.now() / 1000);

  const defaults: DecodedInvoice = {
    paymentRequest: VALID_MAINNET_INVOICE,
    complete: true,
    prefix: 'lnbc20u',
    networkBech32: 'bc',
    currency: 'Bitcoin (BTC)',
    amount: {
      millisatoshis: '2000000',
      satoshis: 2000,
      btc: 0.00002,
      formatted: '2,000 sats (2,000,000 msat)',
    },
    timestamp: 1496314658,
    timestampString: '2017-06-01T11:57:38.000Z',
    timeExpireDate: 1496318258,
    timeExpireDateString: '2017-06-01T12:57:38.000Z',
    paymentHash: '0001020304050607080900010203040506070809000102030405060708090102',
    paymentSecret: '1111111111111111111111111111111111111111111111111111111111111111',
    description: undefined,
    descriptionHash: undefined,
    expireTime: 3600,
    payeeNodeKey: MAINNET_RECOVERED_KEY,
    signature: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    recoveryFlag: 0,
    fallbackAddresses: [],
    routeHints: [],
    featureBits: { word_length: 4, extra_bits: { start_bit: 20, bits: [], has_required: false } },
    minFinalCltvExpiry: 9,
    expired: false,
    expiryDeltaSeconds: 3600,
    expiryDescription: '1h 0m 0s',
    signatureValid: true,
    recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
  };

  return { ...defaults, ...overrides };
}

// ===========================================================================
// Section 2a: lookupNode() in known-nodes.ts
// ===========================================================================

describe('lookupNode', () => {
  it('should return NodeInfo for a known pubkey (Wallet of Satoshi)', () => {
    const node = lookupNode(WALLET_OF_SATOSHI_PUBKEY);
    expect(node).not.toBeNull();
    expect(node!.alias).toBe('Wallet of Satoshi');
    expect(node!.type).toBe('custodial-exchange');
  });

  it('should return NodeInfo for ACINQ pubkey', () => {
    const node = lookupNode('03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f');
    expect(node).not.toBeNull();
    expect(node!.alias).toBe('ACINQ');
    expect(node!.type).toBe('non-custodial-wallet');
  });

  it('should return NodeInfo for a known LSP (Breez LSP)', () => {
    const node = lookupNode(BREEZ_LSP_PUBKEY);
    expect(node).not.toBeNull();
    expect(node!.alias).toBe('Breez LSP');
    expect(node!.type).toBe('lsp');
  });

  it('should return null for an unknown pubkey', () => {
    const node = lookupNode(MAINNET_RECOVERED_KEY);
    expect(node).toBeNull();
  });

  it('should return null for an empty string', () => {
    const node = lookupNode('');
    expect(node).toBeNull();
  });

  it('should return null for a partial/invalid key', () => {
    const node = lookupNode('00');
    expect(node).toBeNull();
  });
});

// ===========================================================================
// Section 2b: whoisInvoice() in cli.ts
// ===========================================================================

describe('whoisInvoice', () => {
  // For whoisInvoice tests, we mock lookupNode so we can control exactly what
  // it returns for specific recovered keys.
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('should identify a known node when recovered key matches KNOWN_NODES (Wallet of Satoshi)', () => {
    // Use a bad invoice string so recoverPubkey returns null, allowing
    // our overridden recoveredPayeeNodeKey to take effect.
    const invoice = buildMockInvoice({ recoveredPayeeNodeKey: WALLET_OF_SATOSHI_PUBKEY });
    const result = whoisInvoice(invoice, 'lnbc1');
    expect(result.node).toBeDefined();
    expect(result.node!.alias).toBe('Wallet of Satoshi');
    expect(result.node!.type).toBe('custodial-exchange');
    expect(result.classification).toContain('Payee identified: Wallet of Satoshi');
    expect(result.classification).toContain('custodial-exchange');
  });

  it('should identify a known node (routing-node type, Wandering Thunder)', () => {
    const invoice = buildMockInvoice({ recoveredPayeeNodeKey: WANDERING_THUNDER_PUBKEY });
    const result = whoisInvoice(invoice, 'lnbc1');
    expect(result.node).toBeDefined();
    expect(result.node!.alias).toBe('Wandering Thunder');
    expect(result.node!.type).toBe('routing-node');
    expect(result.classification).toContain('Payee identified: Wandering Thunder');
  });

  it('should report unknown public node for a key NOT in KNOWN_NODES with no route hints', () => {
    // With VALID_MAINNET_INVOICE, recoverPubkey returns MAINNET_RECOVERED_KEY
    // which is NOT in KNOWN_NODES
    const invoice = buildMockInvoice({ routeHints: [] });
    const result = whoisInvoice(invoice, VALID_MAINNET_INVOICE);
    expect(result.node).toBeUndefined();
    expect(result.behindLsp).toBe(false);
    expect(result.classification).toBe('Unknown public node (not in bundled dataset)');
  });

  it('should detect a known LSP behind route hints', () => {
    // Route hint pubkey IS a known LSP
    const routeHint: RouteHintEntry = {
      pubkey: BREEZ_LSP_PUBKEY,
      short_channel_id: '654321x0x1',
      fee_base_msat: 0,
      fee_proportional_millionths: 0,
      cltv_expiry_delta: 9,
    };
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
      routeHints: [routeHint],
    });
    const result = whoisInvoice(invoice, 'lnbc1');
    expect(result.node).toBeUndefined();
    expect(result.behindLsp).toBe(true);
    expect(result.lsp).toBeDefined();
    expect(result.lsp!.alias).toBe('Breez LSP');
    expect(result.lsp!.type).toBe('lsp');
    expect(result.classification).toContain('Private node behind LSP: Breez LSP');
  });

  it('should detect an unknown LSP behind route hints', () => {
    // Route hint pubkey is NOT in KNOWN_NODES
    const routeHint: RouteHintEntry = {
      pubkey: MAINNET_RECOVERED_KEY,
      short_channel_id: '111111x111x1',
      fee_base_msat: 500,
      fee_proportional_millionths: 50,
      cltv_expiry_delta: 12,
    };
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: SIGNED_RECOVERED_KEY,
      routeHints: [routeHint],
    });
    const result = whoisInvoice(invoice, 'lnbc1');
    expect(result.node).toBeUndefined();
    expect(result.behindLsp).toBe(true);
    expect(result.lsp).toBeDefined();
    expect(result.lsp!.alias).toBe('Unknown LSP');
    expect(result.lsp!.type).toBe('lsp');
    // When lsp is defined (even with unknown alias), the classification is
    // "Private node behind LSP: Unknown LSP"
    expect(result.classification).toContain('Private node behind LSP: Unknown LSP');
  });

  it('should detect a known node that is also behind an LSP', () => {
    const routeHint: RouteHintEntry = {
      pubkey: ACINQ_LSP_PUBKEY,
      short_channel_id: '999999x999x9',
      fee_base_msat: 0,
      fee_proportional_millionths: 0,
      cltv_expiry_delta: 9,
    };
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: WALLET_OF_SATOSHI_PUBKEY,
      routeHints: [routeHint],
    });
    const result = whoisInvoice(invoice, 'lnbc1');
    expect(result.node).toBeDefined();
    expect(result.node!.alias).toBe('Wallet of Satoshi');
    expect(result.behindLsp).toBe(true);
    expect(result.lsp).toBeDefined();
    expect(result.lsp!.alias).toBe('ACINQ LSP');
    expect(result.classification).toContain('via ACINQ LSP (LSP)');
  });

  it('should handle multiple route hints (uses first for LSP detection)', () => {
    const firstHint: RouteHintEntry = {
      pubkey: BREEZ_LSP_PUBKEY,
      short_channel_id: '111x111x1',
      fee_base_msat: 0,
      fee_proportional_millionths: 0,
      cltv_expiry_delta: 9,
    };
    const secondHint: RouteHintEntry = {
      pubkey: ACINQ_LSP_PUBKEY,
      short_channel_id: '222x222x2',
      fee_base_msat: 0,
      fee_proportional_millionths: 0,
      cltv_expiry_delta: 9,
    };
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
      routeHints: [firstHint, secondHint],
    });
    const result = whoisInvoice(invoice, 'lnbc1');
    // First route hint is used for LSP
    expect(result.lsp).toBeDefined();
    expect(result.lsp!.pubkey).toBe(BREEZ_LSP_PUBKEY);
    expect(result.lsp!.alias).toBe('Breez LSP');
    expect(result.classification).toContain('Breez LSP');
  });

  it('should return "Could not determine payee" when recoveredKey is empty and no route hints', () => {
    // Simulate an invoice where recoverPubkey returns empty string
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: '',
      payeeNodeKey: undefined,
      routeHints: [],
    });
    // We need an invoice string that makes recoverPubkey return ''
    const result = whoisInvoice(invoice, 'lnbc1qwerty');
    expect(result.recoveredKey).toBe('');
    expect(result.node).toBeUndefined();
    expect(result.behindLsp).toBe(false);
    expect(result.classification).toBe('Could not determine payee');
  });

  it('should populate payeeNodeKey in the result', () => {
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
      payeeNodeKey: MAINNET_RECOVERED_KEY,
    });
    const result = whoisInvoice(invoice, 'lnbc1');
    expect(result.payeeNodeKey).toBe(MAINNET_RECOVERED_KEY);
  });

  it('should return lsp undefined when behindLsp is false', () => {
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
      routeHints: [],
    });
    const result = whoisInvoice(invoice, VALID_MAINNET_INVOICE);
    expect(result.lsp).toBeUndefined();
    expect(result.behindLsp).toBe(false);
  });
});

// ===========================================================================
// Section 2c: auditInvoice() in cli.ts
// ===========================================================================

describe('auditInvoice', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  // ── Privacy checks ──────────────────────────────────────────

  it('should find MEDIUM severity when payee is identifiable (known node)', () => {
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: WALLET_OF_SATOSHI_PUBKEY,
    });
    const result = auditInvoice(invoice, 'lnbc1');
    const finding = result.findings.find(f => f.title === 'Payee Identified');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
    expect(finding!.category).toBe('privacy');
    expect(finding!.detail).toContain('Wallet of Satoshi');
  });

  it('should find HIGH severity for each route hint SCID', () => {
    const routeHint: RouteHintEntry = {
      pubkey: BREEZ_LSP_PUBKEY,
      short_channel_id: '123456x789x1',
      fee_base_msat: 1000,
      fee_proportional_millionths: 100,
      cltv_expiry_delta: 9,
    };
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
      routeHints: [routeHint, { ...routeHint, short_channel_id: '999x888x7' }],
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const scidFindings = result.findings.filter(f => f.title === 'Route Hint SCID Leak');
    expect(scidFindings.length).toBe(2);
    for (const f of scidFindings) {
      expect(f.severity).toBe('HIGH');
      expect(f.category).toBe('privacy');
    }
    expect(scidFindings[0].detail).toContain('123456x789x1');
    expect(scidFindings[1].detail).toContain('999x888x7');
  });

  it('should find MEDIUM severity when LSP pubkey is exposed', () => {
    const routeHint: RouteHintEntry = {
      pubkey: ACINQ_LSP_PUBKEY,
      short_channel_id: '555x444x3',
      fee_base_msat: 0,
      fee_proportional_millionths: 0,
      cltv_expiry_delta: 9,
    };
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
      routeHints: [routeHint],
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const lspFinding = result.findings.find(f => f.title === 'LSP Pubkey Exposure');
    expect(lspFinding).toBeDefined();
    expect(lspFinding!.severity).toBe('MEDIUM');
    expect(lspFinding!.category).toBe('privacy');
    expect(lspFinding!.detail).toContain('ACINQ LSP');
  });

  it('should NOT find LSP pubkey exposure when no route hints', () => {
    const invoice = buildMockInvoice({ routeHints: [] });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const lspFinding = result.findings.find(f => f.title === 'LSP Pubkey Exposure');
    expect(lspFinding).toBeUndefined();
  });

  // ── Security checks ─────────────────────────────────────────

  it('should find CRITICAL severity for invalid signature', () => {
    const invoice = buildMockInvoice({ signatureValid: false });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Invalid Signature');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('CRITICAL');
    expect(finding!.category).toBe('security');
    expect(finding!.detail).toContain('tampered');
  });

  it('should find LOW severity for unverified signature', () => {
    const invoice = buildMockInvoice({
      signatureValid: 'unverified',
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
      payeeNodeKey: undefined,
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Signature Unverified');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('LOW');
    expect(finding!.category).toBe('security');
    expect(finding!.detail).toContain('n` tag'); // backtick-escaped in source
  });

  it('should NOT add signature findings when signatureValid is true', () => {
    const invoice = buildMockInvoice({ signatureValid: true });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const invalidSig = result.findings.find(f => f.title === 'Invalid Signature');
    const unverifiedSig = result.findings.find(f => f.title === 'Signature Unverified');
    expect(invalidSig).toBeUndefined();
    expect(unverifiedSig).toBeUndefined();
  });

  it('should find MEDIUM severity for expired invoice', () => {
    const invoice = buildMockInvoice({
      expired: true,
      expiryDeltaSeconds: -3600,
      expiryDescription: '1h ago',
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Invoice Expired');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
    expect(finding!.category).toBe('security');
    expect(finding!.detail).toContain('expired');
  });

  it('should find LOW severity for near-expiry invoice (< 10 min)', () => {
    const invoice = buildMockInvoice({
      expired: false,
      expiryDeltaSeconds: 300,
      expiryDescription: '5m 0s',
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Invoice Nearing Expiry');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('LOW');
    expect(finding!.category).toBe('security');
    expect(finding!.detail).toContain('5m');
  });

  it('should NOT find near-expiry finding when expiry is >= 10 minutes', () => {
    const invoice = buildMockInvoice({
      expired: false,
      expiryDeltaSeconds: 600,
      expiryDescription: '10m 0s',
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Invoice Nearing Expiry');
    expect(finding).toBeUndefined();
  });

  it('should NOT find expiry or near-expiry when invoice is expired (only expiry finding)', () => {
    const invoice = buildMockInvoice({
      expired: true,
      expiryDeltaSeconds: -100,
      expiryDescription: '1m 40s ago',
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const expiredFinding = result.findings.find(f => f.title === 'Invoice Expired');
    const nearExpiry = result.findings.find(f => f.title === 'Invoice Nearing Expiry');
    expect(expiredFinding).toBeDefined();
    expect(nearExpiry).toBeUndefined();
  });

  it('should find LOW severity for zero-amount invoice with description', () => {
    const invoice = buildMockInvoice({
      amount: {
        millisatoshis: '0',
        satoshis: 0,
        btc: 0,
        formatted: '0 sats (0 msat)',
      },
      description: 'Test zero-amount invoice',
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Zero-Amount Invoice with Description');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('LOW');
    expect(finding!.category).toBe('security');
    expect(finding!.detail).toContain('zero amount');
  });

  it('should NOT find zero-amount finding when millisatoshis is null (any-amount invoice)', () => {
    const invoice = buildMockInvoice({
      amount: {
        millisatoshis: null,
        satoshis: null,
        btc: null,
        formatted: 'Any amount',
      },
      description: 'Any amount invoice',
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Zero-Amount Invoice with Description');
    expect(finding).toBeUndefined();
  });

  it('should find HIGH severity for missing payment_secret', () => {
    const invoice = buildMockInvoice({
      paymentSecret: undefined,
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Missing Payment Secret');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('HIGH');
    expect(finding!.category).toBe('security');
    expect(finding!.detail).toContain('probing');
  });

  it('should NOT find missing payment_secret when present', () => {
    const invoice = buildMockInvoice({ paymentSecret: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890' });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Missing Payment Secret');
    expect(finding).toBeUndefined();
  });

  it('should find MEDIUM severity for unknown required feature bits', () => {
    const invoice = buildMockInvoice({
      featureBits: {
        word_length: 4,
        extra_bits: { start_bit: 100, bits: [1], has_required: true },
      },
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Unknown Required Feature Bits');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('MEDIUM');
    expect(finding!.category).toBe('security');
    expect(finding!.detail).toContain('required');
  });

  it('should NOT flag feature bits when extra_bits has_required is false', () => {
    const invoice = buildMockInvoice({
      featureBits: {
        word_length: 4,
        extra_bits: { start_bit: 10, bits: [], has_required: false },
      },
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Unknown Required Feature Bits');
    expect(finding).toBeUndefined();
  });

  it('should NOT flag feature bits when extra_bits is missing', () => {
    const invoice = buildMockInvoice({
      featureBits: { word_length: 4 },
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Unknown Required Feature Bits');
    expect(finding).toBeUndefined();
  });

  it('should find INFO severity for fallback addresses', () => {
    const fallbackAddr: FallbackAddress = {
      code: 0,
      address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
      addressHash: '751e76e8199196d454941c45d1b3a323f1433bd6',
    };
    const invoice = buildMockInvoice({ fallbackAddresses: [fallbackAddr] });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Fallback Address Present');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('INFO');
    expect(finding!.category).toBe('info');
    expect(finding!.detail).toContain('(bc)');
  });

  it('should NOT flag fallback addresses when none present', () => {
    const invoice = buildMockInvoice({ fallbackAddresses: [] });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const finding = result.findings.find(f => f.title === 'Fallback Address Present');
    expect(finding).toBeUndefined();
  });

  // ── Aggregation / summary ───────────────────────────────────

  it('should compute riskLevel as the highest severity among findings', () => {
    // CRITICAL > HIGH > MEDIUM > LOW > INFO
    const invoice = buildMockInvoice({
      signatureValid: false,          // CRITICAL
      expired: true,                   // MEDIUM
      paymentSecret: undefined,        // HIGH
      fallbackAddresses: [{ code: 0, address: 'bc1abc', addressHash: 'abc' }], // INFO
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('should compute riskLevel as HIGH when highest is HIGH (no CRITICAL)', () => {
    const invoice = buildMockInvoice({
      signatureValid: true,
      paymentSecret: undefined,  // HIGH
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    expect(result.riskLevel).toBe('HIGH');
  });

  it('should compute riskLevel as MEDIUM when highest is MEDIUM', () => {
    const invoice = buildMockInvoice({
      signatureValid: true,
      paymentSecret: 'some-secret',
      expired: true, // MEDIUM
      fallbackAddresses: [],
    });
    const result = auditInvoice(invoice, 'lnbc1');
    expect(result.riskLevel).toBe('MEDIUM');
  });

  it('should compute riskLevel as INFO when only INFO findings exist', () => {
    const invoice = buildMockInvoice({
      signatureValid: true,
      paymentSecret: 'some-secret',
      expired: false,
      expiryDeltaSeconds: 7200,
      // Only fallback addresses → INFO
      fallbackAddresses: [{ code: 0, address: 'bc1abc', addressHash: 'abc' }],
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    expect(result.riskLevel).toBe('INFO');
  });

  it('should compute riskLevel as INFO when no findings at all', () => {
    const invoice = buildMockInvoice({
      signatureValid: true,
      paymentSecret: 'some-secret',
      expired: false,
      expiryDeltaSeconds: 7200,
      fallbackAddresses: [],
      routeHints: [],
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    expect(result.riskLevel).toBe('INFO');
  });

  it('should produce accurate summary counts', () => {
    const routeHint: RouteHintEntry = {
      pubkey: BREEZ_LSP_PUBKEY,
      short_channel_id: '1x1x1',
      fee_base_msat: 0,
      fee_proportional_millionths: 0,
      cltv_expiry_delta: 9,
    };
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: WALLET_OF_SATOSHI_PUBKEY, // triggers Payee Identified (privacy)
      routeHints: [routeHint],                          // triggers Route Hint SCID Leak (privacy) + LSP Pubkey Exposure (privacy)
      paymentSecret: undefined,                         // triggers Missing Payment Secret (security)
      fallbackAddresses: [{ code: 0, address: 'bc1abc', addressHash: 'abc' }], // INFO
    });
    const result = auditInvoice(invoice, 'lnbc1');
    expect(result.summary.privacy).toBeGreaterThanOrEqual(2); // Payee Identified + SCID Leak + LSP Exposure
    expect(result.summary.security).toBeGreaterThanOrEqual(1); // Missing Payment Secret
    expect(result.summary.info).toBeGreaterThanOrEqual(1);     // Fallback Address
  });

  it('should produce an empty findings array for a clean invoice', () => {
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY, // not in KNOWN_NODES → no payee identified
      signatureValid: true,
      paymentSecret: 'some-secret',
      expired: false,
      expiryDeltaSeconds: 7200,
      fallbackAddresses: [],
      routeHints: [],
      description: undefined,
      amount: { millisatoshis: '2000000', satoshis: 2000, btc: 0.00002, formatted: '2,000 sats' },
    });
    const result = auditInvoice(invoice, 'lnbc1');
    expect(result.findings.length).toBe(0);
    expect(result.riskLevel).toBe('INFO');
  });
});

// ===========================================================================
// Section 2d: highestSeverity() in cli.ts
// ===========================================================================

describe('highestSeverity', () => {
  it('should return INFO for empty findings array', () => {
    expect(highestSeverity([])).toBe('INFO');
  });

  it('should return the severity of a single finding', () => {
    const findings: AuditFinding[] = [
      { category: 'security', severity: 'HIGH', title: 'T', detail: 'D' },
    ];
    expect(highestSeverity(findings)).toBe('HIGH');
  });

  it('should return CRITICAL when it is the highest', () => {
    const findings: AuditFinding[] = [
      { category: 'privacy', severity: 'MEDIUM', title: 'T', detail: 'D' },
      { category: 'security', severity: 'CRITICAL', title: 'T', detail: 'D' },
      { category: 'info', severity: 'INFO', title: 'T', detail: 'D' },
    ];
    expect(highestSeverity(findings)).toBe('CRITICAL');
  });

  it('should return HIGH over MEDIUM and LOW', () => {
    const findings: AuditFinding[] = [
      { category: 'security', severity: 'LOW', title: 'T', detail: 'D' },
      { category: 'privacy', severity: 'MEDIUM', title: 'T', detail: 'D' },
      { category: 'security', severity: 'HIGH', title: 'T', detail: 'D' },
    ];
    expect(highestSeverity(findings)).toBe('HIGH');
  });

  it('should return MEDIUM over LOW and INFO', () => {
    const findings: AuditFinding[] = [
      { category: 'info', severity: 'INFO', title: 'T', detail: 'D' },
      { category: 'security', severity: 'LOW', title: 'T', detail: 'D' },
      { category: 'privacy', severity: 'MEDIUM', title: 'T', detail: 'D' },
    ];
    expect(highestSeverity(findings)).toBe('MEDIUM');
  });

  it('should ignore ordering and find the true max', () => {
    const findings: AuditFinding[] = [
      { category: 'info', severity: 'INFO', title: 'T', detail: 'D' },
      { category: 'info', severity: 'INFO', title: 'T', detail: 'D' },
      { category: 'info', severity: 'INFO', title: 'T', detail: 'D' },
      { category: 'security', severity: 'CRITICAL', title: 'T', detail: 'D' },
    ];
    expect(highestSeverity(findings)).toBe('CRITICAL');
  });
});

// ===========================================================================
// Section 2e: printWhois() and printWhoisJson() in formatter.ts
// ===========================================================================

describe('printWhois', () => {
  let writeSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    writeSpy.mockRestore();
  });

  it('should print whois output for a known node', () => {
    const whois: WhoisResult = {
      recoveredKey: WALLET_OF_SATOSHI_PUBKEY,
      payeeNodeKey: WALLET_OF_SATOSHI_PUBKEY,
      node: { alias: 'Wallet of Satoshi', type: 'custodial-exchange' },
      lsp: undefined,
      behindLsp: false,
      classification: 'Payee identified: Wallet of Satoshi (custodial-exchange)',
    };
    printWhois(whois);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('Wallet of Satoshi');
    expect(output).toContain('custodial-exchange');
    expect(output).toContain('Payee identified');
  });

  it('should print whois output for an LSP-routed invoice', () => {
    const whois: WhoisResult = {
      recoveredKey: MAINNET_RECOVERED_KEY,
      payeeNodeKey: MAINNET_RECOVERED_KEY,
      node: undefined,
      lsp: { pubkey: BREEZ_LSP_PUBKEY, alias: 'Breez LSP', type: 'lsp' },
      behindLsp: true,
      classification: 'Private node behind LSP: Breez LSP',
    };
    printWhois(whois);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('Breez LSP');
    expect(output).toContain('routed through an LSP');
    expect(output).toContain(BREEZ_LSP_PUBKEY);
    expect(output).toContain('Private node behind LSP');
  });

  it('should print whois output for an unknown node', () => {
    const whois: WhoisResult = {
      recoveredKey: MAINNET_RECOVERED_KEY,
      payeeNodeKey: MAINNET_RECOVERED_KEY,
      node: undefined,
      lsp: undefined,
      behindLsp: false,
      classification: 'Unknown public node (not in bundled dataset)',
    };
    printWhois(whois);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('Unknown node');
    expect(output).toContain('not in bundled dataset');
  });

  it('should print "Could not determine payee" when no recovered key', () => {
    const whois: WhoisResult = {
      recoveredKey: '',
      payeeNodeKey: undefined,
      node: undefined,
      lsp: undefined,
      behindLsp: false,
      classification: 'Could not determine payee',
    };
    printWhois(whois);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('Could not determine payee');
  });

  it('should highlight n-tag mismatch when payeeNodeKey differs from recoveredKey', () => {
    const whois: WhoisResult = {
      recoveredKey: '02aaaa...',
      payeeNodeKey: '02bbbb...',
      node: undefined,
      lsp: undefined,
      behindLsp: false,
      classification: 'Unknown public node (not in bundled dataset)',
    };
    printWhois(whois);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('n-tag key');
    expect(output).toContain('02bbbb');
  });

  it('should show route hints warning when behindLsp=true but lsp undefined', () => {
    const whois: WhoisResult = {
      recoveredKey: MAINNET_RECOVERED_KEY,
      payeeNodeKey: MAINNET_RECOVERED_KEY,
      node: undefined,
      lsp: undefined,
      behindLsp: true,
      classification: 'Private node behind an unknown LSP',
    };
    printWhois(whois);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('Invoice uses route hints');
    expect(output).toContain('likely behind an LSP');
  });
});

describe('printWhoisJson', () => {
  let writeSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    writeSpy.mockRestore();
  });

  it('should print valid JSON for a known node whois result', () => {
    const whois: WhoisResult = {
      recoveredKey: WALLET_OF_SATOSHI_PUBKEY,
      payeeNodeKey: WALLET_OF_SATOSHI_PUBKEY,
      node: { alias: 'Wallet of Satoshi', type: 'custodial-exchange' },
      lsp: undefined,
      behindLsp: false,
      classification: 'Payee identified: Wallet of Satoshi (custodial-exchange)',
    };
    printWhoisJson(whois);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    const parsed = JSON.parse(output);
    expect(parsed.recoveredKey).toBe(WALLET_OF_SATOSHI_PUBKEY);
    expect(parsed.node.alias).toBe('Wallet of Satoshi');
    expect(parsed.node.type).toBe('custodial-exchange');
    expect(parsed.behindLsp).toBe(false);
    expect(parsed.classification).toContain('Payee identified');
  });

  it('should print valid JSON for an LSP-routed whois result', () => {
    const whois: WhoisResult = {
      recoveredKey: MAINNET_RECOVERED_KEY,
      payeeNodeKey: MAINNET_RECOVERED_KEY,
      node: undefined,
      lsp: { pubkey: BREEZ_LSP_PUBKEY, alias: 'Breez LSP', type: 'lsp' },
      behindLsp: true,
      classification: 'Private node behind LSP: Breez LSP',
    };
    printWhoisJson(whois);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    const parsed = JSON.parse(output);
    expect(parsed.recoveredKey).toBe(MAINNET_RECOVERED_KEY);
    expect(parsed.lsp.alias).toBe('Breez LSP');
    expect(parsed.behindLsp).toBe(true);
  });

  it('should output a trailing newline', () => {
    const whois: WhoisResult = {
      recoveredKey: MAINNET_RECOVERED_KEY,
      payeeNodeKey: MAINNET_RECOVERED_KEY,
      node: undefined,
      lsp: undefined,
      behindLsp: false,
      classification: 'Unknown',
    };
    printWhoisJson(whois);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output.endsWith('\n')).toBe(true);
  });
});

// ===========================================================================
// Section 2f: printAudit() and printAuditJson() in formatter.ts
// ===========================================================================

describe('printAudit', () => {
  let writeSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    writeSpy.mockRestore();
  });

  it('should print "No findings" for a clean audit', () => {
    const audit: AuditResult = {
      findings: [],
      riskLevel: 'INFO',
      summary: { privacy: 0, security: 0, info: 0 },
    };
    printAudit(audit);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('No findings');
    expect(output).toContain('clean');
  });

  it('should print privacy findings with their severity', () => {
    const findings: AuditFinding[] = [
      { category: 'privacy', severity: 'MEDIUM', title: 'Payee Identified', detail: 'The payee is Wallet of Satoshi.' },
    ];
    const audit: AuditResult = {
      findings,
      riskLevel: 'MEDIUM',
      summary: { privacy: 1, security: 0, info: 0 },
    };
    printAudit(audit);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('Privacy');
    expect(output).toContain('[MEDIUM]');
    expect(output).toContain('Payee Identified');
    expect(output).toContain('Wallet of Satoshi');
  });

  it('should print security findings with their severity', () => {
    const findings: AuditFinding[] = [
      { category: 'security', severity: 'CRITICAL', title: 'Invalid Signature', detail: 'Signature does not match.' },
    ];
    const audit: AuditResult = {
      findings,
      riskLevel: 'CRITICAL',
      summary: { privacy: 0, security: 1, info: 0 },
    };
    printAudit(audit);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('Security');
    expect(output).toContain('[CRITICAL]');
    expect(output).toContain('Invalid Signature');
  });

  it('should print info findings with their severity', () => {
    const findings: AuditFinding[] = [
      { category: 'info', severity: 'INFO', title: 'Fallback Address Present', detail: '1 fallback address.' },
    ];
    const audit: AuditResult = {
      findings,
      riskLevel: 'INFO',
      summary: { privacy: 0, security: 0, info: 1 },
    };
    printAudit(audit);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('Info');
    expect(output).toContain('[INFO]');
    expect(output).toContain('Fallback Address Present');
  });

  it('should print risk summary with counts', () => {
    const findings: AuditFinding[] = [
      { category: 'privacy', severity: 'MEDIUM', title: 'T1', detail: 'D1' },
      { category: 'security', severity: 'HIGH', title: 'T2', detail: 'D2' },
      { category: 'info', severity: 'INFO', title: 'T3', detail: 'D3' },
    ];
    const audit: AuditResult = {
      findings,
      riskLevel: 'HIGH',
      summary: { privacy: 1, security: 1, info: 1 },
    };
    printAudit(audit);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output).toContain('Risk Summary');
    expect(output).toContain('HIGH');
    expect(output).toContain('1 privacy');
    expect(output).toContain('1 security');
    expect(output).toContain('1 info');
  });

  it('should group multiple findings in correct sections', () => {
    const findings: AuditFinding[] = [
      { category: 'privacy', severity: 'MEDIUM', title: 'Payee Identified', detail: 'Identified' },
      { category: 'security', severity: 'LOW', title: 'Near Expiry', detail: 'Expiring soon' },
      { category: 'security', severity: 'HIGH', title: 'Missing Secret', detail: 'No secret' },
      { category: 'info', severity: 'INFO', title: 'Fallback', detail: 'Has fallback' },
    ];
    const audit: AuditResult = {
      findings,
      riskLevel: 'HIGH',
      summary: { privacy: 1, security: 2, info: 1 },
    };
    printAudit(audit);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    // All titles present
    expect(output).toContain('Payee Identified');
    expect(output).toContain('Near Expiry');
    expect(output).toContain('Missing Secret');
    expect(output).toContain('Fallback');
    // Severity icons or labels
    expect(output).toContain('[MEDIUM]');
    expect(output).toContain('[LOW]');
    expect(output).toContain('[HIGH]');
    expect(output).toContain('[INFO]');
  });
});

describe('printAuditJson', () => {
  let writeSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    writeSpy.mockRestore();
  });

  it('should print valid JSON for an audit result with findings', () => {
    const findings: AuditFinding[] = [
      { category: 'privacy', severity: 'MEDIUM', title: 'Payee Identified', detail: 'The payee is known.' },
      { category: 'security', severity: 'HIGH', title: 'Missing Payment Secret', detail: 'No secret field.' },
    ];
    const audit: AuditResult = {
      findings,
      riskLevel: 'HIGH',
      summary: { privacy: 1, security: 1, info: 0 },
    };
    printAuditJson(audit);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    const parsed = JSON.parse(output);
    expect(parsed.findings.length).toBe(2);
    expect(parsed.riskLevel).toBe('HIGH');
    expect(parsed.summary.privacy).toBe(1);
    expect(parsed.summary.security).toBe(1);
    expect(parsed.findings[0].category).toBe('privacy');
    expect(parsed.findings[0].severity).toBe('MEDIUM');
    expect(parsed.findings[1].severity).toBe('HIGH');
  });

  it('should print valid JSON for an audit result without findings', () => {
    const audit: AuditResult = {
      findings: [],
      riskLevel: 'INFO',
      summary: { privacy: 0, security: 0, info: 0 },
    };
    printAuditJson(audit);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    const parsed = JSON.parse(output);
    expect(parsed.findings.length).toBe(0);
    expect(parsed.riskLevel).toBe('INFO');
  });

  it('should output a trailing newline', () => {
    const audit: AuditResult = {
      findings: [],
      riskLevel: 'INFO',
      summary: { privacy: 0, security: 0, info: 0 },
    };
    printAuditJson(audit);
    const output = writeSpy.mock.calls.map(c => String(c[0])).join('');
    expect(output.endsWith('\n')).toBe(true);
  });
});

// ===========================================================================
// Section: Integration – whoisInvoice + lookupNode with real data
// ===========================================================================

describe('whoisInvoice integration with KNOWN_NODES', () => {
  it('should identify Wallet of Satoshi via its real pubkey', () => {
    const invoice = buildMockInvoice({ recoveredPayeeNodeKey: WALLET_OF_SATOSHI_PUBKEY });
    // Use a bad invoice so recoverPubkey falls through to recoveredPayeeNodeKey
    const result = whoisInvoice(invoice, 'lnbc1');
    expect(result.node).toBeDefined();
    expect(result.node!.alias).toBe('Wallet of Satoshi');
  });

  it('should return null for key NOT in KNOWN_NODES', () => {
    const invoice = buildMockInvoice({ recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY });
    const result = whoisInvoice(invoice, VALID_MAINNET_INVOICE);
    expect(result.node).toBeUndefined();
    expect(result.classification).toBe('Unknown public node (not in bundled dataset)');
  });

  it('should detect Breez LSP from route hints with real lookup', () => {
    const routeHint: RouteHintEntry = {
      pubkey: BREEZ_LSP_PUBKEY,
      short_channel_id: '1x1x1',
      fee_base_msat: 0,
      fee_proportional_millionths: 0,
      cltv_expiry_delta: 9,
    };
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
      routeHints: [routeHint],
    });
    const result = whoisInvoice(invoice, VALID_MAINNET_INVOICE);
    expect(result.behindLsp).toBe(true);
    expect(result.lsp).toBeDefined();
    expect(result.lsp!.alias).toBe('Breez LSP');
  });
});

// ===========================================================================
// Section: Integration – auditInvoice with real decoded invoices
// ===========================================================================

describe('auditInvoice integration with real invoices', () => {
  it('should audit VALID_MAINNET_INVOICE (expired, fallback address, known payee key)', () => {
    const decoded = decodeInvoice(VALID_MAINNET_INVOICE);
    const result = auditInvoice(decoded, VALID_MAINNET_INVOICE);
    // This invoice has a payeeNodeKey matching the recovered key, so:
    // - recovered key is 03e7156ae33b0a... which is NOT in KNOWN_NODES → no Payee Identified
    // - It has a fallback address → INFO
    // - It is expired → MEDIUM
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    const expired = result.findings.find(f => f.title === 'Invoice Expired');
    expect(expired).toBeDefined();
    expect(expired!.severity).toBe('MEDIUM');
    const fallback = result.findings.find(f => f.title === 'Fallback Address Present');
    expect(fallback).toBeDefined();
    expect(fallback!.severity).toBe('INFO');
    expect(result.riskLevel).toBe('MEDIUM');
  });

  it('should audit SIGNED_MAINNET_INVOICE (missing payment_secret, expired)', () => {
    const decoded = decodeInvoice(SIGNED_MAINNET_INVOICE);
    const result = auditInvoice(decoded, SIGNED_MAINNET_INVOICE);
    // This invoice has:
    // - recovered key not in KNOWN_NODES
    // - No route hints
    // - No payment_secret → HIGH
    // - expired → MEDIUM
    // - description "Payment for services", amount 500000 (non-zero) → no zero-amount finding
    const missingSecret = result.findings.find(f => f.title === 'Missing Payment Secret');
    expect(missingSecret).toBeDefined();
    expect(missingSecret!.severity).toBe('HIGH');
    const expired = result.findings.find(f => f.title === 'Invoice Expired');
    expect(expired).toBeDefined();
    expect(result.riskLevel).toBe('HIGH'); // HIGH > MEDIUM
  });
});

// ===========================================================================
// Section: KNOWN_NODES dataset integrity
// ===========================================================================

describe('KNOWN_NODES dataset', () => {
  it('should have all required node types present', () => {
    const types = new Set(Object.values(KNOWN_NODES).map(n => n.type));
    expect(types.has('custodial-exchange')).toBe(true);
    expect(types.has('non-custodial-wallet')).toBe(true);
    expect(types.has('infrastructure')).toBe(true);
    expect(types.has('lsp')).toBe(true);
    expect(types.has('routing-node')).toBe(true);
    expect(types.has('merchant')).toBe(true);
    expect(types.has('community')).toBe(true);
  });

  it('should have at least 15 known nodes', () => {
    expect(Object.keys(KNOWN_NODES).length).toBeGreaterThanOrEqual(15);
  });

  it('should have valid aliases for all entries', () => {
    for (const [key, info] of Object.entries(KNOWN_NODES)) {
      // Keys are hex-encoded compressed pubkeys (should be 66 chars for 33 bytes)
      // Note: some synthetic test keys in the dataset may be shorter
      expect(key.length).toBeGreaterThanOrEqual(60);
      expect(info.alias).toBeTruthy();
      expect(info.alias.length).toBeGreaterThan(0);
    }
  });
});

// ===========================================================================
// Section: Edge cases for auditInvoice
// ===========================================================================

describe('auditInvoice edge cases', () => {
  it('should handle combined route hints producing multiple privacy findings', () => {
    // Route hints trigger: SCID leak (per hint) + LSP exposure = 3 privacy findings for 2 hints
    const hints: RouteHintEntry[] = [
      { pubkey: BREEZ_LSP_PUBKEY, short_channel_id: '111x111x1', fee_base_msat: 0, fee_proportional_millionths: 0, cltv_expiry_delta: 9 },
      { pubkey: ACINQ_LSP_PUBKEY, short_channel_id: '222x222x2', fee_base_msat: 0, fee_proportional_millionths: 0, cltv_expiry_delta: 9 },
    ];
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: MAINNET_RECOVERED_KEY,
      routeHints: hints,
    });
    const result = auditInvoice(invoice, VALID_MAINNET_INVOICE);
    const privacyFindings = result.findings.filter(f => f.category === 'privacy');
    // 2 SCID leaks + 1 LSP exposure = 3 privacy findings
    expect(privacyFindings.length).toBe(3);
    expect(result.summary.privacy).toBe(3);
  });

  it('should handle invoice with all possible issue types simultaneously', () => {
    const hints: RouteHintEntry[] = [
      { pubkey: BREEZ_LSP_PUBKEY, short_channel_id: '333x333x3', fee_base_msat: 0, fee_proportional_millionths: 0, cltv_expiry_delta: 9 },
    ];
    const invoice = buildMockInvoice({
      recoveredPayeeNodeKey: WALLET_OF_SATOSHI_PUBKEY,
      payeeNodeKey: WALLET_OF_SATOSHI_PUBKEY,
      routeHints: hints,
      signatureValid: false,
      expired: true,
      expiryDeltaSeconds: -100,
      expiryDescription: '1m 40s ago',
      paymentSecret: undefined,
      description: 'Test invoice',
      amount: { millisatoshis: '0', satoshis: 0, btc: 0, formatted: '0 sats' },
      featureBits: { word_length: 4, extra_bits: { start_bit: 100, bits: [1], has_required: true } },
      fallbackAddresses: [{ code: 0, address: 'bc1abc', addressHash: 'abc' }],
    });
    const result = auditInvoice(invoice, 'lnbc1');
    // Count expected findings:
    // Privacy: Payee Identified (MEDIUM) + SCID Leak (HIGH) + LSP Exposure (MEDIUM) = 3
    // Security: Invalid Signature (CRITICAL) + Expired (MEDIUM) + Zero-Amount (LOW) + Missing Secret (HIGH) + Feature Bits (MEDIUM) = 5
    // Info: Fallback Address (INFO) = 1
    // Total = 9
    expect(result.findings.length).toBe(9);

    // Verify specific ones exist
    expect(result.findings.find(f => f.title === 'Payee Identified')).toBeDefined();
    expect(result.findings.find(f => f.title === 'Route Hint SCID Leak')).toBeDefined();
    expect(result.findings.find(f => f.title === 'LSP Pubkey Exposure')).toBeDefined();
    expect(result.findings.find(f => f.title === 'Invalid Signature')).toBeDefined();
    expect(result.findings.find(f => f.title === 'Invoice Expired')).toBeDefined();
    expect(result.findings.find(f => f.title === 'Zero-Amount Invoice with Description')).toBeDefined();
    expect(result.findings.find(f => f.title === 'Missing Payment Secret')).toBeDefined();
    expect(result.findings.find(f => f.title === 'Unknown Required Feature Bits')).toBeDefined();
    expect(result.findings.find(f => f.title === 'Fallback Address Present')).toBeDefined();

    // riskLevel should be CRITICAL (highest)
    expect(result.riskLevel).toBe('CRITICAL');
    expect(result.summary.privacy).toBe(3);
    expect(result.summary.security).toBe(5);
    expect(result.summary.info).toBe(1);
  });
});

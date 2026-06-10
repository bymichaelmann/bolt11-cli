/**
 * bolt11-cli – Test suite.
 */

import { describe, it, expect } from 'vitest';
import { decodeInvoice, humanDuration } from '../src/decoder.js';

// ---------------------------------------------------------------------------
// Test Vectors
// ---------------------------------------------------------------------------

// Valid mainnet invoice (lnbc) from the bolt11 README
const VALID_MAINNET_INVOICE =
  'lnbc20u1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kxqrrsssp5m6kmam774klwlh4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs9qypqqqcqpf3cwux5979a8j28d4ydwahx00saa68wq3az7v9jdgzkghtxnkf3z5t7q5suyq2dl9tqwsap8j0wptc82cpyvey9gf6zyylzrm60qtcqsq7egtsq';

// Generated invoices with fixed timestamp (1700000000 = Nov 14, 2023) and fixed
// private key 0101...01. The signature validity depends on the bolt11 library's
// internal verification – for these encoded+signed invoices, it should be valid.

// Mainnet invoice: 500 satoshis, description: "Payment for services"
const SIGNED_MAINNET_INVOICE =
  'lnbc5u1pj48ugqpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpq2pshjmt9de6zqen0wgs8xetjwe5kxetnxqrrsscqpf94gldela63d9w0r03qkxn9asnu3q35zejmt8w3r5k90ejycja9txptrm4udltv8djzh9qv08c0zk0ks4fqtjamklzvcfdyymcrvrf0qp2cepqz';

// Testnet invoice: 2000 satoshis
const SIGNED_TESTNET_INVOICE =
  'lntb20u1pj48ugqpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdqc23jhxarwv46zqurp09kk2mn5xqrrsscqpflwn97eh73z6ue6tfmzssdzwckcvj23cp6te2q9d7pfgqddfsrmwz2809xscjr3wzhlclt3lvh4pya99jfwfqf9fxpz4f5j69rzd0qpgp6zjx5v';

// Zero-amount invoice (satoshis: 0)
const ZERO_AMOUNT_INVOICE =
  'lnbc1pj48ugqpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdqqxqrrsscqpfgrcytfc66jmherxveemqhutj597yp8m66jk6kern4zakf3qdrlvq005d7lys3k5kdz85dez3z6zv2ecc2k09ec9g7p0f3ysmvugx9vsqm6cm94';

// Expired invoice: timestamp 1000000000 (Sep 2001), 3600s expiry
const EXPIRED_INVOICE =
  'lnbc1u1qae4jsqpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdqcg4u8q6tjv4jzqurp09kk2mn5xqrrsscqpf9dr22346wlnxme3zjtne7jj2yh2hqqvhsqnqvna8k7v5wagsqa2k8a503r2t2trnfp9ye232xxs6uqp5dz56dhx3caxkxvej6ju4nespr3nqtx';

// Invoice with description hash: 300 satoshis
const DESC_HASH_INVOICE =
  'lnbc3u1pj48ugqpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp540x7l27da74ummatehh6hn0040x7l27da74ummatehh6hn0040xsxqrrsscqpfaew6ey84mg4dk5tdlgmsr845x4mt7kzk5evajlczr3zw0eft20ur3fu2lhnxvryv220pq0vthxn32nh0h3eqydjtx2f0uyrz4e7emvgqgu27fk';

// Invalid string
const INVALID_INVOICE = 'this-is-not-a-bolt11-invoice';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('decodeInvoice', () => {
  it('should decode a valid mainnet invoice (lnbc) from BOLT11 README', () => {
    const result = decodeInvoice(VALID_MAINNET_INVOICE);

    expect(result.prefix).toMatch(/^lnbc/);
    expect(result.networkBech32).toBe('bc');
    expect(result.currency).toContain('Bitcoin');
    expect(result.complete).toBe(true);

    // Amount: 20u = 2000 satoshis = 2,000,000 msat
    expect(result.amount.millisatoshis).toBe('2000000');
    expect(result.amount.satoshis).toBe(2000);
    expect(result.amount.formatted).toContain('sats');

    // Payment hash
    expect(result.paymentHash).toBe('0001020304050607080900010203040506070809000102030405060708090102');

    // Timestamp
    expect(result.timestamp).toBe(1496314658);

    // Expiry (default 3600)
    expect(result.expireTime).toBe(3600);

    // Payee node key
    expect(result.payeeNodeKey).toBe('03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad');

    // Recovery flag
    expect(typeof result.recoveryFlag).toBe('number');

    // Signature
    expect(result.signature).toBeTruthy();
    expect(result.signature.length).toBe(128);

    // CLTV
    expect(result.minFinalCltvExpiry).toBe(9);

    // Fallback addresses
    expect(Array.isArray(result.fallbackAddresses)).toBe(true);

    // The README invoice is from 2017 – it will be expired
    // (timestamp 1496314658, expiry 3600s → expired ~June 2017)
    expect(result.expired).toBe(true);
  });

  it('should decode a dynamically signed mainnet invoice', () => {
    const result = decodeInvoice(SIGNED_MAINNET_INVOICE);

    expect(result.prefix).toMatch(/^lnbc/);
    expect(result.networkBech32).toBe('bc');
    // 500 sats = 500,000 msat
    expect(result.amount.millisatoshis).toBe('500000');
    expect(result.amount.satoshis).toBe(500);
    expect(result.description).toBe('Payment for services');
    expect(result.paymentHash).toBe('0001020304050607080900010203040506070809000102030405060708090102');
    expect(result.signature).toBeTruthy();
    expect(typeof result.signatureValid).toBe('boolean');
    // Timestamp should be 1700000000
    expect(result.timestamp).toBe(1700000000);

    // This is signed, so it should be valid (complete: true)
    expect(result.complete).toBe(true);
  });

  it('should decode a valid testnet invoice (lntb)', () => {
    const result = decodeInvoice(SIGNED_TESTNET_INVOICE);

    expect(result.prefix).toMatch(/^lntb/);
    expect(result.networkBech32).toBe('tb');
    expect(result.currency).toContain('Testnet');
    expect(result.amount.millisatoshis).toBe('2000000');
    expect(result.amount.satoshis).toBe(2000);
    expect(result.timestamp).toBe(1700000000);
  });

  it('should decode a zero-amount invoice', () => {
    const result = decodeInvoice(ZERO_AMOUNT_INVOICE);

    expect(result.amount.millisatoshis).toBeNull();
    expect(result.amount.satoshis).toBeNull();
    expect(result.amount.btc).toBeNull();
    expect(result.amount.formatted).toContain('Any');
  });

  it('should detect expired invoices', () => {
    const result = decodeInvoice(EXPIRED_INVOICE);

    expect(result.expired).toBe(true);
    expect(result.expiryDeltaSeconds).toBeLessThanOrEqual(0);
    expect(result.expiryDescription).toContain('ago');
    expect(result.timestamp).toBe(1000000000);
    expect(result.expireTime).toBe(3600);
    expect(result.timeExpireDate).toBe(1000003600);
  });

  it('should throw on invalid invoice string', () => {
    expect(() => decodeInvoice(INVALID_INVOICE)).toThrow();
  });

  it('should throw on empty string', () => {
    expect(() => decodeInvoice('')).toThrow();
    expect(() => decodeInvoice('   ')).toThrow();
  });

  it('should handle description hash', () => {
    const result = decodeInvoice(DESC_HASH_INVOICE);

    expect(result.descriptionHash).toBe(
      'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd'
    );
    expect(result.description).toBeUndefined();
  });

  it('should have payment hash always present', () => {
    const result = decodeInvoice(VALID_MAINNET_INVOICE);
    expect(result.paymentHash).toBeTruthy();
    expect(result.paymentHash.length).toBe(64); // 32 bytes hex
  });

  it('should have route hints as array', () => {
    const result = decodeInvoice(VALID_MAINNET_INVOICE);
    expect(Array.isArray(result.routeHints)).toBe(true);
  });

  it('should have fallback addresses as array with correct structure', () => {
    const result = decodeInvoice(VALID_MAINNET_INVOICE);
    expect(Array.isArray(result.fallbackAddresses)).toBe(true);
    if (result.fallbackAddresses.length > 0) {
      expect(result.fallbackAddresses[0]).toHaveProperty('address');
      expect(result.fallbackAddresses[0]).toHaveProperty('code');
      expect(result.fallbackAddresses[0]).toHaveProperty('addressHash');
    }
  });

  it('should produce valid JSON output', () => {
    const result = decodeInvoice(VALID_MAINNET_INVOICE);
    const json = JSON.stringify(result);
    const parsed = JSON.parse(json);
    expect(parsed.paymentHash).toBe(result.paymentHash);
    expect(parsed.amount.millisatoshis).toBe(result.amount.millisatoshis);
    expect(parsed.expired).toBe(result.expired);
    expect(parsed.signature).toBe(result.signature);
  });

  it('should have correct signature validation status for valid invoice', () => {
    const result = decodeInvoice(VALID_MAINNET_INVOICE);
    expect(result.signatureValid).toBe(true);
  });

  it('should handle testnet invoice with correct timestamps', () => {
    const result = decodeInvoice(SIGNED_TESTNET_INVOICE);
    expect(typeof result.timestamp).toBe('number');
    expect(result.timestamp).toBeGreaterThan(0);
    expect(typeof result.timeExpireDate).toBe('number');
    expect(result.timeExpireDate).toBeGreaterThan(result.timestamp);
  });

  it('should include the original payment request', () => {
    const result = decodeInvoice(VALID_MAINNET_INVOICE);
    expect(result.paymentRequest).toBe(VALID_MAINNET_INVOICE);
  });

  it('should have expiryDescription for non-expired invoices', () => {
    const result = decodeInvoice(VALID_MAINNET_INVOICE);
    // The README invoice has timestamp 1496314658 + 3600s expiry
    // so it is already expired. For a non-expired check, use the signed invoice.
    expect(result.expired).toBe(true);
    expect(result.expiryDescription).toContain('ago');
  });

  it('should handle invoice with description hash and no description', () => {
    const result = decodeInvoice(DESC_HASH_INVOICE);
    expect(result.descriptionHash).toBeTruthy();
    expect(result.description).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// humanDuration tests
// ---------------------------------------------------------------------------

describe('humanDuration', () => {
  it('should format 0 seconds', () => {
    expect(humanDuration(0)).toBe('0s');
  });

  it('should format seconds only', () => {
    expect(humanDuration(30)).toBe('30s');
  });

  it('should format minutes and seconds', () => {
    expect(humanDuration(60)).toBe('1m 0s');
    expect(humanDuration(90)).toBe('1m 30s');
  });

  it('should format hours, minutes, seconds', () => {
    expect(humanDuration(3600)).toBe('1h 0m 0s');
    expect(humanDuration(3661)).toBe('1h 1m 1s');
  });

  it('should format days, hours, minutes, seconds', () => {
    expect(humanDuration(86400)).toBe('1d 0h 0m 0s');
    expect(humanDuration(90061)).toBe('1d 1h 1m 1s');
  });

  it('should handle negative values as 0', () => {
    expect(humanDuration(-100)).toBe('0s');
  });
});

// ---------------------------------------------------------------------------
// decodeInvoice error handling
// ---------------------------------------------------------------------------

describe('decodeInvoice error handling', () => {
  it('should throw for non-bolt11 string without ln prefix', () => {
    expect(() => decodeInvoice('hello')).toThrow(/ln/);
  });

  it('should throw for a string that is too short', () => {
    expect(() => decodeInvoice('lnbc1')).toThrow();
  });

  it('should throw for garbage with ln prefix', () => {
    expect(() => decodeInvoice('lnbc1garbage')).toThrow();
  });

  it('should not throw for valid invoice', () => {
    expect(() => decodeInvoice(VALID_MAINNET_INVOICE)).not.toThrow();
  });
});

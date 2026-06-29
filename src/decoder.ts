/**
 * bolt11-cli – Decode and validate BOLT11 invoices.
 */

import { createHash } from 'node:crypto';
import bolt11 from 'bolt11';
import type { PaymentRequestObject, TagsObject, RoutingInfo } from 'bolt11';
import { Signature } from '@noble/secp256k1';
import type {
  DecodedInvoice,
  AmountDisplay,
  RouteHintEntry,
  FallbackAddress,
} from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Network info lookup */
const NETWORKS: Record<string, { currency: string; network: string }> = {
  bc: { currency: 'Bitcoin (BTC)', network: 'mainnet' },
  tb: { currency: 'Bitcoin Testnet (tBTC)', network: 'testnet' },
  regtest: { currency: 'Bitcoin Regtest', network: 'regtest' },
  simnet: { currency: 'Bitcoin Simnet', network: 'simnet' },
  signet: { currency: 'Bitcoin Signet', network: 'signet' },
};

/** Determine currency from bech32 prefix */
function getCurrency(bech32: string): string {
  return NETWORKS[bech32]?.currency ?? `Bech32: ${bech32}`;
}

/** Format an amount display object */
function formatAmount(millisatoshis: string | null): AmountDisplay {
  if (millisatoshis === null) {
    return {
      millisatoshis: null,
      satoshis: null,
      btc: null,
      formatted: 'Any amount',
    };
  }
  const msat = BigInt(millisatoshis);
  const sat = msat / 1000n;
  const btcNum = Number(sat) / 100_000_000;
  const satNum = Number(sat);
  const msatNum = Number(msat);

  const msatStr = msatNum.toLocaleString('en-US');
  const satStr = satNum.toLocaleString('en-US');

  let formatted: string;
  if (btcNum >= 1) {
    formatted = `${btcNum.toFixed(8)} BTC (${satStr} sats / ${msatStr} msat)`;
  } else if (satNum >= 1) {
    formatted = `${satStr} sats (${msatStr} msat)`;
  } else {
    formatted = `${msatStr} msat`;
  }

  return {
    millisatoshis,
    satoshis: msat % 1000n === 0n ? satNum : null,
    btc: satNum > 0 ? btcNum : null,
    formatted,
  };
}

/** Parse route hints from raw bolt11 data */
function parseRouteHints(tags: TagsObject): RouteHintEntry[] {
  const raw = tags.routing_info;
  if (!raw || !Array.isArray(raw)) return [];
  return raw.map((r) => ({
    pubkey: r.pubkey,
    short_channel_id: r.short_channel_id,
    fee_base_msat: r.fee_base_msat,
    fee_proportional_millionths: r.fee_proportional_millionths,
    cltv_expiry_delta: r.cltv_expiry_delta,
  }));
}

/** Parse fallback addresses */
function parseFallbackAddresses(tags: TagsObject): FallbackAddress[] {
  const raw = tags.fallback_address;
  if (!raw) return [];
  return Array.isArray(raw) ? raw : [raw];
}

// ---------------------------------------------------------------------------
// Minimal bech32 decoder (no checksum verification; we only need the 5-bit
// words to reconstruct the signed message).
// ---------------------------------------------------------------------------

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32DecodeWords(invoice: string): { prefix: string; words: number[] } {
  const lowered = invoice.toLowerCase();
  const split = lowered.lastIndexOf('1');
  if (split === -1) throw new Error('No separator');
  const prefix = lowered.slice(0, split);
  const dataPart = lowered.slice(split + 1);
  // Last 6 characters are the checksum – ignore them
  const chars = dataPart.slice(0, -6);
  if (!chars) throw new Error('No data');
  const words = Array.from(chars, (c) => {
    const v = BECH32_CHARSET.indexOf(c);
    if (v === -1) throw new Error(`Invalid bech32 char: ${c}`);
    return v;
  });
  return { prefix, words };
}

// ---------------------------------------------------------------------------
// 5-bit → 8-bit conversion (matches BOLT11 spec's right-padding behaviour)
// ---------------------------------------------------------------------------

/**
 * Convert an array of `inBits`-wide words to `outBits`-wide words.
 * Right-pads with zero bits when leftover data exists (matching the
 * BOLT11 spec's signed-message construction).
 */
function convertBits(data: number[], inBits: number, outBits: number): number[] {
  let value = 0;
  let bits = 0;
  const maxV = (1 << outBits) - 1;
  const result: number[] = [];
  for (let i = 0; i < data.length; ++i) {
    value = (value << inBits) | data[i];
    bits += inBits;
    while (bits >= outBits) {
      bits -= outBits;
      result.push((value >> bits) & maxV);
    }
  }
  if (bits > 0) {
    result.push((value << (outBits - bits)) & maxV);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Signatures – Recover pubkey and verify via @noble/secp256k1
// ---------------------------------------------------------------------------

/**
 * Independently recover the compressed payee public key from the BOLT11
 * signature by reconstructing the signed message per the spec:
 *
 *   message = SHA256( bech32_prefix_utf8 || 5-to-8-bit(data_words) )
 *
 * The last 104 bech32 words (520 bits = 65 bytes) are the signature:
 *   64 bytes = r || s (compact ECDSA signature)
 *   1 byte   = recovery flag (0–3)
 *
 * All words before that form the signed data (timestamp + tags).
 *
 * @param invoice – The raw BOLT11 invoice string
 * @returns Recovered compressed public key (33-byte hex) or null on failure
 */
export function recoverPubkey(invoice: string): string | null {
  try {
    // Bech32-decode the full invoice to get prefix and all 5-bit words
    const { prefix, words } = bech32DecodeWords(invoice);

    // The last 104 words (520 bits = 65 bytes) are the signature
    if (words.length < 104) return null;
    const sigWords = words.slice(-104);
    const dataWords = words.slice(0, -104);

    // Convert data words from 5-bit to 8-bit (with right-padding, per spec)
    const dataBytes = Buffer.from(convertBits(dataWords, 5, 8));

    // Reconstruct the signed message: SHA256(prefix || dataBytes)
    const toSign = Buffer.concat([Buffer.from(prefix, 'utf8'), dataBytes]);
    const msgHash = createHash('sha256').update(toSign).digest();

    // Convert signature words to bytes (65 bytes: 64 r||s + 1 recovery flag)
    const sigBytes = Buffer.from(convertBits(sigWords, 5, 8));
    if (sigBytes.length !== 65) return null;

    const recoveryFlag = sigBytes[64];
    const sig64 = sigBytes.subarray(0, 64);

    if (![0, 1, 2, 3].includes(recoveryFlag)) return null;

    // Recover the public key from signature + message hash
    const sig = Signature.fromCompact(new Uint8Array(sig64));
    const recoveredPoint = sig.addRecoveryBit(recoveryFlag).recoverPublicKey(new Uint8Array(msgHash));

    // Return compressed 33-byte key as hex
    const raw = recoveredPoint.toRawBytes(true);
    return Buffer.from(raw).toString('hex');
  } catch {
    return null;
  }
}

/**
 * Verify a BOLT11 invoice's signature by independently recovering the
 * payee public key using @noble/secp256k1 (from-scratch, no delegation to
 * the bolt11 library).
 *
 * When the invoice carries an explicit `payee_node_key` (`n`) tag, the
 * recovered key is compared against it:
 *   - match    → `signatureValid = true`
 *   - mismatch → `signatureValid = false`
 *
 * When the invoice has **no** `n` tag, the signature is mathematically
 * well-formed (recovery succeeded) but there is no independent reference
 * to cross-check against.  In that case `signatureValid` is set to the
 * string `"unverified"` and the recovered key is still populated so the
 * caller can inspect or look it up externally.
 *
 * @param decoded          – The bolt11-decoded payment request object
 * @param invoiceStr       – The raw invoice string (for reconstructing the message)
 * @param tagPayeeNodeKey  – Value of the `payee_node_key` (`n`) tag from the
 *                           invoice, or undefined when the tag was absent
 * @returns Object with `signatureValid` (boolean | 'unverified' | null) and
 *          optionally `recoveredPayeeNodeKey` (string).
 */
function verifySignature(
  decoded: PaymentRequestObject,
  invoiceStr: string,
  tagPayeeNodeKey?: string,
): { signatureValid: boolean | 'unverified' | null; recoveredPayeeNodeKey?: string } {
  if (!decoded.signature || decoded.recoveryFlag === undefined) {
    return { signatureValid: null };
  }

  const recoveredKey = recoverPubkey(invoiceStr);

  if (recoveredKey === null) {
    return { signatureValid: null };
  }

  // When the invoice has an explicit `n` tag, compare the recovered
  // key against that tag's value (purely from-scratch – no bolt11 crypto).
  if (tagPayeeNodeKey !== undefined) {
    return {
      signatureValid: recoveredKey === tagPayeeNodeKey,
      recoveredPayeeNodeKey: recoveredKey,
    };
  }

  // No `n` tag – recovery succeeded but we have no key to compare against.
  return {
    signatureValid: 'unverified',
    recoveredPayeeNodeKey: recoveredKey,
  };
}

// ---------------------------------------------------------------------------
// Main decode function
// ---------------------------------------------------------------------------

/**
 * Decode and validate a BOLT11 invoice string.
 *
 * @param invoiceStr – Raw invoice string (lnbc…, lntb…, etc.)
 * @returns DecodedInvoice with all fields populated
 * @throws Error on invalid input
 */
export function decodeInvoice(invoiceStr: string): DecodedInvoice {
  const trimmed = invoiceStr.trim();

  if (!trimmed) {
    throw new Error('Empty invoice string');
  }

  // Basic sanity: must start with ln or LN
  if (!/^ln/i.test(trimmed)) {
    throw new Error('Invalid invoice: must start with "ln" prefix');
  }

  let decoded: PaymentRequestObject & { tagsObject: TagsObject };

  try {
    decoded = bolt11.decode(trimmed);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to decode invoice: ${message}`);
  }

  const tags = decoded.tagsObject;
  const networkBech32 = decoded.network?.bech32 ?? 'unknown';
  const prefix = decoded.prefix ?? trimmed.slice(0, trimmed.indexOf('1'));

  // Amount
  const millisatoshis = decoded.millisatoshis ?? null;
  const amount = formatAmount(millisatoshis);

  // Timestamps
  const timestamp = decoded.timestamp ?? 0;
  const timestampString = decoded.timestampString ?? new Date(timestamp * 1000).toISOString();
  const expireTime = tags.expire_time ?? 3600;
  const timeExpireDate = decoded.timeExpireDate ?? (timestamp + expireTime);
  const timeExpireDateString = decoded.timeExpireDateString ?? new Date(timeExpireDate * 1000).toISOString();

  // Expiry
  const now = Math.floor(Date.now() / 1000);
  const expiryDeltaSeconds = timeExpireDate - now;
  const expired = expiryDeltaSeconds <= 0;

  let expiryDescription: string;
  if (expired) {
    const past = Math.abs(expiryDeltaSeconds);
    expiryDescription = humanDuration(past) + ' ago';
  } else {
    expiryDescription = humanDuration(expiryDeltaSeconds);
  }

  // Tags
  const paymentHash = tags.payment_hash ?? '';
  const paymentSecret = tags.payment_secret ?? undefined;
  const description = tags.description ?? undefined;
  const descriptionHash = tags.purpose_commit_hash ?? undefined;
  const payeeNodeKey = decoded.payeeNodeKey ?? tags.payee_node_key ?? undefined;
  const minFinalCltvExpiry = tags.min_final_cltv_expiry ?? 9;

  // Signature – independent recovery via @noble/secp256k1
  const signature = decoded.signature ?? '';
  const recoveryFlag = decoded.recoveryFlag ?? 0;
  const sigResult = verifySignature(decoded, trimmed, decoded.payeeNodeKey ?? tags.payee_node_key);
  const signatureValid = sigResult.signatureValid;
  const recoveredPayeeNodeKey = sigResult.recoveredPayeeNodeKey;

  // Route hints & fallback addresses
  const routeHints = parseRouteHints(tags);
  const fallbackAddresses: FallbackAddress[] = parseFallbackAddresses(tags);

  // Feature bits
  const featureBits = tags.feature_bits as Record<string, unknown> ?? {};

  return {
    paymentRequest: trimmed,
    complete: decoded.complete ?? false,
    prefix,
    networkBech32,
    currency: getCurrency(networkBech32),
    amount,
    timestamp,
    timestampString,
    timeExpireDate,
    timeExpireDateString,
    paymentHash,
    paymentSecret,
    description,
    descriptionHash,
    expireTime,
    payeeNodeKey,
    signature,
    recoveryFlag,
    recoveredPayeeNodeKey,
    fallbackAddresses,
    routeHints,
    featureBits,
    minFinalCltvExpiry,
    expired,
    expiryDeltaSeconds,
    expiryDescription,
    signatureValid,
  };
}

// ---------------------------------------------------------------------------
// Duration helper
// ---------------------------------------------------------------------------

/**
 * Convert seconds to a human-readable duration string.
 */
export function humanDuration(totalSeconds: number): string {
  if (totalSeconds < 0) totalSeconds = 0;

  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = Math.floor(totalSeconds % 60);

  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0 || days > 0) parts.push(`${hours}h`);
  if (minutes > 0 || hours > 0 || days > 0) parts.push(`${minutes}m`);
  parts.push(`${seconds}s`);

  return parts.join(' ');
}

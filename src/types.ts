/**
 * bolt11-cli – Type definitions
 */

/** Human-readable display amounts */
export interface AmountDisplay {
  /** Raw millisatoshis as string (or null for zero-amount invoices) */
  millisatoshis: string | null;
  /** Optional satoshi amount (set only for whole satoshi amounts) */
  satoshis: number | null;
  /** BTC value */
  btc: number | null;
  /** Formatted string like "0.002 BTC (200,000 sats / 200,000,000 msat)" */
  formatted: string;
}

/** Route hint entry */
export interface RouteHintEntry {
  pubkey: string;
  short_channel_id: string;
  fee_base_msat: number;
  fee_proportional_millionths: number;
  cltv_expiry_delta: number;
}

/** Fallback address */
export interface FallbackAddress {
  code: number;
  address: string;
  addressHash: string;
}

/** Decoded invoice – clean representation */
export interface DecodedInvoice {
  /** The original invoice string */
  paymentRequest: string;
  /** Whether decoding was complete */
  complete: boolean;
  /** Human-readable prefix (e.g. lnbc20u) */
  prefix: string;
  /** Network prefix (bc, tb, etc.) */
  networkBech32: string;
  /** Currency based on network */
  currency: string;
  /** Amount information */
  amount: AmountDisplay;
  /** Timestamp (unix seconds) */
  timestamp: number;
  /** ISO timestamp string */
  timestampString: string;
  /** Expiry date (unix seconds) */
  timeExpireDate: number;
  /** ISO expiry string */
  timeExpireDateString: string;
  /** Payment hash (hex) */
  paymentHash: string;
  /** Payment secret (hex) - optional */
  paymentSecret?: string;
  /** Description string - optional */
  description?: string;
  /** Description hash (purpose_commit_hash) - optional */
  descriptionHash?: string;
  /** Expiry in seconds */
  expireTime: number;
  /** Payee node public key (hex) - optional */
  payeeNodeKey?: string;
  /** Signature (hex) */
  signature: string;
  /** Recovery flag for signature */
  recoveryFlag: number;
  /** Fallback addresses */
  fallbackAddresses: FallbackAddress[];
  /** Route hints */
  routeHints: RouteHintEntry[];
  /** Feature bits */
  featureBits: Record<string, unknown>;
  /** Minimum final CLTV expiry */
  minFinalCltvExpiry: number;
  /** Whether the invoice is expired */
  expired: boolean;
  /** Seconds until (or since) expiry */
  expiryDeltaSeconds: number;
  /** Human-readable expiry description */
  expiryDescription: string;
  /** Whether signature is valid (null if cannot verify) */
  signatureValid: boolean | null;
}

/** Options for display */
export interface DisplayOptions {
  /** Output as JSON */
  json: boolean;
  /** Verbose output (for validate command) */
  verbose: boolean;
}

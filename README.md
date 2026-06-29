# ⚡ bolt11-cli

**Decode, validate, and audit Bitcoin Lightning Network BOLT11 payment invoices from the command line.**

`bolt11-cli` is a fast, typed CLI tool for parsing, displaying, validating, and auditing BOLT11 Lightning invoices (`lnbc…`, `lntb…`). It decodes every field, **independently recovers the payee public key via from-scratch ECDSA** (using audited @noble/secp256k1 — not delegating to the decoder library), identifies who you're paying, and produces a structured privacy + security audit — **all offline, no data leaves your machine.**

---

## Install

```bash
npm install -g bolt11-cli
```

Or run directly from source:

```bash
git clone https://github.com/michaelmann/bolt11-cli.git
cd bolt11-cli
npm install && npm run build
node bin/bolt11.js
```

---

## Usage

### Decode an invoice (default)

```bash
bolt11 lnbc20u1pvjluez…                                      # inline argument
bolt11 decode lnbc20u1pvjluez…                                # explicit command
echo "lnbc20u1pvjluez…" | bolt11                              # piped from stdin
bolt11 --file invoice.txt                                      # read from file
```

### Pretty-print with recovered payee key

The default output now includes the **independently recovered payee public key** next to the explicit `n`-tag (if present), with a green checkmark when they match:

```
 ⚡ BOLT11 Lightning Invoice
 ────────────────────────────────────────────────────────

 ━━━ Overview ━━━

  Currency                       Bitcoin (BTC)
  Network                        bc
  Amount                         2,000 sats (2,000,000 msat)
  Complete                       ✓

 ━━━ Timing ━━━
  ...

 ━━━ Cryptography ━━━

  Recovery Flag                  0
  Signature                      304402203b14a0...
  Signature Valid                ✓ Valid signature
  Recovered Key                  03e7156ae33b...9dd9ad
```

### JSON output

```bash
bolt11 decode --json lnbc20u1pvjluez… | jq '.amount'
```

```json
{
  "recoveredPayeeNodeKey": "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad",
  "signatureValid": true,
  "amount": { ... }
}
```

### Validate only

```bash
bolt11 validate lnbc20u1pvjluez…        # silent, exit code only
bolt11 validate --verbose lnbc20u1…     # shows ✓/✗
```

### Who am I paying? — `bolt11 whois`

Identify the payee of any invoice by recovering the payee public key from the signature and looking it up in a bundled dataset of well-known Lightning nodes:

```bash
bolt11 whois lnbc20u1pvjluez…
```

Output:
```
 🔍 Who Am I Paying?
 ────────────────────────────────────────────────────────

  You are likely paying: Wallet of Satoshi
  Type:                    custodial-exchange

  Classification: Payee identified: Wallet of Satoshi (custodial-exchange)
  Recovered key:  03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad
```

Detection works for:
- **Custodial exchanges** — Wallet of Satoshi, Kraken, Bitfinex, Blink
- **Non-custodial wallets** — ACINQ/Phoenix, Breez
- **LSP-routed invoices** — detects when the payee is behind an LSP (Breez LSP, ACINQ LSP, Lightning Labs Pool, etc.)
- **Merchants** — Bitrefill, BTC Pay Server
- **Community** — Stacker News, Geyser Fund

The bundled dataset ships with ~20 well-known nodes. Offline-first: full operation with zero network.

### Invoice Privacy & Security Audit — `bolt11 audit`

Perform a structured privacy + security audit on any invoice:

```bash
bolt11 audit lnbc20u1pvjluez…
```

```
 🛡  Invoice Privacy & Security Audit
 ────────────────────────────────────────────────────────

 ━━━ Privacy ━━━

  ⚠ [MEDIUM] Payee Identified
    The invoice payee was identified as "Wallet of Satoshi" (custodial-exchange).
    Your payment counterparty is known.

  ✗ [HIGH] Route Hint SCID Leak
    Route hint contains short_channel_id 12345:67890:1.
    If this is an unannounced channel, the SCID may reveal on-chain UTXO info.

 ━━━ Security ━━━

  ⚠ [MEDIUM] Invoice Expired
    This invoice expired 38721d ago. Expired invoices should not be paid.

  ✗ [HIGH] Missing Payment Secret
    No `payment_secret` — vendor uses legacy format. Probing/MPP risk.

 ━━━ Risk Summary ━━━

  Overall risk:  HIGH
  Findings:      2 privacy, 2 security, 0 info
```

**Checks performed:**

| Category | Check | Severity |
|----------|-------|----------|
| Privacy | Payee identifiable | MEDIUM |
| Privacy | Route hint SCID leak (on-chain UTXO exposure) | HIGH |
| Privacy | LSP pubkey exposure | MEDIUM |
| Security | Invalid signature | CRITICAL |
| Security | Expired / near-expiry | MEDIUM |
| Security | Amount vs description sanity | LOW |
| Security | Missing payment_secret (probing/MPP risk) | HIGH |
| Security | Unknown required feature bits | MEDIUM |
| Info | Fallback address network mismatch | INFO |

Exit code 4 when findings beyond INFO severity exist — ideal for CI pipelines.

```bash
bolt11 audit --json lnbc20u1pvjluez… | jq '.riskLevel'
# "HIGH"
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Valid invoice |
| 1    | Decode error |
| 2    | Expired |
| 3    | Signature invalid |
| 4    | Audit findings present (beyond INFO) |

---

## Why offline matters

Web invoice decoders and services like Lightning Detective / Invoice Detective require you to paste your invoice into a website — leaking the payment hash, amount, and metadata to a third party. **bolt11-cli does everything offline.** The payee identification and audit run entirely on your machine:

- **ECDSA pubkey recovery** — from-scratch using @noble/secp256k1, no delegation to the decoder library
- **BOLT11 conformance** — independently verified against the spec test vectors
- **Bundled node dataset** — no network calls for payee identification

---

## Wallet developer workflow

```bash
# Audit invoice before forwarding to user
bolt11 audit --json invoice.txt

# Check who the payee is
bolt11 whois --json invoice.txt | jq '.node.alias'

# Automatic CI validation
bolt11 validate invoice.txt || echo "Invoice may be compromised"
```

---

## Merchant workflow

```bash
# Verify invoice before displaying to customer
bolt11 decode --json lnbc… | jq '{amount, description, expired}'

# Generate invoice acceptance report
bolt11 audit lnbc… --json > invoice-audit.json
```

---

## Features

- **Full BOLT11 decoding** — HRP, amount (msat/sat/BTC), currency, timestamp, payment hash, description / description hash, expiry, payee node key, fallback addresses, route hints, min_final_cltv_expiry, feature bits
- **Independent ECDSA pubkey recovery** — from-scratch using @noble/secp256k1 (audited, verified against spec test vectors)
- **Signature verification** — cross-checks recovered key against the `n` tag per spec
- **Payee identification** — `bolt11 whois` with bundled known-nodes dataset
- **Privacy & security audit** — `bolt11 audit` with structured findings, risk summary, JSON output
- **Expiry checking** — shows remaining time, red status for expired invoices, exit code 2
- **Colorful TUI** — chalk-based sections, emojis, alignment
- **JSON mode** — `--json` for piping to `jq` or other tools
- **Multiple input modes** — argument, stdin, file (`--file`)
- **Silent validation** — `bolt11 validate` exits with code only, use `--verbose` for details

---

## API (programmatic use)

```typescript
import { decodeInvoice } from 'bolt11-cli';

const invoice = decodeInvoice('lnbc20u1pvjluez…');
console.log(invoice.amount.formatted);            // "2,000 sats (2,000,000 msat)"
console.log(invoice.signatureValid);               // true / false / 'unverified' / null
console.log(invoice.recoveredPayeeNodeKey);        // hex pubkey recovered from signature
console.log(invoice.expired);                      // true / false
```

---

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run tests (33 conformance + integration tests)
npm test

# Run tests in watch mode
npm run test:watch
```

### Requirements

- Node.js 18+
- npm

### Test suite

```bash
npm test
```

Tests cover:
- Valid mainnet and testnet invoices
- Zero-amount invoices
- Expired invoice detection
- JSON output validity
- Invalid invoice error handling
- Description hash parsing
- Duration formatting
- **ECDSA pubkey recovery conformance** (from-scratch vs spec vectors)
- **Signature verification** (cross-check against `n` tag)
- **Recovery edge cases** (malformed/truncated invoices)

---

## License

MIT © [Michael Mann](mailto:michaelmann@disroot.org)

---

## Related

- [BOLT #11 specification](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
- [bolt11 npm package](https://npm.im/bolt11) — the decoding library used for field parsing
- [@noble/secp256k1](https://github.com/paulmillr/noble-secp256k1) — audited ECDSA implementation used for independent pubkey recovery
- [Invoice Detective](https://detective.lipa.dev) — web-based invoice analysis (requires sharing your invoice)

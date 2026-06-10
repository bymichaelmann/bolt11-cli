# ⚡ bolt11-cli

**Decode and validate Bitcoin Lightning Network BOLT11 payment invoices from the command line.**

`bolt11-cli` is a fast, typed CLI tool for parsing, displaying, and validating BOLT11 Lightning invoices (`lnbc…`, `lntb…`). It decodes every field, verifies the cryptographic signature, checks expiry, and outputs either a colorful terminal view or structured JSON.

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

### Pretty-print

![screenshot](docs/screenshot.png)

The default output shows all fields with emojis, colored sections, and alignment:

```
 ⚡ BOLT11 Lightning Invoice
 ────────────────────────────────────────────────────────

 ━━━ Overview ━━━

  Currency                       Bitcoin (BTC)
  Network                        bc
  Amount                         2,000 sats (2,000,000 msat)
  Complete                       ✓

 ━━━ Timing ━━━

  Created                        2017-06-01T10:57:38.000Z (1496314658)
  Expires                        2017-06-01T11:57:38.000Z (1496318258)
  Expiry Duration                3600s
  Status                         ✗ EXPIRED
  Overdue by                     … ago
 …
```

Expired invoices are shown in red/amber. Valid signatures are marked with a green ✓.

### JSON output

```bash
bolt11 decode --json lnbc20u1pvjluez… | jq '.amount'
```

```json
{
  "paymentHash": "0001020304050607080900010203040506070809000102030405060708090102",
  "amount": {
    "millisatoshis": "2000000",
    "satoshis": 2000,
    "btc": 0.00002,
    "formatted": "2,000 sats (2,000,000 msat)"
  },
  "expired": true,
  "signatureValid": true,
  ...
}
```

### Validate only

```bash
bolt11 validate lnbc20u1pvjluez…        # silent, exit code only
bolt11 validate --verbose lnbc20u1…     # shows ✓/✗
```

Exit codes:

| Code | Meaning              |
|------|----------------------|
| 0    | Valid invoice        |
| 1    | Decode error         |
| 2    | Expired              |
| 3    | Signature invalid    |

### Help

```bash
bolt11 --help
bolt11 decode --help
bolt11 validate --help
bolt11 --version
```

---

## Features

- **Full BOLT11 decoding** — HRP, amount (msat/sat/BTC), currency, timestamp, payment hash, description / description hash, expiry, payee node key, fallback addresses, route hints (compact format), min_final_cltv_expiry, feature bits
- **Signature verification** — recovers the public key and validates the signed payload
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
console.log(invoice.amount.formatted);     // "2,000 sats (2,000,000 msat)"
console.log(invoice.signatureValid);       // true / false / null
console.log(invoice.expired);              // true / false
```

---

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run tests
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

---

## License

MIT © [Michael Mann](mailto:michaelmann@disroot.org)

---

## Related

- [BOLT #11 specification](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
- [bolt11 npm package](https://npm.im/bolt11) — the decoding library used under the hood

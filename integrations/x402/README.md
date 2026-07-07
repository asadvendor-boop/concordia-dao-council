# x402 Governance Report Adapter

The core proof for Concordia remains the Casper Testnet governance receipt transaction. The x402 path is implemented as a paid specialist-report boundary that can run in local demo mode or real facilitator mode.

Current implementation:

- `shared/x402_payments.py` builds HTTP payment-request headers.
- `/x402/governance-report` returns HTTP `402` until an `X-Payment` proof is supplied.
- Demo mode validates a deterministic local HMAC-style proof.
- Real mode is enabled with `X402_SETTLEMENT_MODE=real` and `X402_FACILITATOR_URL`.
- Real mode calls facilitator `/verify` and `/settle`.
- Verification/settlement retries are bounded to absorb Casper provider indexer lag.

Configuration:

```bash
X402_SETTLEMENT_MODE=real
X402_FACILITATOR_URL=https://your-facilitator.example
X402_FACILITATOR_TOKEN=optional-token
X402_PAYMENT_ADDRESS=your-casper-payment-address
X402_PAYMENT_AMOUNT=1000000
X402_PAYMENT_NETWORK=casper-testnet
X402_MAX_ATTEMPTS=4
X402_RETRY_DELAY_SECONDS=5
```

No production payment private key is embedded in the repository.

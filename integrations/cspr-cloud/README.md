# CSPR.cloud Adapter

`shared/cspr_cloud.py` contains credential-gated helpers for account, deploy, rate, stream, and node endpoint context.

Local behavior:

- Without `CSPR_CLOUD_ACCESS_TOKEN`, helpers return deterministic local context and label responses as `cspr.cloud.mock`.
- With a valid token and API URL, helpers perform REST reads against the configured CSPR.cloud endpoint.

Concordia's final proof does not rely on mocked CSPR.cloud values. The proof path is the Casper Testnet governance receipt transaction returned by Locke.

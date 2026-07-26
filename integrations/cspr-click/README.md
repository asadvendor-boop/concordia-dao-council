# CSPR.click Browser Signing Path

Concordia exposes a browser-wallet signing intent for the production custody path. The live qualification proof can use the configured Testnet Locke custody signer, but the dashboard Proof Center and API expose the unsigned typed envelope that an authorized signer can approve through CSPR.click / Casper Wallet.

Implemented paths:

- `GET /cspr-click/unsigned-receipt/{proposal_id}` returns contract hash, entry point, typed runtime args, and the receipt payload.
- Dashboard Proof Center loads `https://sdk.cspr.click/sdk-v1/csprclick-sdk.js` and attempts a wallet signing request when the user has a compatible wallet/session.
- If no wallet is available, the UI reports that explicitly instead of fabricating a signature.

The repository does not store private keys. The production path is: backend packages the exact unsigned envelope, a multisig signer approves in the browser wallet, and the signed transaction is broadcast to Casper Testnet.

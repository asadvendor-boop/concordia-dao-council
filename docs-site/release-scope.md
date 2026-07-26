# V1.5 Release Scope

This page is the claim boundary for Concordia V1.5.

## Included

- V1 council, transcript, policy, dissent, human approval, and replay behavior
- V1 evidence, proof, judge, JSON, PDF, CSV, certificate, IPFS, and CSPR.live
  surfaces
- canonical receipt `e926582f…d852`
- recorded quorum rejection `6280b8e1…7431` and acceptance `9d631fe1…2928`
- supplemental recorded Testnet receipts
- SafePay Lite as recorded native-CSPR evidence under the apex
- `@concordia-dao/verify` 0.1.4 as a provenance-strengthened V1-first 0.1.3 compatibility superset

## Excluded

- **Casper-native x402 v2 is implemented** as an HTTP 402 payment request,
  payment intent, and native-transfer verification on Testnet.
- **A later official facilitator service and successful external-provider
  settlement are not shipped or claimed.**
- **Mainnet has not been executed.**
- **Governance v3 is excluded from V1.5.**
- No seven-upgrade V2 product claim is made.
- SafePay Lite remains recorded native-CSPR evidence; no live external SafePay
  provider, escrow, refund, marketplace, or WCSPR claim is made.

Historical V2/V3 files retained for npm compatibility are fixtures and parser
assets. They remain off public product promotion and do not alter the V1
runtime.

## Publication gates

Source copy is not hosted proof. Final release claims require:

1. exact candidate CI and docs build;
2. main-only Pages deployment bound to the release SHA;
3. CodeQL default-setup and Dependabot review with no unresolved High-or-greater
   alerts;
4. npm 0.1.4 publication from the exact public `main` tip with `gitHead` and OIDC provenance;
5. clean-consumer API, CLI, signature, and V1 fixture verification; and
6. a hosted crawl of the complete reviewer surface.

Until a gate is observed, report it as pending rather than inferred.

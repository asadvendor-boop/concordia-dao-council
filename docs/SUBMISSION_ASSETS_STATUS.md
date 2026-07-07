# Concordia Submission Assets Status

Generated: 2026-07-01

This file separates verified engineering proof from publication assets that must be supplied after the public repo and demo video are created.

## Ready Technical Assets

| Asset | Status | Evidence |
|---|---|---|
| Live app | Ready | https://concordia.47.84.232.193.sslip.io/dashboard/judge |
| Canonical reviewer receipt | Ready | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Supplemental dynamic lifecycle proof | Ready | `DAO-PROP-DYN-002` -> `68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0` |
| Supplemental quorum proof | Ready | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| Supplemental Odra topology genesis | Ready | CouncilRegistry representative `register_agent`, TreasuryPolicy `validate_allocation`, and CardIndexLedger `seal_card_root` install/call hashes in `artifacts/live/odra-topology-genesis-proof.json` |
| Browser wallet receipt | Ready | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| SafePay Lite x402 proof | Ready | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive | Ready | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |
| Proof pack | Ready | `artifacts/live/live-proof-pack-current.json` |
| Verifier script | Ready | `scripts/verify_concordia_receipt.py` |
| Certificate | Ready | `artifacts/live/certificate-current.html` and `artifacts/live/certificate-current.pdf` |
| Launch roadmap | Ready | `docs/LAUNCH_ROADMAP.md` |
| Demo video | Published | https://www.youtube.com/watch?v=GU01V83Jrko |
| DoraHacks submission text | Ready | `docs/DORAHACKS_SUBMISSION_TEXT.md` |
| Technical jury note | Ready | `docs/TECHNICAL_JURY_NOTE.md` and `https://concordia.47.84.232.193.sslip.io/technical-jury-note` |

## External Publication Assets

These live outside the repository and are referenced here for submission.

| Asset | Status | Required Action |
|---|---|---|
| Public GitHub repository URL | Published | https://github.com/asadvendor-boop/concordia-dao-council |
| Public demo video URL | Published | https://www.youtube.com/watch?v=GU01V83Jrko |
| X/Twitter launch post URL | Published | https://x.com/ConcordiaDAO/status/2074438324769689653 |
| Telegram/Discord/community URL | Optional / pending | Create or link the community channel if used. |

## Honest Boundary For Odra Topology

The canonical reviewer proof uses the Jun 29 v1 Odra `GovernanceReceipt` receipt anchor. The Jun 30 v2 quorum-enabled GovernanceReceipt package powers the live-complete quorum exercise. The auxiliary `CouncilRegistry`, `TreasuryPolicy`, and `CardIndexLedger` modules are captured as supplemental topology genesis proof in `artifacts/live/odra-topology-genesis-proof.json`: CouncilRegistry through a representative `register_agent` call, TreasuryPolicy through `validate_allocation`, and CardIndexLedger through `seal_card_root`.

The topology genesis proof is supplemental. It proves auxiliary module execution, but it does not replace the canonical reviewer receipt or claim Concordia is a fully productized four-contract DAO suite.

The canonical reviewer proof is frozen for reproducibility. Dynamic proposals are preview/execution-ready unless fully evidenced and signed; full cross-contract production enforcement is roadmap, not overclaimed.

# INTERFACE MANIFEST — WP3 (approval boundary, demo capability, room identity)

- Producer branch: `claude/finals-product-security`
- Producer commit: `d096403`
- Rooted at freeze: `concordia-g1-freeze-v2.0-a` (`b24c0409`)
- Spec authority: `handoff/G1_INTERFACE_SPEC.md` §12 (Approval boundary v1 / Demo capability v1 / Room identity v1), §14
- Status of my lane: 59 new AU/DM/RM tests green (x3 stable runs); freeze suite 16/16.

All items below are changes in **Codex-owned files** that I cannot edit. My lane
is committed and self-consistent; these are what Codex must apply for full
integration. Grouped by file.

## gateway/database.py — fold demo ledger DDL into init_db()
Currently created lazily + idempotently by `gateway/routes/demo_cleanup.py::ensure_demo_tables`
on the shared routes connection (CREATE TABLE IF NOT EXISTS). Please fold into `init_db()`:
- `demo_capabilities(capability_id PK, scenario_id, client_binding_hash, nonce_hash, issued_at, expires_at, demo_run_id, consumed_at, response_status, response_json)`
- `demo_runs(demo_run_id, proposal_id, scenario_id, is_demo, created_at, PK(demo_run_id, proposal_id))`
- Optional later: `is_demo` / `demo_run_id` columns on `proposals` (today provenance lives in `demo_runs` keyed by proposal_id, which the spec permits).

## gateway/app.py
- `:393-395` lifespan warning reads `os.getenv('APPROVAL_UI_CSRF_SECRET')` and falsely warns "approval UI disabled" when only `APPROVAL_UI_CSRF_SECRET_FILE` is set. Switch to file-aware loading (same semantics as `approve_ui._load_secret` / `shared.runtime_secrets.read_secret`).
- `:95` decide fate of `load_dotenv('/etc/concordia/approval.env')` now that approve_ui is `_FILE`-only in production.

## gateway/auth.py + gateway/routes/submission.py — GATEWAY_SECRET→'gateway' full-ACL fallback
- Global removal of the `GATEWAY_SECRET → 'gateway'` full-ACL fallback for **agent** traffic (`auth.py:51-54`, duplicated at `submission.py:187-202`).
- WP3 slice already implemented in `rooms.py`: gateway-role message posting returns 403 in production mode (`APP_ENV=production/prod` without `CONCORDIA_TEST_MODE`); non-production keeps matrix behavior. The global removal has blast radius across submission.py / authorization.py / nonce.py / app.py where the 'gateway' role is relied on — coordinate.
- Note: `auth.py:46-49` maps `PROPOSAL_ROOM_API_KEY` to a scribe fallback; under the frozen matrix scribe has no room ops, so that fallback is now inert for rooms (awareness only).

## tests/test_concordia_core.py — Codex owns migration (§14)
- `~:1830 test_demo_cleanup_detaches_preserved_rooms_before_deleting_proposals` now fails `TypeError` (remove_demo_proposals requires `demo_run_id`; asserted the removed `DAO-PROP-%` prefix deletion). Replacement coverage exists in `tests/test_demo_capability.py` (DM-07/DM-08/no-prefix). This is the single sanctioned break from WP3.

## Compose / secrets (WP10)
- Provision `/run/secrets/demo_capability_hmac_secret` (≥32 random bytes; **MUST differ** from operator + approval secrets — gateway fails closed 503 on reuse/short).
- Mount `/run/secrets/dashboard_demo_gateway_token` for **both** gateway (`DASHBOARD_DEMO_GATEWAY_TOKEN_FILE`) and dashboard services.
- Add the two NEW approval docker secrets `approval_ui_user` + `approval_ui_approver_id` (compose currently mounts only proxy_secret / bcrypt_hash / csrf_secret; all five `_FILE` names now required in production).
- Ensure `POST /internal/demo/capability` and `POST /internal/demo/activate` are **NOT** routed through Caddy (internal network only).

## Caddy (WP10)
- `/approve*` handler must add `basic_auth` bound to the bcrypt hash AND strip + overwrite `X-Proxy-Secret` from a server-side secret (never forward caller-supplied). Route `APPROVAL_PROXY_SECRET` into the Caddy container. The direct gateway `/approve` route must not be publicly routable. Gateway-side AU-01..06 assume this overwrite exists at the hosted layer.

## dashboard/app/_components/ConcordiaApp.js (Codex's WP7 lane — cross-lane note)
- `:1024-1041` still POSTs `{scenario_type}` (including a `reset` scenario) to `/api/demo/activate`. Migrate to the two-step capability flow: `POST /api/demo/capability {scenario_id}` → `POST /api/demo/activate {capability, scenario_id}` (same-origin cookie handled automatically), and **remove the reset button** — the public reset path no longer exists anywhere.

## agents/locke/__init__.py (Codex)
- `:607-655` operator join calls: re-adding recorder is now an idempotent no-op (auto-joined at room creation); the NEW scribe invite returns 403 `join_target_not_permitted` (frozen matrix has no scribe row; call is best-effort try/except so the receipt path degrades gracefully). Decide: amend the matrix for Wells' optional governance-summary room flow, or deprecate it. Scribe keys now have no room operations at all.

## Cleanup invocation (Codex decision)
- `remove_demo_proposals(db, demo_run_id)` is function-only by design (no public/HTTP surface). Operator runbooks that used `POST /demo/reset` must call it server-side, or Codex adds an internal operator-token cleanup endpoint if wanted.

## Deviations from spec I made (for Codex review)
- Message identity fields: schema says caller-supplied `sender_id/sender_role/sender_type` "forbidden" (400); implemented **reject-on-conflict** (400 `identity_fields_are_server_derived`) while accepting values exactly equal to server-derived identity — required because Codex-owned `shared/proposal_room.py` always transmits these fields. Stored identity is always server-derived.
- Participant `role` field: **ignored** (server-derived) rather than rejected — recorder sends `role=agent_id` junk on every add_participant; rejecting would break the live demo pipeline.
- Idempotent re-join: adding an already-member participant returns 200 for any room member regardless of matrix (grants nothing new; keeps Locke's operator receipt-publish re-add of recorder alive).
- AU-08: non-allowlisted/unconfigured approver keeps existing 500 (preserved exact authenticate order + status codes).
- Legacy operator-token `POST /demo/trigger` retained (server-side tooling, not the public path); now shares the capability executor, records demo_run_id+is_demo, mints `DAO-DEMO-` ids.
- Capability status codes chosen where schema was silent: 401 invalid_capability, 403 scenario_mismatch/client_binding_mismatch/capability_expired, 429 throttled (checked before consumption), 503 secret misconfiguration/reuse.
- `demo_capabilities.response_status` extra column so idempotent replay reproduces non-200 honest-failure responses. Failed pipeline runs consume the capability; browser requests a fresh one to retry.

## Open questions for Codex
- Effective demo concurrency is 1 (preserved single `_trigger_lock`), stricter than schema `maximum_concurrent_runs=2` — harmless; ack?
- Capability **issuance** has no dedicated rate limit (only activation is limited); existing `RateLimitMiddleware` (600/min) covers internal endpoints — want issuance-specific limits?
- `__Host-` cookie requires HTTPS (Secure); local plain-HTTP dev drops it — deploy-profile concern, not a code defect.

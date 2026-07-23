-- 0002: append-only durable journal of every credentialed upstream /settle
-- call. One row per EVENT, never mutated: `request_started` is committed
-- (synchronous=FULL) BEFORE any network I/O, and exactly one terminal event
-- (`response_observed` on a 2xx read, `request_failed` otherwise) may follow.
-- UPDATE and DELETE always abort — evidence is only ever appended.
--
-- The migration is idempotent (IF NOT EXISTS throughout) so re-applying it on
-- an existing volume is a no-op.

CREATE TABLE IF NOT EXISTS x402_upstream_settle_calls (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL CHECK (event_type IN
    ('request_started', 'response_observed', 'request_failed')),
  call_id TEXT NOT NULL CHECK (call_id GLOB
    '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'),
  network TEXT NOT NULL,
  wcspr_contract TEXT NOT NULL,
  signed_payment_payload_hash TEXT NOT NULL,
  payer_account_hash TEXT NOT NULL,
  authorization_nonce TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  envelope_hash TEXT NOT NULL,
  request_method TEXT NOT NULL,
  request_url TEXT NOT NULL,
  request_headers_json TEXT NOT NULL,
  request_body TEXT NOT NULL,
  request_body_sha256 TEXT NOT NULL,
  response_status INTEGER,
  response_headers_json TEXT,
  response_body TEXT,
  response_body_sha256 TEXT,
  failure_code TEXT,
  observed_at TEXT NOT NULL
);

-- Append-only: any mutation of recorded evidence aborts.
CREATE TRIGGER IF NOT EXISTS x402_upstream_settle_calls_no_update
BEFORE UPDATE ON x402_upstream_settle_calls
BEGIN
  SELECT RAISE(ABORT, 'x402_upstream_settle_calls_append_only');
END;

CREATE TRIGGER IF NOT EXISTS x402_upstream_settle_calls_no_delete
BEFORE DELETE ON x402_upstream_settle_calls
BEGIN
  SELECT RAISE(ABORT, 'x402_upstream_settle_calls_append_only');
END;

-- Exactly one start and at most one terminal per call.
CREATE UNIQUE INDEX IF NOT EXISTS x402_settle_one_start_per_call
  ON x402_upstream_settle_calls (call_id)
  WHERE event_type = 'request_started';

CREATE UNIQUE INDEX IF NOT EXISTS x402_settle_one_terminal_per_call
  ON x402_upstream_settle_calls (call_id)
  WHERE event_type IN ('response_observed', 'request_failed');

-- The ledger's exclusive-submission gate promises at most ONE /settle per
-- authorization and per signed payload, EVER; the journal enforces the same
-- promise independently at the evidence layer.
CREATE UNIQUE INDEX IF NOT EXISTS x402_settle_one_start_per_authorization
  ON x402_upstream_settle_calls
    (network, wcspr_contract, payer_account_hash, authorization_nonce)
  WHERE event_type = 'request_started';

CREATE UNIQUE INDEX IF NOT EXISTS x402_settle_one_start_per_payload
  ON x402_upstream_settle_calls (network, signed_payment_payload_hash)
  WHERE event_type = 'request_started';

-- A terminal event must follow a start for the SAME call and carry the
-- identical binding: a terminal with no matching start (or a drifted
-- binding field) aborts, so an outcome can never be attributed to a call
-- that was not journaled first.
CREATE TRIGGER IF NOT EXISTS x402_settle_terminal_matches_start
BEFORE INSERT ON x402_upstream_settle_calls
WHEN NEW.event_type IN ('response_observed', 'request_failed')
BEGIN
  SELECT RAISE(ABORT, 'x402_settle_terminal_without_matching_start')
  WHERE NOT EXISTS (
    SELECT 1 FROM x402_upstream_settle_calls
    WHERE event_type = 'request_started'
      AND call_id = NEW.call_id
      AND network = NEW.network
      AND wcspr_contract = NEW.wcspr_contract
      AND signed_payment_payload_hash = NEW.signed_payment_payload_hash
      AND payer_account_hash = NEW.payer_account_hash
      AND authorization_nonce = NEW.authorization_nonce
      AND resource_id = NEW.resource_id
      AND action_id = NEW.action_id
      AND envelope_hash = NEW.envelope_hash
      AND request_method = NEW.request_method
      AND request_url = NEW.request_url
      AND request_body_sha256 = NEW.request_body_sha256
  );
END;

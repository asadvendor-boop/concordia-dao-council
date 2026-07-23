BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS x402_upstream_settle_calls (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL CHECK (event_type IN ('request_started','response_observed','request_failed')),
  call_id TEXT NOT NULL CHECK (length(call_id) = 64 AND call_id NOT GLOB '*[^0-9a-f]*'),
  network TEXT NOT NULL CHECK (network = 'casper:casper-test'),
  wcspr_contract TEXT NOT NULL CHECK (length(wcspr_contract) = 64 AND wcspr_contract NOT GLOB '*[^0-9a-f]*'),
  signed_payment_payload_hash TEXT NOT NULL CHECK (length(signed_payment_payload_hash) = 64 AND signed_payment_payload_hash NOT GLOB '*[^0-9a-f]*'),
  payer_account_hash TEXT NOT NULL CHECK (length(payer_account_hash) = 64 AND payer_account_hash NOT GLOB '*[^0-9a-f]*'),
  authorization_nonce TEXT NOT NULL CHECK (length(authorization_nonce) = 64 AND authorization_nonce NOT GLOB '*[^0-9a-f]*'),
  resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 128),
  action_id TEXT NOT NULL CHECK (length(action_id) = 64 AND action_id NOT GLOB '*[^0-9a-f]*'),
  envelope_hash TEXT NOT NULL CHECK (length(envelope_hash) = 64 AND envelope_hash NOT GLOB '*[^0-9a-f]*'),
  request_method TEXT,
  request_url TEXT,
  request_headers_canonical_json BLOB,
  request_body BLOB,
  request_body_sha256 TEXT,
  response_status INTEGER,
  response_headers_canonical_json BLOB,
  response_body BLOB,
  response_body_sha256 TEXT,
  failure_code TEXT,
  observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 20 AND 32),
  CHECK (
    (event_type = 'request_started'
      AND request_method = 'POST'
      AND request_url = 'https://x402-facilitator.cspr.cloud/settle'
      AND typeof(request_headers_canonical_json) = 'blob'
      AND length(request_headers_canonical_json) BETWEEN 2 AND 4096
      AND typeof(request_body) = 'blob'
      AND length(request_body) BETWEEN 2 AND 65536
      AND length(request_body_sha256) = 64
      AND request_body_sha256 NOT GLOB '*[^0-9a-f]*'
      AND response_status IS NULL
      AND response_headers_canonical_json IS NULL
      AND response_body IS NULL
      AND response_body_sha256 IS NULL
      AND failure_code IS NULL)
    OR
    (event_type = 'response_observed'
      AND request_method IS NULL
      AND request_url IS NULL
      AND request_headers_canonical_json IS NULL
      AND request_body IS NULL
      AND request_body_sha256 IS NULL
      AND response_status = 200
      AND typeof(response_headers_canonical_json) = 'blob'
      AND length(response_headers_canonical_json) BETWEEN 2 AND 4096
      AND typeof(response_body) = 'blob'
      AND length(response_body) BETWEEN 2 AND 65536
      AND length(response_body_sha256) = 64
      AND response_body_sha256 NOT GLOB '*[^0-9a-f]*'
      AND failure_code IS NULL)
    OR
    (event_type = 'request_failed'
      AND request_method IS NULL
      AND request_url IS NULL
      AND request_headers_canonical_json IS NULL
      AND request_body IS NULL
      AND request_body_sha256 IS NULL
      AND (response_status IS NULL OR response_status BETWEEN 400 AND 599)
      AND response_headers_canonical_json IS NULL
      AND response_body IS NULL
      AND response_body_sha256 IS NULL
      AND length(failure_code) BETWEEN 1 AND 64)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS x402_upstream_settle_calls_one_start
  ON x402_upstream_settle_calls(call_id) WHERE event_type = 'request_started';
CREATE UNIQUE INDEX IF NOT EXISTS x402_upstream_settle_calls_one_terminal
  ON x402_upstream_settle_calls(call_id) WHERE event_type IN ('response_observed','request_failed');
CREATE UNIQUE INDEX IF NOT EXISTS x402_upstream_settle_calls_authorization_once
  ON x402_upstream_settle_calls(network,wcspr_contract,payer_account_hash,authorization_nonce)
  WHERE event_type = 'request_started';
CREATE UNIQUE INDEX IF NOT EXISTS x402_upstream_settle_calls_payload_once
  ON x402_upstream_settle_calls(network,signed_payment_payload_hash)
  WHERE event_type = 'request_started';
CREATE TRIGGER IF NOT EXISTS x402_upstream_settle_calls_terminal_binding
BEFORE INSERT ON x402_upstream_settle_calls
WHEN NEW.event_type IN ('response_observed','request_failed')
BEGIN
  SELECT RAISE(ABORT, 'x402_settle_journal_orphan_or_binding_mismatch')
  WHERE NOT EXISTS (
    SELECT 1 FROM x402_upstream_settle_calls AS started
    WHERE started.event_type = 'request_started'
      AND started.call_id = NEW.call_id
      AND started.network = NEW.network
      AND started.wcspr_contract = NEW.wcspr_contract
      AND started.signed_payment_payload_hash = NEW.signed_payment_payload_hash
      AND started.payer_account_hash = NEW.payer_account_hash
      AND started.authorization_nonce = NEW.authorization_nonce
      AND started.resource_id = NEW.resource_id
      AND started.action_id = NEW.action_id
      AND started.envelope_hash = NEW.envelope_hash
  );
END;
CREATE TRIGGER IF NOT EXISTS x402_upstream_settle_calls_no_update
BEFORE UPDATE ON x402_upstream_settle_calls
BEGIN
  SELECT RAISE(ABORT, 'x402_settle_journal_append_only');
END;
CREATE TRIGGER IF NOT EXISTS x402_upstream_settle_calls_no_delete
BEFORE DELETE ON x402_upstream_settle_calls
BEGIN
  SELECT RAISE(ABORT, 'x402_settle_journal_append_only');
END;
COMMIT;

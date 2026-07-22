-- SafePay Lite supplemental v2 durable ledger (G1 frozen schema).
-- Frozen tables/columns per handoff/G1_CROSS_LANE_SCHEMAS.json safepay_v2:
--   safepay_reports, safepay_quotes, payment_consumptions,
--   safepay_quote_rate_limits, safepay_quote_issue_reservations.
-- safepay_redemption_observations is a provider-internal append-only table
-- powering honest evidence derivation (never authoritative booleans).

CREATE TABLE IF NOT EXISTS safepay_reports (
  report_hash TEXT PRIMARY KEY,
  report_media_type TEXT NOT NULL CHECK(report_media_type = 'application/json'),
  report_bytes BLOB NOT NULL CHECK(length(report_bytes) <= 262144),
  decoded_length INTEGER NOT NULL CHECK(decoded_length = length(report_bytes) AND decoded_length >= 0 AND decoded_length <= 262144),
  created_at INTEGER NOT NULL CHECK(created_at >= 0)
);

CREATE TABLE IF NOT EXISTS safepay_quotes (
  quote_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  network TEXT NOT NULL,
  payee_account_hash TEXT NOT NULL,
  amount_motes TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  report_version TEXT NOT NULL,
  report_hash TEXT NOT NULL REFERENCES safepay_reports(report_hash),
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  quote_nonce TEXT NOT NULL UNIQUE,
  quote_hash TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_safepay_quotes_expires_at ON safepay_quotes(expires_at);

CREATE TABLE IF NOT EXISTS payment_consumptions (
  network TEXT NOT NULL,
  payment_hash TEXT NOT NULL,
  quote_id TEXT NOT NULL,
  proposal_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  quote_hash TEXT NOT NULL,
  report_hash TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  fulfillment_json TEXT NOT NULL,
  response_hash TEXT NOT NULL,
  consumed_at INTEGER NOT NULL CHECK(consumed_at >= 0),
  PRIMARY KEY(network, payment_hash)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_consumptions_unique
  ON payment_consumptions(network, payment_hash);
CREATE INDEX IF NOT EXISTS idx_payment_consumptions_quote
  ON payment_consumptions(quote_id);

CREATE TABLE IF NOT EXISTS safepay_quote_rate_limits (
  scope TEXT NOT NULL,
  client_key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY(scope, client_key, window_start)
);

CREATE TABLE IF NOT EXISTS safepay_quote_issue_reservations (
  reservation_id TEXT PRIMARY KEY,
  client_key TEXT NOT NULL,
  proposal_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','completed','failed')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_safepay_reservations_state
  ON safepay_quote_issue_reservations(state, expires_at);

CREATE TABLE IF NOT EXISTS safepay_redemption_observations (
  observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK(kind IN ('first_consumption','idempotent_replay','cross_binding_rejected')),
  http_status INTEGER NOT NULL,
  network TEXT NOT NULL,
  payment_hash TEXT NOT NULL,
  quote_id TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  observed_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_safepay_redemption_observations_unique
  ON safepay_redemption_observations(kind, network, payment_hash, quote_id);

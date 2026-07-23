#!/bin/sh
set -eu

load_secret_file() {
  var_name="$1"
  file_var_name="${var_name}_FILE"
  file_path="$(printenv "$file_var_name" 2>/dev/null || true)"
  current_value="$(printenv "$var_name" 2>/dev/null || true)"
  if [ -n "$file_path" ] && [ -z "$current_value" ]; then
    if [ ! -r "$file_path" ]; then
      echo "Cannot read secret file for $var_name: $file_path" >&2
      exit 78
    fi
    export "$var_name=$(cat "$file_path")"
  fi
}

for secret_name in \
  LLM_API_KEY \
  GATEWAY_SECRET \
  RECORDER_SUBMISSION_KEY \
  TRIAGE_SUBMISSION_KEY \
  DIAGNOSIS_SUBMISSION_KEY \
  SAFETY_REVIEWER_SUBMISSION_KEY \
  COMMANDER_SUBMISSION_KEY \
  OPERATOR_SUBMISSION_KEY \
  SCRIBE_SUBMISSION_KEY \
  PROPOSAL_ROOM_API_KEY \
  CONCORDIA_OPERATOR_TOKEN \
  APPROVAL_PROXY_SECRET \
  APPROVAL_UI_BCRYPT_HASH \
  APPROVAL_UI_CSRF_SECRET
do
  load_secret_file "$secret_name"
done

service="${CONCORDIA_SERVICE:-${1:-gateway}}"

case "$service" in
  gateway)
    python -m shared.runtime_release_mounts
    exec uv run --no-sync uvicorn gateway.app:app --host "${GATEWAY_HOST:-0.0.0.0}" --port "${GATEWAY_PORT:-8000}"
    ;;
  simulator)
    exec uv run --no-sync uvicorn app:app --app-dir proposal-simulator --host "${SIMULATOR_HOST:-0.0.0.0}" --port "${SIMULATOR_PORT:-9000}"
    ;;
  agent)
    if [ -z "${AGENT_ROLE:-}" ]; then
      echo "AGENT_ROLE is required for CONCORDIA_SERVICE=agent" >&2
      exit 64
    fi
    exec uv run --no-sync python -m "agents.${AGENT_ROLE}"
    ;;
  recorder-heartbeat)
    exec uv run --no-sync python -m agents.recorder.heartbeat
    ;;
  x402-provider)
    exec uv run --no-sync uvicorn x402_provider.app:app --host "${X402_PROVIDER_HOST:-0.0.0.0}" --port "${X402_PROVIDER_PORT:-8000}"
    ;;
  *)
    echo "Unknown CONCORDIA service: $service" >&2
    exit 64
    ;;
esac

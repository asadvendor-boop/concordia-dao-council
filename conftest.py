"""Root conftest — sets dummy environment for credential-free local tests."""
import os

# Set dummy agent IDs so env-dependent code doesn't crash
os.environ.setdefault("OPERATOR_AGENT_ID", "test-operator-00000000")
os.environ.setdefault("RECORDER_AGENT_ID", "test-recorder-00000000")
os.environ.setdefault("TRIAGE_AGENT_ID", "test-triage-00000000")
os.environ.setdefault("COMMANDER_AGENT_ID", "test-commander-00000000")
os.environ.setdefault("SAFETY_REVIEWER_AGENT_ID", "test-safety-00000000")
os.environ.setdefault("DIAGNOSIS_AGENT_ID", "test-diagnosis-00000000")
os.environ.setdefault("SCRIBE_AGENT_ID", "test-scribe-00000000")
os.environ.setdefault("RECORDER_SUBMISSION_KEY", "test-submission-key")
os.environ.setdefault("APPROVAL_PROXY_SECRET", "test-proxy-secret")
os.environ.setdefault("GATEWAY_BCRYPT_HASH", "$2b$12$test")
os.environ.setdefault("GATEWAY_SECRET", "test-gateway-secret")
os.environ.setdefault("PROPOSAL_SIMULATOR_URL", "http://127.0.0.1:5001")
os.environ.setdefault("CONCORDIA_TEST_MODE", "true")

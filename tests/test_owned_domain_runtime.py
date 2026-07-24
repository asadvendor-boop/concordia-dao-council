"""Finals runtime URLs must use the Concordia-owned service map."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_owned_domains_are_the_only_active_runtime_defaults() -> None:
    caddy = (ROOT / "deploy/shared-host/Caddyfile.snippet").read_text(encoding="utf-8")
    env_example = (ROOT / "deploy/shared-host/concordia.env.example").read_text(
        encoding="utf-8"
    )
    collector = (ROOT / "scripts/bound_live_proof_collector.py").read_text(
        encoding="utf-8"
    )
    compose = (ROOT / "deploy/shared-host/compose.prod.yml").read_text(
        encoding="utf-8"
    )
    organizer_gate = (ROOT / "scripts/organizer-link-gate-core.mjs").read_text(
        encoding="utf-8"
    )
    release_manifest = (ROOT / "shared/release_manifest.py").read_text(
        encoding="utf-8"
    )

    assert "CONCORDIA_HOSTNAME=concordiadao.xyz" in env_example
    assert "X402_PROVIDER_HOSTNAME=safepay.concordiadao.xyz" in env_example
    assert (
        "X402_PROVIDER_URL=https://safepay.concordiadao.xyz/x402/risk-report"
        in env_example
    )
    assert (
        "X402_PROVIDER_URL: https://safepay.concordiadao.xyz/x402/risk-report"
        in compose
    )
    assert "X402_PROVIDER_URL: ${X402_PROVIDER_URL:-}" not in compose
    assert "{$CONCORDIA_HOSTNAME:concordiadao.xyz}" in caddy
    assert "{$X402_PROVIDER_HOSTNAME:safepay.concordiadao.xyz}" in caddy
    assert caddy.count("ca https://acme-v02.api.letsencrypt.org/directory") == 4
    assert "https://safepay.concordiadao.xyz/health" in collector
    assert "https://safepay.concordiadao.xyz/x402/v2/redemptions" in collector
    assert '"https://concordiadao.xyz"' in organizer_gate
    assert "sslip.io" not in organizer_gate
    assert '"app": "https://concordiadao.xyz/"' in release_manifest
    assert '"safepay_provider": "https://safepay.concordiadao.xyz/"' in release_manifest

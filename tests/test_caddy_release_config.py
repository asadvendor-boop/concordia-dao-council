"""Static release contracts for the shared-host Caddy snippet.

Runtime adaptation and hosted probes remain WP10 release gates. These tests make
the security-sensitive routing intent reviewable without requiring Docker in CI.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CADDYFILE = ROOT / "deploy/shared-host/Caddyfile.snippet"
SHARED_HOST_README = ROOT / "deploy/shared-host/README.md"
SAFEPAY_CADDY_PREFLIGHT = (
    ROOT / "scripts/preflight_shared_caddy_safepay_secret.sh"
)


def _config() -> str:
    return CADDYFILE.read_text(encoding="utf-8")


def test_sslip_and_purchased_apex_share_the_same_app_route() -> None:
    config = _config()

    assert "(concordia_app)" in config
    assert "{$CONCORDIA_HOSTNAME}" in config
    assert "{$CONCORDIA_APEX_HOSTNAME:concordiadao.xyz}" in config
    assert config.count("import concordia_app") == 2
    assert "{$CONCORDIA_WWW_HOSTNAME:www.concordiadao.xyz}" in config
    assert (
        "redir https://{$CONCORDIA_APEX_HOSTNAME:concordiadao.xyz}{uri} 308" in config
    )


def test_approval_boundary_uses_mounted_files_and_overwrites_spoofed_header() -> None:
    config = _config()

    approval = config.index("handle /approve*")
    next_handler = config.index("\n\thandle ", approval + 1)
    block = config[approval:next_handler]
    assert "basic_auth" in block
    assert "{file./run/secrets/approval_ui_user}" in block
    assert "{file./run/secrets/approval_ui_bcrypt_hash}" in block
    assert "header_up X-Proxy-Secret {file./run/secrets/approval_proxy_secret}" in block
    assert "APPROVAL_PROXY_SECRET}" not in block


def test_internal_and_legacy_demo_routes_are_not_public_gateway_routes() -> None:
    config = _config()

    assert "handle /internal" not in config
    assert "handle /demo/*" not in config
    assert "handle /demo/reset" not in config


def test_provider_sslip_vhost_remains_available_for_tls_repair() -> None:
    config = _config()

    assert "{$X402_PROVIDER_HOSTNAME}" in config
    assert "reverse_proxy concordia-x402-provider:8000" in config


def test_safepay_provider_overwrites_client_identity_and_proxy_attestation() -> None:
    config = _config()

    start = config.index("{$X402_PROVIDER_HOSTNAME}")
    end = config.index(
        "{$CONCORDIA_X402_HOSTNAME:x402.concordiadao.xyz}",
        start,
    )
    block = config[start:end]
    route = block[block.index("handle /x402/*") :]
    assert "header_up X-Concordia-Client-IP {remote_host}" in route
    assert (
        "header_up X-Concordia-SafePay-Proxy "
        "{file./run/secrets/safepay_proxy_secret}"
    ) in route
    assert "{$SAFEPAY_PROXY_SECRET}" not in route


def test_safepay_gateway_route_overwrites_client_identity_and_attestation() -> None:
    config = _config()

    start = config.index("(concordia_app)")
    end = config.index("{$CONCORDIA_HOSTNAME}", start)
    block = config[start:end]
    route_start = block.index("handle /x402/v2/*")
    route_end = block.index("\n\thandle ", route_start + 1)
    route = block[route_start:route_end]
    assert "reverse_proxy concordia-gateway:8000" in route
    assert "header_up X-Concordia-Client-IP {remote_host}" in route
    assert (
        "header_up X-Concordia-SafePay-Proxy "
        "{file./run/secrets/safepay_proxy_secret}"
    ) in route
    assert "{$SAFEPAY_PROXY_SECRET}" not in route


def test_safepay_request_body_is_limited_at_both_public_caddy_edges() -> None:
    config = _config()

    gateway_start = config.index("handle /x402/v2/*")
    gateway_end = config.index("\n\thandle ", gateway_start + 1)
    gateway_route = config[gateway_start:gateway_end]

    provider_host = config.index("{$X402_PROVIDER_HOSTNAME}")
    provider_start = config.index("handle /x402/*", provider_host)
    provider_end = config.index("\n\thandle ", provider_start + 1)
    provider_route = config[provider_start:provider_end]

    for route in (gateway_route, provider_route):
        assert "request_body {" in route
        assert "max_size 64KB" in route
        assert route.index("request_body {") < route.index("reverse_proxy")
    assert config.count("max_size 64KB") == 2


def test_shared_caddy_secret_has_an_explicit_runtime_preflight() -> None:
    """Shared Caddy is external to Compose, so release must probe its mount."""

    readme = SHARED_HOST_README.read_text(encoding="utf-8")
    preflight = SAFEPAY_CADDY_PREFLIGHT.read_text(encoding="utf-8")

    assert "preflight_shared_caddy_safepay_secret.sh" in readme
    assert "before every Caddy adapt/reload" in readme
    assert "byte-identical" in readme
    assert "/run/secrets/safepay_proxy_secret" in preflight
    assert "docker exec -i" in preflight
    assert "test -r" in preflight
    assert "wc -c" in preflight
    assert 'tr -d "[:space:]" < "$secret_path"' in preflight
    assert 'cmp -s "$secret_path" -' in preflight
    assert '< "$app_secret_path"' in preflight
    assert "secret_value=" not in preflight
    assert "cat " not in preflight
    assert "echo" not in preflight
    assert "set -eu" in preflight


def test_official_x402_host_exposes_only_frozen_method_path_pairs() -> None:
    config = _config()

    start = config.index("{$CONCORDIA_X402_HOSTNAME:x402.concordiadao.xyz}")
    block = config[start:]
    assert "method GET" in block
    assert "path /health /supported /resource/*" in block
    assert "method POST" in block
    assert "path /verify /settle" in block
    assert "handle / {" in block
    # The wildcard is required: under Caddy 2.8, ``redir /supported 308``
    # parses ``/supported`` as a matcher and emits a 302 whose Location is 308.
    assert "redir * /supported 308" in block
    assert "redir /supported 308" not in block
    assert block.count("reverse_proxy concordia-x402-official:8787") == 2
    assert (
        block.count("header_up X-Concordia-Client-IP {remote_host}") == 2
    )
    assert 'respond "route_not_found" 404' in block


def test_tracked_caddyfile_contains_no_secret_value_placeholders_from_env() -> None:
    config = _config()

    assert "{$APPROVAL_UI_BCRYPT_HASH}" not in config
    assert "{$APPROVAL_PROXY_SECRET}" not in config
    assert "{$APPROVAL_UI_USER}" not in config
    assert "/run/secrets/approval_ui_user" in config
    assert "/run/secrets/approval_ui_bcrypt_hash" in config
    assert "/run/secrets/approval_proxy_secret" in config

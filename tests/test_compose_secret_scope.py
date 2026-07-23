"""Production secret material must be mounted only into its consumers."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml

from shared.cspr_cloud import (
    CSPRCloudConfig,
    CSPRCloudConfigError,
    _headers,
    _node_headers,
    cspr_cloud_status,
    get_account_context,
    get_cspr_cloud_config,
    get_node_status,
    get_public_testnet_probe,
    node_rpc_context,
    streaming_subscription_context,
)
from shared.runtime_secrets import read_secret


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/shared-host/compose.prod.yml"

SCOPED_TOKENS = {
    "CSPR_CLOUD_ACCESS_TOKEN": "cspr_cloud_access_token",
    "X402_FACILITATOR_TOKEN": "x402_facilitator_token",
    "X402_PROVIDER_TOKEN": "x402_provider_token",
}


def _compose() -> dict[str, object]:
    loaded = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_shared_environment_contains_no_external_access_token_values() -> None:
    document = _compose()
    common = document["x-concordia-env"]
    assert isinstance(common, dict)

    for variable in SCOPED_TOKENS:
        assert variable not in common
        assert f"{variable}_FILE" not in common


def test_external_tokens_are_file_mounted_only_into_exact_consumers() -> None:
    document = _compose()
    services = document["services"]
    secrets = document["secrets"]
    assert isinstance(services, dict)
    assert isinstance(secrets, dict)

    expected = {"mercer": {"CSPR_CLOUD_ACCESS_TOKEN"}}
    for service_name, service in services.items():
        assert isinstance(service, dict)
        environment = service.get("environment", {})
        mounted = set(service.get("secrets", []))
        assert isinstance(environment, dict)
        expected_variables = expected.get(service_name, set())
        for variable, secret_name in SCOPED_TOKENS.items():
            if variable in expected_variables:
                assert environment.get(f"{variable}_FILE") == (
                    f"/run/secrets/{secret_name}"
                )
                assert variable not in environment
                assert secret_name in mounted
            else:
                assert variable not in environment
                assert f"{variable}_FILE" not in environment
                assert secret_name not in mounted

    definition = secrets["cspr_cloud_access_token"]
    assert isinstance(definition, dict)
    assert set(definition) == {"file"}
    assert str(definition["file"]).startswith("${")
    assert "x402_facilitator_token" not in secrets
    assert "x402_provider_token" not in secrets


def test_casper_signer_path_and_key_are_scoped_to_gateway_and_locke() -> None:
    document = _compose()
    common = document["x-concordia-env"]
    services = document["services"]
    assert "CASPER_SECRET_KEY_PATH" not in common

    for service_name, service in services.items():
        environment = service.get("environment", {})
        mounted = set(service.get("secrets", []))
        if service_name in {"gateway", "locke"}:
            assert environment["CASPER_SECRET_KEY_PATH"] == (
                "/run/secrets/casper_secret_key"
            )
            assert "casper_secret_key" in mounted
        else:
            assert "CASPER_SECRET_KEY_PATH" not in environment
            assert "casper_secret_key" not in mounted


def test_legacy_x402_credentials_and_facilitator_are_absent_from_runtime() -> None:
    document = _compose()
    for service_name, service in document["services"].items():
        environment = service.get("environment", {})
        if service_name == "x402-official":
            assert environment["X402_FACILITATOR_URL"] == (
                "https://x402-facilitator.cspr.cloud"
            )
        else:
            assert "X402_FACILITATOR_URL" not in environment
        assert "X402_FACILITATOR_TOKEN" not in environment
        assert "X402_FACILITATOR_TOKEN_FILE" not in environment
        assert "X402_PROVIDER_TOKEN" not in environment
        assert "X402_PROVIDER_TOKEN_FILE" not in environment


def test_finals_boundary_secrets_are_file_scoped_to_exact_consumers() -> None:
    document = _compose()
    services = document["services"]
    assert isinstance(services, dict)

    expected: dict[str, set[str]] = {
        "approval_ui_user": {"gateway"},
        "approval_ui_approver_id": {"gateway"},
        "demo_capability_hmac_secret": {"gateway"},
        "dashboard_demo_gateway_token": {"gateway", "dashboard"},
        "safepay_proxy_secret": {"gateway", "x402-provider"},
        "safepay_quote_token_secret": {"gateway"},
        "safepay_client_key_hmac_secret": {"x402-provider"},
        "x402_official_cspr_cloud_token": {"x402-official"},
        "x402_official_signer": {"x402-official"},
        "x402_official_gateway_token": {"gateway", "x402-official"},
    }
    env_names = {
        "approval_ui_user": "APPROVAL_UI_USER_FILE",
        "approval_ui_approver_id": "APPROVAL_UI_APPROVER_ID_FILE",
        "demo_capability_hmac_secret": "DEMO_CAPABILITY_HMAC_SECRET_FILE",
        "dashboard_demo_gateway_token": "DASHBOARD_DEMO_GATEWAY_TOKEN_FILE",
        "safepay_proxy_secret": "SAFEPAY_PROXY_SECRET_FILE",
        "safepay_quote_token_secret": "SAFEPAY_QUOTE_TOKEN_SECRET_FILE",
        "safepay_client_key_hmac_secret": "SAFEPAY_CLIENT_KEY_HMAC_SECRET_FILE",
        "x402_official_cspr_cloud_token": "X402_CSPR_CLOUD_TOKEN_FILE",
        "x402_official_signer": "X402_SIGNER_FILE",
        "x402_official_gateway_token": "X402_GATEWAY_TOKEN_FILE",
    }

    for secret_name, consumers in expected.items():
        for service_name, service in services.items():
            environment = service.get("environment", {})
            mounted = set(service.get("secrets", []))
            assert isinstance(environment, dict)
            if service_name in consumers:
                assert secret_name in mounted
                assert environment[env_names[secret_name]] == (
                    f"/run/secrets/{secret_name}"
                )
            else:
                assert secret_name not in mounted
                assert env_names[secret_name] not in environment

    dashboard = services["dashboard"]
    assert "concordia_operator_token" not in set(dashboard.get("secrets", []))
    assert "CONCORDIA_OPERATOR_TOKEN_FILE" not in dashboard["environment"]


def test_finals_boundary_secret_definitions_are_file_backed() -> None:
    document = _compose()
    secrets = document["secrets"]
    expected = {
        "approval_ui_user",
        "approval_ui_approver_id",
        "demo_capability_hmac_secret",
        "dashboard_demo_gateway_token",
        "safepay_proxy_secret",
        "safepay_quote_token_secret",
        "safepay_client_key_hmac_secret",
        "x402_official_cspr_cloud_token",
        "x402_official_signer",
        "x402_official_gateway_token",
    }
    for name in expected:
        definition = secrets[name]
        assert isinstance(definition, dict)
        assert set(definition) == {"file"}
        assert str(definition["file"]).startswith("${")
        assert str(definition["file"]).startswith(
            "${" + name.upper() + "_FILE:-/opt/apps/concordia/secrets/"
        )


def test_safepay_v2_provider_has_durable_ledger_and_frozen_runtime_terms() -> None:
    document = _compose()
    provider = document["services"]["x402-provider"]
    environment = provider["environment"]

    assert environment["X402_LEDGER"] == "/data/safepay.db"
    assert environment["SAFEPAY_TRUSTED_PROXY_CIDRS"] == (
        "${SAFEPAY_TRUSTED_PROXY_CIDRS:?Set SAFEPAY_TRUSTED_PROXY_CIDRS}"
    )
    assert environment["SAFEPAY_PAYEE_ACCOUNT_HASH"] == (
        "${SAFEPAY_PAYEE_ACCOUNT_HASH:?Set SAFEPAY_PAYEE_ACCOUNT_HASH}"
    )
    assert environment["SAFEPAY_AMOUNT_MOTES"] == (
        "${SAFEPAY_AMOUNT_MOTES:?Set SAFEPAY_AMOUNT_MOTES}"
    )
    assert provider["volumes"] == ["x402_provider_data:/data"]
    assert "x402_provider_data" in document["volumes"]
    assert "ports" not in provider


def test_gateway_has_safepay_proxy_identity_and_quote_capability_configuration() -> None:
    document = _compose()
    gateway = document["services"]["gateway"]
    environment = gateway["environment"]

    assert environment["SAFEPAY_TRUSTED_PROXY_CIDRS"] == (
        "${SAFEPAY_TRUSTED_PROXY_CIDRS:?Set SAFEPAY_TRUSTED_PROXY_CIDRS}"
    )
    assert environment["SAFEPAY_PROXY_SECRET_FILE"] == (
        "/run/secrets/safepay_proxy_secret"
    )
    assert environment["SAFEPAY_QUOTE_TOKEN_SECRET_FILE"] == (
        "/run/secrets/safepay_quote_token_secret"
    )


def test_official_x402_service_is_frozen_internal_and_persistent() -> None:
    document = _compose()
    service = document["services"]["x402-official"]
    environment = service["environment"]

    assert service["build"] == {
        "context": "../..",
        "dockerfile": "services/x402-official/Dockerfile",
    }
    assert service["restart"] == "unless-stopped"
    assert "ports" not in service
    assert environment == {
        "NODE_ENV": "production",
        "X402_OFFICIAL_PORT": "8787",
        "X402_FACILITATOR_URL": "https://x402-facilitator.cspr.cloud",
        "X402_NETWORK": "casper:casper-test",
        "X402_SCHEME": "exact",
        "X402_WCSPR_PACKAGE_HASH": (
            "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e"
        ),
        "X402_WCSPR_CONTRACT_HASH": (
            "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a"
        ),
        "X402_WCSPR_CONTRACT_VERSION": "8",
        "X402_TOKEN_NAME": "Wrapped CSPR",
        "X402_TOKEN_SYMBOL": "WCSPR",
        "X402_TOKEN_DECIMALS": "9",
        "X402_TOKEN_DOMAIN_VERSION": "1",
        "X402_LEDGER_PATH": "/data/x402-official.db",
        "X402_GATEWAY_INTERNAL_URL": "http://gateway:8000",
        "X402_RESOURCES_FILE": "/run/config/x402-resources.json",
        "X402_CSPR_CLOUD_TOKEN_FILE": (
            "/run/secrets/x402_official_cspr_cloud_token"
        ),
        "X402_SIGNER_FILE": "/run/secrets/x402_official_signer",
        "X402_GATEWAY_TOKEN_FILE": (
            "/run/secrets/x402_official_gateway_token"
        ),
    }
    assert set(service["volumes"]) == {
        "x402_official_data:/data",
        (
            "${X402_OFFICIAL_CONFIG_DIR:-/opt/apps/concordia/config/"
            "x402-official}:/run/config:ro"
        ),
    }
    assert "x402_official_data" in document["volumes"]
    assert set(service["networks"]) == {"concordia-edge", "concordia-internal"}
    assert service["networks"]["concordia-internal"]["aliases"] == [
        "concordia-x402-official"
    ]
    assert "gateway" in document["services"]["gateway"]["networks"][
        "concordia-internal"
    ]["aliases"]


def test_official_x402_healthcheck_is_local_and_fail_closed() -> None:
    service = _compose()["services"]["x402-official"]
    healthcheck = service["healthcheck"]

    assert healthcheck["test"] == [
        "CMD-SHELL",
        (
            "node -e \"fetch('http://127.0.0.1:8787/health')"
            ".then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))\""
        ),
    ]
    assert healthcheck["interval"] == "10s"
    assert healthcheck["timeout"] == "5s"
    assert healthcheck["retries"] == 12


def test_cspr_cloud_reads_file_secret_and_file_wins_over_direct_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    token_file = tmp_path / "cspr-cloud-token"
    token_file.write_text("file-token\n", encoding="ascii")
    monkeypatch.setenv("CSPR_CLOUD_ACCESS_TOKEN", "stale-direct-token")
    monkeypatch.setenv("CSPR_CLOUD_ACCESS_TOKEN_FILE", str(token_file))

    config = get_cspr_cloud_config()

    assert config.access_token == "file-token"


def test_production_cspr_cloud_never_accepts_direct_environment_token(
    monkeypatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CSPR_CLOUD_MOCK", "0")
    monkeypatch.setenv("CSPR_CLOUD_ACCESS_TOKEN", "direct-token")
    monkeypatch.delenv("CSPR_CLOUD_ACCESS_TOKEN_FILE", raising=False)

    assert get_cspr_cloud_config().access_token == ""


@pytest.mark.parametrize("app_env", ["prod", " PROD ", " Production "])
def test_all_production_environment_aliases_reject_direct_tokens(
    monkeypatch,
    app_env: str,
) -> None:
    monkeypatch.setenv("APP_ENV", app_env)
    monkeypatch.setenv("CSPR_CLOUD_MOCK", "0")
    monkeypatch.setenv("CSPR_CLOUD_ACCESS_TOKEN", "direct-token")
    monkeypatch.delenv("CSPR_CLOUD_ACCESS_TOKEN_FILE", raising=False)

    assert get_cspr_cloud_config().access_token == ""


def test_runtime_secret_file_failure_never_falls_back_to_direct_env(
    tmp_path: Path,
    monkeypatch,
) -> None:
    unsafe = tmp_path / "unsafe-token"
    unsafe.write_text("unsafe-file-token", encoding="ascii")
    unsafe.chmod(0o666)
    monkeypatch.setenv("SCOPED_TOKEN", "direct-token")
    monkeypatch.setenv("SCOPED_TOKEN_FILE", str(unsafe))

    assert read_secret("SCOPED_TOKEN") == ""


def test_runtime_secret_rejects_symlink_and_allows_local_env_without_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = tmp_path / "target"
    target.write_text("linked-token", encoding="ascii")
    linked = tmp_path / "linked"
    linked.symlink_to(target)
    monkeypatch.setenv("SCOPED_TOKEN", "direct-token")
    monkeypatch.setenv("SCOPED_TOKEN_FILE", str(linked))
    assert read_secret("SCOPED_TOKEN") == ""

    monkeypatch.delenv("SCOPED_TOKEN_FILE")
    assert read_secret("SCOPED_TOKEN") == "direct-token"


def test_cspr_cloud_sends_raw_authorization_without_bearer_prefix() -> None:
    config = CSPRCloudConfig(
        api_url="https://api.testnet.cspr.cloud",
        stream_url="wss://streaming.testnet.cspr.cloud",
        node_rpc_url="https://node.testnet.cspr.cloud/rpc",
        access_token="cspr-cloud-token",
        mock=False,
    )

    assert _headers(config)["authorization"] == "cspr-cloud-token"


def test_cspr_cloud_token_is_bound_to_exact_https_api_origin() -> None:
    for unsafe in (
        "http://api.testnet.cspr.cloud",
        "https://api.testnet.cspr.cloud.evil.example",
        "https://example.com",
        "https://api.testnet.cspr.cloud/path",
    ):
        config = CSPRCloudConfig(
            api_url=unsafe,
            stream_url="wss://streaming.testnet.cspr.cloud",
            node_rpc_url="https://node.testnet.casper.network/rpc",
            access_token="never-send-me",
            mock=False,
        )
        with pytest.raises(CSPRCloudConfigError):
            _headers(config)

    for malformed_token in ("Bearer token", "token with space", "token\nvalue"):
        config = CSPRCloudConfig(
            api_url="https://api.testnet.cspr.cloud",
            stream_url="wss://streaming.testnet.cspr.cloud",
            node_rpc_url="https://node.testnet.casper.network/rpc",
            access_token=malformed_token,
            mock=False,
        )
        with pytest.raises(CSPRCloudConfigError):
            _headers(config)


def test_gateway_can_report_service_scoped_cspr_cloud_without_token(
    monkeypatch,
) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CSPR_CLOUD_MOCK", "0")
    monkeypatch.delenv("CSPR_CLOUD_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("CSPR_CLOUD_ACCESS_TOKEN_FILE", raising=False)
    monkeypatch.setenv("CSPR_CLOUD_SERVICE_SCOPE", "mercer")

    status = cspr_cloud_status()

    assert status["status"] == "service_scoped"
    assert status["rest_configured"] is False
    assert status["credential_service_declared"] is True
    assert status["credential_available_to_this_process"] is False
    assert status["credential_scope"] == "mercer"


def test_unconfigured_guidance_requires_a_secret_file(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CSPR_CLOUD_MOCK", "0")
    monkeypatch.delenv("CSPR_CLOUD_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("CSPR_CLOUD_ACCESS_TOKEN_FILE", raising=False)

    result = asyncio.run(get_account_context("01" + ("00" * 32)))

    assert "CSPR_CLOUD_ACCESS_TOKEN_FILE" in result["error"]
    assert "CSPR_CLOUD_ACCESS_TOKEN " not in result["error"]


def test_public_node_status_never_receives_cspr_cloud_authorization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    token_file = tmp_path / "cspr-cloud-token"
    token_file.write_text("sensitive-token", encoding="ascii")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CSPR_CLOUD_ACCESS_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("CSPR_NODE_RPC_URL", "https://node.testnet.casper.network/rpc")
    observed: dict[str, object] = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"result": {"chainspec_name": "casper-test"}}

    class Client:
        def __init__(self, **kwargs) -> None:
            observed["client"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def post(self, url, *, headers, json):
            observed["url"] = url
            observed["headers"] = headers
            observed["json"] = json
            return Response()

    monkeypatch.setattr("shared.cspr_cloud.httpx.AsyncClient", Client)

    result = asyncio.run(get_node_status())

    assert result["live"] is True
    assert "authorization" not in observed["headers"]
    assert observed["client"] == {
        "timeout": 15.0,
        "follow_redirects": False,
        "trust_env": False,
    }


def test_exact_cspr_cloud_node_receives_raw_authorization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    token_file = tmp_path / "cspr-cloud-token"
    token_file.write_text("node-access-token", encoding="ascii")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CSPR_CLOUD_ACCESS_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("CSPR_NODE_RPC_URL", "https://node.testnet.cspr.cloud/rpc")
    observed: dict[str, object] = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"result": {"chainspec_name": "casper-test"}}

    class Client:
        def __init__(self, **kwargs) -> None:
            observed["client"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def post(self, url, *, headers, json):
            observed["url"] = url
            observed["headers"] = headers
            observed["json"] = json
            return Response()

    monkeypatch.setattr("shared.cspr_cloud.httpx.AsyncClient", Client)

    result = asyncio.run(get_node_status())

    assert result["live"] is True
    assert observed["headers"] == {
        "content-type": "application/json",
        "authorization": "node-access-token",
    }
    assert observed["client"] == {
        "timeout": 15.0,
        "follow_redirects": False,
        "trust_env": False,
    }


@pytest.mark.parametrize(
    "node_url",
    [
        "http://node.testnet.cspr.cloud/rpc",
        "https://node.testnet.cspr.cloud:444/rpc",
        "https://node.testnet.cspr.cloud/not-rpc",
        "https://node.testnet.cspr.cloud/rpc?redirect=1",
    ],
)
def test_cspr_cloud_node_origin_variants_fail_closed(
    tmp_path: Path,
    monkeypatch,
    node_url: str,
) -> None:
    token_file = tmp_path / "cspr-cloud-token"
    token_file.write_text("node-access-token", encoding="ascii")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CSPR_CLOUD_ACCESS_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("CSPR_NODE_RPC_URL", node_url)

    result = asyncio.run(get_node_status())

    assert result["live"] is False
    assert result["error"] == "CSPRCloudConfigError"


@pytest.mark.parametrize(
    "node_url",
    [
        "https://node.testnet.cspr.cloud.evil.example/rpc",
        "https://node.testnet.casper.network/rpc",
        "https://rpc.example.test/rpc",
    ],
)
def test_non_cspr_cloud_node_origins_never_receive_the_access_token(
    node_url: str,
) -> None:
    config = CSPRCloudConfig(
        api_url="https://api.testnet.cspr.cloud",
        stream_url="wss://streaming.testnet.cspr.cloud",
        node_rpc_url=node_url,
        access_token="never-send-me",
        mock=False,
    )

    assert "authorization" not in _node_headers(config)


def test_cspr_cloud_origins_are_bound_to_the_configured_chain(monkeypatch) -> None:
    testnet = CSPRCloudConfig(
        api_url="https://api.testnet.cspr.cloud",
        stream_url="wss://streaming.testnet.cspr.cloud",
        node_rpc_url="https://node.testnet.cspr.cloud/rpc",
        access_token="raw-token",
        mock=False,
    )
    mainnet = CSPRCloudConfig(
        api_url="https://api.cspr.cloud",
        stream_url="wss://streaming.cspr.cloud",
        node_rpc_url="https://node.cspr.cloud/rpc",
        access_token="raw-token",
        mock=False,
    )

    monkeypatch.setenv("CASPER_CHAIN_NAME", "casper-test")
    assert _headers(testnet)["authorization"] == "raw-token"
    assert _node_headers(testnet)["authorization"] == "raw-token"
    with pytest.raises(CSPRCloudConfigError):
        _headers(mainnet)
    with pytest.raises(CSPRCloudConfigError):
        _node_headers(mainnet)

    monkeypatch.setenv("CASPER_CHAIN_NAME", "casper")
    assert _headers(mainnet)["authorization"] == "raw-token"
    assert _node_headers(mainnet)["authorization"] == "raw-token"
    with pytest.raises(CSPRCloudConfigError):
        _headers(testnet)
    with pytest.raises(CSPRCloudConfigError):
        _node_headers(testnet)


def test_network_label_is_derived_from_the_configured_chain(monkeypatch) -> None:
    monkeypatch.setenv("CASPER_CHAIN_NAME", "casper")
    monkeypatch.setenv("CSPR_CLOUD_MOCK", "mock")
    monkeypatch.setenv("CSPR_CLOUD_API_URL", "https://api.cspr.cloud")
    monkeypatch.setenv("CSPR_CLOUD_STREAM_URL", "wss://streaming.cspr.cloud")
    monkeypatch.setenv("CSPR_NODE_RPC_URL", "https://node.cspr.cloud/rpc")

    account = asyncio.run(get_account_context("01" + ("00" * 32)))

    assert account["network"] == "casper-mainnet"
    assert node_rpc_context()["network"] == "casper-mainnet"


def test_offline_node_mock_uses_the_configured_chain(monkeypatch) -> None:
    monkeypatch.setenv("CASPER_CHAIN_NAME", "casper")
    monkeypatch.setenv("CASPER_MCP_OFFLINE_MOCK", "1")

    status = asyncio.run(get_node_status())

    assert status["network"] == "casper-mainnet"
    assert status["status"]["chainspec_name"] == "casper"


@pytest.mark.parametrize(
    ("variable", "unsafe_value"),
    [
        (
            "CSPR_CLOUD_API_URL",
            "https://user:password@api.testnet.cspr.cloud?reflected=secret",
        ),
        (
            "CSPR_CLOUD_STREAM_URL",
            "wss://user:password@streaming.testnet.cspr.cloud?reflected=secret",
        ),
        (
            "CSPR_NODE_RPC_URL",
            "https://user:password@node.testnet.casper.network/rpc?reflected=secret",
        ),
    ],
)
def test_status_redacts_invalid_configured_urls(
    monkeypatch,
    variable: str,
    unsafe_value: str,
) -> None:
    monkeypatch.setenv("CASPER_CHAIN_NAME", "casper-test")
    monkeypatch.setenv("CSPR_CLOUD_MOCK", "0")
    monkeypatch.setenv(variable, unsafe_value)

    status = cspr_cloud_status()

    assert status["status"] == "invalid_config"
    assert status["api_url"] != unsafe_value
    assert status["stream_url"] != unsafe_value
    assert status["node_rpc_url"] != unsafe_value
    assert "user" not in repr(status)
    assert "password" not in repr(status)
    assert "reflected" not in repr(status)


def test_status_rejects_and_redacts_malformed_access_token(
    tmp_path: Path,
    monkeypatch,
) -> None:
    token_file = tmp_path / "cspr-cloud-token"
    token_file.write_text("Bearer reflected-secret", encoding="ascii")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CSPR_CLOUD_MOCK", "0")
    monkeypatch.setenv("CSPR_CLOUD_ACCESS_TOKEN_FILE", str(token_file))

    status = cspr_cloud_status()

    assert status["status"] == "invalid_config"
    assert status["rest_configured"] is False
    assert status["credential_available_to_this_process"] is False
    assert "Bearer" not in repr(status)
    assert "reflected-secret" not in repr(status)


def test_invalid_node_url_is_neither_contacted_nor_reflected(monkeypatch) -> None:
    unsafe = "https://user:password@rpc.example.test/rpc?reflected=secret"
    monkeypatch.setenv("CASPER_CHAIN_NAME", "casper-test")
    monkeypatch.setenv("CSPR_CLOUD_MOCK", "0")
    monkeypatch.setenv("CSPR_NODE_RPC_URL", unsafe)
    contacted = False

    class Client:
        def __init__(self, **_kwargs) -> None:
            nonlocal contacted
            contacted = True

    monkeypatch.setattr("shared.cspr_cloud.httpx.AsyncClient", Client)

    status = asyncio.run(get_node_status())
    context = node_rpc_context()

    assert contacted is False
    assert status["live"] is False
    assert status["error"] == "CSPRCloudConfigError"
    assert status["node_rpc_url"] == "redacted_invalid"
    assert context["status"] == "invalid_config"
    assert context["node_rpc_url"] == "redacted_invalid"
    assert "user" not in repr(status) + repr(context)
    assert "password" not in repr(status) + repr(context)


def test_invalid_stream_url_is_redacted_from_context(monkeypatch) -> None:
    unsafe = "wss://user:password@streaming.testnet.cspr.cloud?reflected=secret"
    monkeypatch.setenv("CASPER_CHAIN_NAME", "casper-test")
    monkeypatch.setenv("CSPR_CLOUD_STREAM_URL", unsafe)

    context = streaming_subscription_context()

    assert context["mode"] == "invalid_config"
    assert context["stream_url"] == "redacted_invalid"
    assert "user" not in repr(context)
    assert "password" not in repr(context)


def test_public_probe_rejects_credentialed_url_without_contact(monkeypatch) -> None:
    unsafe = "https://user:password@testnet.cspr.live?reflected=secret"
    monkeypatch.setenv("CASPER_PUBLIC_STATUS_URL", unsafe)
    monkeypatch.setenv("CASPER_MCP_OFFLINE_MOCK", "0")
    contacted = False

    class Client:
        def __init__(self, **_kwargs) -> None:
            nonlocal contacted
            contacted = True

    monkeypatch.setattr("shared.cspr_cloud.httpx.AsyncClient", Client)

    result = asyncio.run(get_public_testnet_probe())

    assert contacted is False
    assert result["live"] is False
    assert result["url"] == "redacted_invalid"
    assert result["error"] == "CSPRCloudConfigError"
    assert "user" not in repr(result)
    assert "password" not in repr(result)

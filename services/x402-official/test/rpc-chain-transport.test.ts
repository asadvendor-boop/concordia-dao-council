import { describe, expect, it, vi } from "vitest";

import {
  CASPER_TESTNET_RPC_URL,
  CSPR_CLOUD_TESTNET_API_URL,
  CasperRpcChainTransport,
} from "../src/rpc-chain.js";
import { ServiceRefusal } from "../src/errors.js";
import type { TransactionReadback } from "../src/types.js";
import { FROZEN } from "./helpers.js";

const ROOT = "aa".repeat(32);
const BLOCK = "bb".repeat(32);
const TX = "cc".repeat(32);
const PAYER = "11".repeat(32);
const PUBLIC_KEY = `01${"22".repeat(32)}`;
const NONCE = "33".repeat(32);
const USED_NONCES_UREF = `uref-${"44".repeat(32)}-007`;

type RpcReply =
  | { result: unknown }
  | { error: { code: number; message?: string; data?: string } };

function packageResult(
  contractHash = FROZEN.contractHash,
  version = FROZEN.contractVersion,
): unknown {
  return {
    api_version: "2.0.0",
    package: {
      ContractPackage: {
        versions: [
          {
            protocol_version_major: 2,
            contract_version: version - 1,
            contract_hash: `contract-${"55".repeat(32)}`,
          },
          {
            protocol_version_major: 2,
            contract_version: version,
            contract_hash: `contract-${contractHash}`,
          },
        ],
        disabled_versions: [[2, version - 1]],
        groups: [],
        lock_status: "Unlocked",
      },
    },
    merkle_proof: "proof",
  };
}

function clArgs(): Array<[string, Record<string, unknown>]> {
  return [
    [
      "from",
      {
        bytes: `00${PAYER}`,
        cl_type: "Key",
      },
    ],
    [
      "to",
      {
        bytes: `00${"66".repeat(32)}`,
        cl_type: "Key",
      },
    ],
    [
      "value",
      {
        bytes: "02e803",
        cl_type: "U256",
      },
    ],
    [
      "valid_after",
      {
        bytes: "0100000000000000",
        cl_type: "U64",
      },
    ],
    [
      "valid_before",
      {
        bytes: "0200000000000000",
        cl_type: "U64",
      },
    ],
    [
      "nonce",
      {
        bytes: `20000000${NONCE}`,
        cl_type: { List: "U8" },
      },
    ],
    [
      "public_key",
      {
        bytes: PUBLIC_KEY,
        cl_type: "PublicKey",
      },
    ],
    [
      "signature",
      {
        bytes: `4100000001${"77".repeat(64)}`,
        cl_type: { List: "U8" },
      },
    ],
  ];
}

function transactionResult(
  overrides: {
    hash?: string;
    errorMessage?: string | null;
    executionInfo?: boolean;
    targetPackage?: string;
    entryPoint?: string;
    args?: Array<[string, Record<string, unknown>]>;
  } = {},
): unknown {
  const hash = overrides.hash ?? TX;
  const executionInfo = overrides.executionInfo ?? true;
  return {
    api_version: "2.0.0",
    transaction: {
      Version1: {
        hash,
        payload: {
          initiator_addr: { PublicKey: `01${"88".repeat(32)}` },
          timestamp: "2026-07-23T00:00:00.000Z",
          ttl: "30m",
          chain_name: "casper-test",
          pricing_mode: {
            PaymentLimited: {
              gas_price_tolerance: 1,
              payment_amount: 2_500_000_000,
              standard_payment: true,
            },
          },
          fields: {
            args: { Named: overrides.args ?? clArgs() },
            target: {
              Stored: {
                id: {
                  ByPackageHash: {
                    addr: overrides.targetPackage ?? FROZEN.packageHash,
                  },
                },
                runtime: "VmCasperV1",
              },
            },
            entry_point: {
              Custom:
                overrides.entryPoint ?? "transfer_with_authorization",
            },
            scheduling: "Standard",
          },
        },
        approvals: [],
      },
    },
    execution_info: executionInfo
      ? {
          block_hash: BLOCK,
          block_height: 8_600_001,
          execution_result: {
            Version2: {
              error_message: overrides.errorMessage ?? null,
            },
          },
        }
      : null,
  };
}

function blockResult(): unknown {
  return {
    api_version: "2.0.0",
    block_with_signatures: {
      block: {
        Version2: {
          hash: BLOCK,
          header: {
            state_root_hash: ROOT,
            height: 8_600_001,
          },
          body: { transactions: {}, rewarded_signatures: [] },
        },
      },
      proofs: [
        {
          public_key: `01${"99".repeat(32)}`,
          signature: `01${"aa".repeat(64)}`,
        },
      ],
    },
  };
}

class MockHttp {
  readonly rpc = new Map<string, RpcReply[]>();
  readonly cloud: Array<{ status: number; body: unknown }> = [];
  readonly calls: Array<{
    url: string;
    authorization: string | null;
    rpcMethod: string | null;
  }> = [];

  queueRpc(method: string, ...replies: RpcReply[]): void {
    this.rpc.set(method, [...(this.rpc.get(method) ?? []), ...replies]);
  }

  queueCloud(status: number, body: unknown): void {
    this.cloud.push({ status, body });
  }

  readonly fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const authorization = new Headers(init?.headers).get("authorization");
    if (url === CASPER_TESTNET_RPC_URL) {
      const request = JSON.parse(String(init?.body)) as {
        id: number;
        method: string;
      };
      this.calls.push({
        url,
        authorization,
        rpcMethod: request.method,
      });
      const queue = this.rpc.get(request.method) ?? [];
      const reply = queue.shift();
      if (reply === undefined) {
        throw new Error(`unexpected_rpc:${request.method}`);
      }
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: request.id,
          ...reply,
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    }
    if (url.startsWith(`${CSPR_CLOUD_TESTNET_API_URL}/deploys?`)) {
      this.calls.push({ url, authorization, rpcMethod: null });
      const reply = this.cloud.shift();
      if (reply === undefined) throw new Error("unexpected_cloud_call");
      return new Response(JSON.stringify(reply.body), {
        status: reply.status,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected_url:${url}`);
  });
}

function makeTransport(mock: MockHttp, token = () => "raw-secret-token") {
  return new CasperRpcChainTransport({
    fetch: mock.fetch as unknown as typeof fetch,
    csprCloudToken: token,
  });
}

function queueStableBoundary(mock: MockHttp): void {
  mock.queueRpc("chain_get_state_root_hash", { result: { state_root_hash: ROOT } });
  mock.queueRpc("chain_get_block", { result: blockResult() });
  mock.queueRpc("chain_get_state_root_hash", { result: { state_root_hash: ROOT } });
  mock.queueRpc("state_get_package", { result: packageResult() });
  mock.queueRpc("state_get_entity", {
    result: {
      api_version: "2.0.0",
      entity: {
        Contract: {
          contract: {
            named_keys: [{ name: "used_nonces", key: USED_NONCES_UREF }],
          },
        },
      },
      merkle_proof: "proof",
    },
  });
}

describe("CasperRpcChainTransport package and transaction readback", () => {
  it("resolves the highest enabled package version from fresh Casper RPC state", async () => {
    const mock = new MockHttp();
    mock.queueRpc("state_get_package", { result: packageResult() });

    await expect(makeTransport(mock).resolveActivePackage(FROZEN.packageHash)).resolves.toEqual({
      lockStatus: "Unlocked",
      enabledVersion: FROZEN.contractVersion,
      enabledContractHash: FROZEN.contractHash,
    });
    expect(mock.calls).toHaveLength(1);
    expect(mock.calls[0]?.authorization).toBeNull();
  });

  it("decodes all eight typed TransactionV1 runtime arguments and execution result", async () => {
    const mock = new MockHttp();
    mock.queueRpc("info_get_transaction", { result: transactionResult() });
    mock.queueRpc("chain_get_block", { result: blockResult() });
    mock.queueRpc("state_get_package", { result: packageResult() });

    const readback = await makeTransport(mock).getFinalizedTransaction(TX);
    expect(readback).toEqual<TransactionReadback>({
      transactionHash: TX,
      finalized: true,
      executionSuccess: true,
      targetContractHash: FROZEN.contractHash,
      contractVersion: FROZEN.contractVersion,
      entryPoint: "transfer_with_authorization",
      argNames: [
        "from",
        "to",
        "value",
        "valid_after",
        "valid_before",
        "nonce",
        "public_key",
        "signature",
      ],
      args: {
        from: { clType: "Key", value: `account-hash-${PAYER}` },
        to: { clType: "Key", value: `account-hash-${"66".repeat(32)}` },
        value: { clType: "U256", value: "1000" },
        valid_after: { clType: "U64", value: "1" },
        valid_before: { clType: "U64", value: "2" },
        nonce: { clType: "List<U8>", value: NONCE },
        public_key: { clType: "PublicKey", value: PUBLIC_KEY },
        signature: {
          clType: "List<U8>",
          value: `01${"77".repeat(64)}`,
        },
      },
    });
  });

  it("returns pending rather than inventing finality when execution_info is absent", async () => {
    const mock = new MockHttp();
    mock.queueRpc("info_get_transaction", {
      result: transactionResult({ executionInfo: false }),
    });

    const readback = await makeTransport(mock).getFinalizedTransaction(TX);
    expect(readback.finalized).toBe(false);
    expect(readback.executionSuccess).toBe(false);
    expect(mock.calls.map((call) => call.rpcMethod)).toEqual([
      "info_get_transaction",
    ]);
  });

  it("records a finalized on-chain execution failure without treating it as success", async () => {
    const mock = new MockHttp();
    mock.queueRpc("info_get_transaction", {
      result: transactionResult({ errorMessage: "User error: 37000" }),
    });
    mock.queueRpc("chain_get_block", { result: blockResult() });
    mock.queueRpc("state_get_package", { result: packageResult() });

    const readback = await makeTransport(mock).getFinalizedTransaction(TX);
    expect(readback.finalized).toBe(true);
    expect(readback.executionSuccess).toBe(false);
  });

  it("refuses to call an executed transaction finalized without signed block proof", async () => {
    const mock = new MockHttp();
    mock.queueRpc("info_get_transaction", { result: transactionResult() });
    mock.queueRpc("chain_get_block", {
      result: {
        ...(blockResult() as Record<string, unknown>),
        block_with_signatures: {
          ...((blockResult() as Record<string, unknown>)[
            "block_with_signatures"
          ] as Record<string, unknown>),
          proofs: [],
        },
      },
    });

    await expect(
      makeTransport(mock).getFinalizedTransaction(TX),
    ).rejects.toMatchObject({
      code: "chain_observation_unavailable",
    } satisfies Partial<ServiceRefusal>);
    expect(mock.calls.map((call) => call.rpcMethod)).toEqual([
      "info_get_transaction",
      "chain_get_block",
    ]);
  });

  it("fails closed on malformed package or CLValue state", async () => {
    const mock = new MockHttp();
    mock.queueRpc("state_get_package", {
      result: {
        package: {
          ContractPackage: {
            versions: [],
            disabled_versions: [],
            lock_status: "Unlocked",
          },
        },
      },
    });
    await expect(
      makeTransport(mock).resolveActivePackage(FROZEN.packageHash),
    ).rejects.toMatchObject({
      code: "chain_observation_unavailable",
    } satisfies Partial<ServiceRefusal>);
  });
});

describe("CasperRpcChainTransport authorization locator", () => {
  it("proves an unused nonce only at a stable finalized state-root boundary", async () => {
    const mock = new MockHttp();
    queueStableBoundary(mock);
    mock.queueRpc("state_get_dictionary_item", {
      error: {
        code: -32003,
        message: "Query failed",
        data: "value was not found in the global state",
      },
    });

    await expect(
      makeTransport(mock).locateSettlementByAuthorization({
        packageHashHex: FROZEN.packageHash,
        contractHashHex: FROZEN.contractHash,
        payerAccountHashHex: PAYER,
        payerPublicKeyHex: PUBLIC_KEY,
        authorizationNonceHex: NONCE,
      }),
    ).resolves.toEqual({
      found: false,
      observed: {
        finalized: true,
        blockHeight: 8_600_001,
        stateRootHash: ROOT,
      },
    });
    expect(mock.cloud).toHaveLength(0);
  });

  it("adopts exactly one used-nonce transaction only after exact RPC readback", async () => {
    const mock = new MockHttp();
    queueStableBoundary(mock);
    mock.queueRpc("state_get_dictionary_item", {
      result: {
        stored_value: {
          CLValue: {
            cl_type: "Bool",
            bytes: "01",
            parsed: true,
          },
        },
      },
    });
    mock.queueCloud(200, {
      item_count: 1,
      page_count: 1,
      data: [
        {
          deploy_hash: TX,
          contract_package_hash: FROZEN.packageHash,
          contract_hash: FROZEN.contractHash,
          status: "processed",
          error_message: null,
          args: {
            from: { cl_type: "Key", parsed: `account-hash-${PAYER}` },
            nonce: {
              cl_type: { List: "U8" },
              parsed: Array.from(Buffer.from(NONCE, "hex")),
            },
            public_key: { cl_type: "PublicKey", parsed: PUBLIC_KEY },
          },
        },
      ],
    });
    mock.queueRpc("info_get_transaction", { result: transactionResult() });
    mock.queueRpc("chain_get_block", { result: blockResult() });
    mock.queueRpc("state_get_package", { result: packageResult() });

    await expect(
      makeTransport(mock).locateSettlementByAuthorization({
        packageHashHex: FROZEN.packageHash,
        contractHashHex: FROZEN.contractHash,
        payerAccountHashHex: PAYER,
        payerPublicKeyHex: PUBLIC_KEY,
        authorizationNonceHex: NONCE,
      }),
    ).resolves.toEqual({ found: true, transactionHash: TX });

    const cloudCall = mock.calls.find((call) => call.url.includes("/deploys?"));
    expect(cloudCall?.authorization).toBe("raw-secret-token");
    expect(cloudCall?.url).toContain(
      `contract_package_hash=${FROZEN.packageHash}`,
    );
    expect(cloudCall?.url).toContain(
      `contract_hash=${FROZEN.contractHash}`,
    );
  });

  it("stays indeterminate when the nonce is used but no exact transaction is proven", async () => {
    const mock = new MockHttp();
    queueStableBoundary(mock);
    mock.queueRpc("state_get_dictionary_item", {
      result: {
        stored_value: {
          CLValue: { cl_type: "Bool", bytes: "01", parsed: true },
        },
      },
    });
    mock.queueCloud(200, { item_count: 0, page_count: 1, data: [] });

    await expect(
      makeTransport(mock).locateSettlementByAuthorization({
        packageHashHex: FROZEN.packageHash,
        contractHashHex: FROZEN.contractHash,
        payerAccountHashHex: PAYER,
        payerPublicKeyHex: PUBLIC_KEY,
        authorizationNonceHex: NONCE,
      }),
    ).rejects.toMatchObject({
      code: "chain_observation_unavailable",
    } satisfies Partial<ServiceRefusal>);
  });

  it("never reads or reflects an authorization-bearing CSPR.cloud error body", async () => {
    const mock = new MockHttp();
    queueStableBoundary(mock);
    mock.queueRpc("state_get_dictionary_item", {
      result: {
        stored_value: {
          CLValue: { cl_type: "Bool", bytes: "01", parsed: true },
        },
      },
    });
    const secret = "do-not-reflect-this-token";
    mock.queueCloud(401, {
      error: `bad authorization ${secret}`,
    });

    let caught: unknown;
    try {
      await makeTransport(mock, () => secret).locateSettlementByAuthorization({
        packageHashHex: FROZEN.packageHash,
        contractHashHex: FROZEN.contractHash,
        payerAccountHashHex: PAYER,
        payerPublicKeyHex: PUBLIC_KEY,
        authorizationNonceHex: NONCE,
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ServiceRefusal);
    expect(String(caught)).not.toContain(secret);
    expect((caught as ServiceRefusal).code).toBe(
      "chain_observation_unavailable",
    );
  });

  it("keeps the request deadline active while a successful response body streams", async () => {
    const secret = "raw-secret-token";
    const fetch = vi.fn(
      async (_input: string | URL | Request, init?: RequestInit) => {
        const signal = init?.signal;
        return new Response(
          new ReadableStream({
            start(controller) {
              signal?.addEventListener(
                "abort",
                () =>
                  controller.error(
                    new DOMException("request timed out", "AbortError"),
                  ),
                { once: true },
              );
            },
          }),
          { status: 200 },
        );
      },
    );
    const transport = new CasperRpcChainTransport({
      fetch: fetch as unknown as typeof globalThis.fetch,
      csprCloudToken: () => secret,
      requestTimeoutMs: 20,
    });

    await expect(
      transport.resolveActivePackage(FROZEN.packageHash),
    ).rejects.toMatchObject({
      code: "chain_observation_unavailable",
    } satisfies Partial<ServiceRefusal>);
  });

  it("never proves non-consumption from a moving or unsigned block snapshot", async () => {
    const mock = new MockHttp();
    for (let i = 0; i < 3; i += 1) {
      mock.queueRpc("chain_get_state_root_hash", {
        result: { state_root_hash: ROOT },
      });
      mock.queueRpc("chain_get_block", {
        result: {
          ...(blockResult() as Record<string, unknown>),
          block_with_signatures: {
            ...((blockResult() as Record<string, unknown>)[
              "block_with_signatures"
            ] as Record<string, unknown>),
            proofs: [],
          },
        },
      });
      mock.queueRpc("chain_get_state_root_hash", {
        result: { state_root_hash: ROOT },
      });
    }

    await expect(
      makeTransport(mock).locateSettlementByAuthorization({
        packageHashHex: FROZEN.packageHash,
        contractHashHex: FROZEN.contractHash,
        payerAccountHashHex: PAYER,
        payerPublicKeyHex: PUBLIC_KEY,
        authorizationNonceHex: NONCE,
      }),
    ).rejects.toMatchObject({
      code: "chain_observation_unavailable",
    } satisfies Partial<ServiceRefusal>);
  });
});

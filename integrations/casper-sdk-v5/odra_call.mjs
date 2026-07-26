#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import casperSdk from "casper-js-sdk";

const {
  Args,
  CLValue,
  ContractCallBuilder,
  HttpHandler,
  Key,
  KeyAlgorithm,
  PrivateKey,
  PublicKey,
  RpcClient,
} = casperSdk;

function stripHashPrefix(value) {
  return String(value || "").replace(/^(hash-|package-)/, "");
}

function accountAddress(publicKeyHex) {
  const publicKey = PublicKey.fromHex(String(publicKeyHex));
  const accountHash = publicKey.accountHash();
  const prefixed =
    typeof accountHash.toPrefixedString === "function"
      ? accountHash.toPrefixedString()
      : `account-hash-${Buffer.from(accountHash.hashBytes).toString("hex")}`;
  return CLValue.newCLKey(Key.newKey(prefixed));
}

function clValue(name, spec) {
  const clType = spec.cl_type ?? spec.type;
  const value = spec.value;
  if (clType === "String") return CLValue.newCLString(String(value ?? ""));
  if (clType === "U32") return CLValue.newCLUInt32(Number(value ?? 0));
  if (clType === "Bool") return CLValue.newCLValueBool(Boolean(value));
  if (clType === "Address") return accountAddress(value);
  if (clType && typeof clType === "object" && Number(clType.ByteArray) === 32) {
    const hex = String(value ?? "").replace(/^(sha256:|hash-)/, "");
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new Error(`${name} must be a 32-byte hex value`);
    }
    return CLValue.newCLByteArray(Uint8Array.from(Buffer.from(hex, "hex")));
  }
  throw new Error(`${name} has unsupported CL type ${JSON.stringify(clType)}`);
}

function argsFromSpec(specs) {
  const mapped = {};
  for (const [name, spec] of Object.entries(specs || {})) {
    mapped[name] = clValue(name, spec);
  }
  return Args.fromMap(mapped);
}

async function main() {
  const inputPath = process.argv[2];
  if (!inputPath) throw new Error("usage: odra_call.mjs <input.json>");
  const input = JSON.parse(await readFile(inputPath, "utf8"));
  const pem = await readFile(input.secret_key_path, "utf8");
  const keyAlgorithm = KeyAlgorithm[String(input.key_algorithm || "ED25519").toUpperCase()];
  const key = PrivateKey.fromPem(pem, keyAlgorithm);
  const rpc = new RpcClient(new HttpHandler(input.node_url || "https://node.testnet.casper.network/rpc"));
  const tx = new ContractCallBuilder()
    .byPackageHash(stripHashPrefix(input.package_hash))
    .entryPoint(input.entry_point)
    .runtimeArgs(argsFromSpec(input.argument_specs))
    .from(key.publicKey)
    .chainName(input.chain_name || "casper-test")
    .payment(Number(input.payment_motes || 5_000_000_000))
    .build();

  const txHash = tx.hash.toHex();
  if (input.dry_run) {
    console.log(JSON.stringify({ status: "dry_run_success", tx_hash: txHash }, null, 2));
    return;
  }

  tx.sign(key);
  await rpc.putTransaction(tx);
  let wait = null;
  try {
    wait = await rpc.waitForTransaction(tx, Number(input.wait_ms || 240_000));
  } catch (error) {
    wait = { error: error instanceof Error ? error.message : String(error) };
  }
  console.log(
    JSON.stringify(
      {
        status: wait && wait.error ? "broadcast_pending_or_failed" : "success",
        deploy_hash: txHash,
        transaction_hash: txHash,
        entry_point: input.entry_point,
        package_hash: input.package_hash,
        wait_result: wait,
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  console.error(JSON.stringify({ status: "failed", error: error instanceof Error ? error.stack : String(error) }));
  process.exitCode = 1;
});

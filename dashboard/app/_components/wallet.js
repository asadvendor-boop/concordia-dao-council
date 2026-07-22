// Browser wallet plumbing: CSPR.click SDK loading and direct Casper Wallet
// signing helpers. Behavior preserved from the pre-refactor monolith.
import { Buffer } from "buffer";
import { CLPublicKey, CLValueBuilder, DeployUtil, RuntimeArgs } from "casper-js-sdk";
import { api, shortHash } from "./lib";

function getCsprClickSdkGlobal() {
  if (typeof window === "undefined") return null;
  if (window.csprclick) return window.csprclick;
  if (window.CSPRClickSdk && typeof window.CSPRClickSdk === "function") {
    try {
      window.csprclick = new window.CSPRClickSdk();
      return window.csprclick;
    } catch {
      return null;
    }
  }
  return window.csprClick || null;
}

function waitForCsprClickSdk(timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    const startedAt = Date.now();
    const poll = () => {
      const sdk = getCsprClickSdkGlobal();
      if (sdk) {
        resolve(sdk);
        return;
      }
      if (Date.now() - startedAt >= timeoutMs) {
        reject(new Error("CSPR.click SDK loaded but did not expose a browser wallet global."));
        return;
      }
      window.setTimeout(poll, 200);
    };
    poll();
  });
}

export function loadCsprClickSdk() {
  if (typeof window === "undefined") return Promise.reject(new Error("Browser wallet signing requires a browser."));
  const loadedSdk = getCsprClickSdkGlobal();
  if (loadedSdk) return Promise.resolve(loadedSdk);
  const sdkUrls = [
    "https://cdn.cspr.click/ui/v2.1.0/csprclick-client-2.1.0.js",
    "https://cdn.cspr.click/ui/v2.0.0/csprclick-client-2.0.0.js",
    "https://cdn.cspr.click/latest/csprclick-sdk-2.1.js",
    "https://sdk.cspr.click/sdk-v1/csprclick-sdk.js",
  ];
  return new Promise((resolve, reject) => {
    const existing = document.querySelector('script[data-concordia-cspr-click="true"]');
    if (existing) {
      waitForCsprClickSdk().then(resolve).catch(reject);
      existing.addEventListener("error", reject, { once: true });
      return;
    }
    const sdkOptions = {
      appName: "Concordia DAO Council",
      appId: process.env.NEXT_PUBLIC_CSPR_CLICK_APP_ID || "csprclick-template",
      providers: ["casper-wallet", "casper-signer", "ledger", "metamask-snap"],
      contentMode: "IFRAME",
      uiContainer: "csprclick-ui",
      chainName: "casper-test",
    };
    window.clickSDKOptions = sdkOptions;
    window.clickUIOptions = {
      uiContainer: "csprclick-ui",
      rootAppElement: "body",
      defaultTheme: "dark",
    };
    window.csprClickSDKAsyncInit = () => {
      const sdk = getCsprClickSdkGlobal();
      if (!sdk) {
        reject(new Error("CSPR.click callback fired before the SDK global was available."));
        return;
      }
      try {
        if (typeof sdk.init === "function") sdk.init(sdkOptions);
      } catch (error) {
        reject(error);
        return;
      }
      resolve(sdk);
    };
    let settled = false;
    const onLoaded = () => {
      const sdk = getCsprClickSdkGlobal();
      if (!sdk || settled) return;
      settled = true;
      try {
        if (typeof sdk.init === "function") sdk.init(sdkOptions);
      } catch (error) {
        reject(error);
        return;
      }
      resolve(sdk);
    };
    window.addEventListener("csprclick:loaded", onLoaded);
    const tryUrl = (index = 0) => {
      if (settled) return;
      if (index >= sdkUrls.length) {
        window.removeEventListener("csprclick:loaded", onLoaded);
        reject(new Error(`CSPR.click SDK global was not available after trying ${sdkUrls.length} SDK URLs.`));
        return;
      }
      const script = document.createElement("script");
      script.src = sdkUrls[index];
      script.async = true;
      script.defer = true;
      script.dataset.concordiaCsprClick = "true";
      script.dataset.sdkUrlIndex = String(index);
      script.onload = () => {
        waitForCsprClickSdk(8000).then((sdk) => {
          if (settled) return;
          settled = true;
          window.removeEventListener("csprclick:loaded", onLoaded);
          if (typeof sdk.init === "function") sdk.init(sdkOptions);
          resolve(sdk);
        }).catch(() => {
          script.remove();
          tryUrl(index + 1);
        });
      };
      script.onerror = () => {
        script.remove();
        tryUrl(index + 1);
      };
      document.head.appendChild(script);
    };
    tryUrl();
  });
}

function waitForCsprClickPublicKey(sdk, timeoutMs = 30000) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let settled = false;
    const finish = (publicKey) => {
      if (settled || !publicKey) return;
      settled = true;
      cleanup();
      resolve(publicKey);
    };
    const cleanup = () => {
      try {
        sdk?.off?.("csprclick:signed_in", onAccountEvent);
        sdk?.off?.("csprclick:switched_account", onAccountEvent);
        sdk?.off?.("csprclick:unsolicited_account_change", onAccountEvent);
      } catch {
        // Some SDK versions expose `on` but not `off`; the timeout still guards completion.
      }
    };
    const onAccountEvent = async (event) => {
      finish(event?.account?.public_key || event?.account?.publicKey || await getCsprClickPublicKey(sdk));
    };
    try {
      sdk?.on?.("csprclick:signed_in", onAccountEvent);
      sdk?.on?.("csprclick:switched_account", onAccountEvent);
      sdk?.on?.("csprclick:unsolicited_account_change", onAccountEvent);
    } catch {
      // Event binding is best-effort; polling covers older SDKs.
    }
    const poll = async () => {
      finish(await getCsprClickPublicKey(sdk));
      if (settled) return;
      if (Date.now() - startedAt >= timeoutMs) {
        cleanup();
        resolve(null);
        return;
      }
      window.setTimeout(poll, 500);
    };
    poll();
  });
}

async function getCsprClickPublicKey(sdk) {
  if (sdk?.getActivePublicKey) {
    const direct = await Promise.resolve(sdk.getActivePublicKey()).catch(() => null);
    if (direct) return direct;
  }
  const active = await Promise.resolve(sdk?.getActiveAccount?.());
  if (active?.public_key) return active.public_key;
  if (active?.publicKey) return active.publicKey;
  const asyncActive = await Promise.resolve(sdk?.getActiveAccountAsync?.());
  if (asyncActive?.public_key) return asyncActive.public_key;
  if (asyncActive?.publicKey) return asyncActive.publicKey;
  return null;
}

async function initializeCsprClickProvider(sdk) {
  const providerName = "casper-wallet";
  if (typeof sdk?.getProviderInstance === "function") {
    await Promise.resolve(sdk.getProviderInstance(providerName)).catch(() => null);
  }
}

export async function connectCsprClickWallet(sdk) {
  const providerName = "casper-wallet";
  const existing = await getCsprClickPublicKey(sdk);
  if (existing) {
    await initializeCsprClickProvider(sdk);
    return existing;
  }
  if (typeof sdk?.signIn === "function") {
    await Promise.resolve(sdk.signIn()).catch(() => null);
    const signedIn = await waitForCsprClickPublicKey(sdk, 8000);
    if (signedIn) {
      await initializeCsprClickProvider(sdk);
      return signedIn;
    }
  }
  if (typeof sdk?.connect === "function") {
    const account = await sdk.connect(providerName).catch(() => null);
    const publicKey = account?.public_key || account?.publicKey;
    if (publicKey) {
      await initializeCsprClickProvider(sdk);
      return publicKey;
    }
  }
  if (typeof sdk?.signInWithAccount === "function") {
    await sdk.signInWithAccount({ provider: providerName }).catch(() => null);
  } else if (typeof sdk?.signIn === "function") {
    await Promise.resolve(sdk.signIn()).catch(() => null);
  }
  const publicKey = await waitForCsprClickPublicKey(sdk, 30000);
  if (publicKey) await initializeCsprClickProvider(sdk);
  return publicKey;
}

function sendCsprClickPayloadOnce(sdk, payload, publicKey) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const onStatus = (status, data) => {
      if (status) window.dispatchEvent(new CustomEvent("concordia:wallet-status", { detail: { status, data } }));
      if (!data || data.cancelled || data.error) return;
      const hash = extractWalletHash(data);
      if (hash) finish(data);
    };
    Promise.resolve(initializeCsprClickProvider(sdk))
      .then(() => sdk.send(payload, publicKey.toLowerCase(), onStatus, 150))
      .then((result) => finish(result))
      .catch((error) => {
        if (settled) return;
        settled = true;
        reject(error);
      });
  });
}

export async function sendCsprClickPayload(sdk, payload, publicKey) {
  try {
    return await sendCsprClickPayloadOnce(sdk, payload, publicKey);
  } catch (error) {
    const message = String(error?.message || error || "");
    if (!/sign\\s*in|signed\\s*out|connect/i.test(message)) throw error;
    if (typeof sdk?.signIn === "function") await Promise.resolve(sdk.signIn()).catch(() => null);
    const activePublicKey = await waitForCsprClickPublicKey(sdk, 15000);
    if (!activePublicKey) throw error;
    await initializeCsprClickProvider(sdk);
    return await sendCsprClickPayloadOnce(sdk, payload, activePublicKey);
  }
}

function getCasperWalletProvider() {
  if (typeof window === "undefined") return null;
  if (typeof window.CasperWalletProvider === "function") {
    return window.CasperWalletProvider(window);
  }
  return window.CasperWalletProvider || window.casperWallet || null;
}

function hexFromWalletSignature(value) {
  if (!value) return "";
  if (typeof value === "string") return value.replace(/^0x/i, "");
  if (value instanceof Uint8Array) {
    return Array.from(value).map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  if (Array.isArray(value)) {
    return value.map((byte) => Number(byte).toString(16).padStart(2, "0")).join("");
  }
  if (value?.data && Array.isArray(value.data)) {
    return value.data.map((byte) => Number(byte).toString(16).padStart(2, "0")).join("");
  }
  return "";
}

function clValueFromWalletArg(name, arg) {
  const clType = arg?.cl_type;
  const value = arg?.value;
  if (clType === "String") {
    return CLValueBuilder.string(String(value ?? ""));
  }
  if (clType === "U32") {
    const parsed = Number(value ?? 0);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0xffffffff) {
      throw new Error(`${name} must be a valid Casper U32`);
    }
    return CLValueBuilder.u32(parsed);
  }
  if (clType && typeof clType === "object" && Number(clType.ByteArray) === 32) {
    const hex = String(value ?? "").replace(/^0x/i, "");
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      throw new Error(`${name} must be a 32-byte hex root`);
    }
    return CLValueBuilder.byteArray(Uint8Array.from(Buffer.from(hex, "hex")));
  }
  throw new Error(`${name} has unsupported Casper CL type`);
}

export function buildCasperWalletDeploy(unsigned, publicKey) {
  const typedArgs = unsigned?.typed_runtime_args || {};
  const runtimeArgs = {};
  for (const [name, arg] of Object.entries(typedArgs)) {
    runtimeArgs[name] = clValueFromWalletArg(name, arg);
  }
  const contractHash = String(unsigned?.contract_hash || "").replace(/^hash-/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(contractHash)) {
    throw new Error("Unsigned package is missing a valid contract hash");
  }
  const account = CLPublicKey.fromHex(publicKey);
  const deployParams = new DeployUtil.DeployParams(account, unsigned?.chain_name || "casper-test");
  const hashBytes = Uint8Array.from(Buffer.from(contractHash, "hex"));
  const entryPoint = unsigned?.entry_point || "store_governance_receipt";
  const args = RuntimeArgs.fromMap(runtimeArgs);
  const session = String(unsigned?.call_target || "contract").toLowerCase() === "package"
    ? DeployUtil.ExecutableDeployItem.newStoredVersionContractByHash(
      hashBytes,
      Number.isInteger(Number(unsigned?.contract_version)) ? Number(unsigned.contract_version) : null,
      entryPoint,
      args,
    )
    : DeployUtil.ExecutableDeployItem.newStoredContractByHash(
      hashBytes,
      entryPoint,
      args,
    );
  const payment = DeployUtil.standardPayment(Number(unsigned?.payment_amount || 5000000000));
  return DeployUtil.makeDeploy(deployParams, session, payment);
}

function attachCasperWalletApproval(deploy, signed, publicKey) {
  const rawSignature = hexFromWalletSignature(signed?.signatureHex || signed?.signature);
  if (!rawSignature) throw new Error("Casper Wallet did not return a signature.");
  const signatureBytes = Uint8Array.from(Buffer.from(rawSignature.replace(/^(01|02)(?=[0-9a-fA-F]{128}$)/i, ""), "hex"));
  const signedDeploy = DeployUtil.setSignature(deploy, signatureBytes, CLPublicKey.fromHex(publicKey));
  return DeployUtil.deployToJson(signedDeploy);
}

async function connectCasperWalletDirect() {
  const provider = getCasperWalletProvider();
  if (!provider) throw new Error("Casper Wallet extension was not found.");
  let publicKey = await Promise.resolve(provider.getActivePublicKey?.()).catch(() => null);
  if (publicKey) return { provider, publicKey };
  if (typeof provider.requestConnection === "function") {
    await provider.requestConnection({ title: document.title }).catch((error) => {
      throw new Error(error?.message || "Casper Wallet connection was rejected.");
    });
  }
  await new Promise((resolve) => window.setTimeout(resolve, 800));
  publicKey = await Promise.resolve(provider.getActivePublicKey?.()).catch(() => null);
  if (!publicKey) throw new Error("No active Casper Wallet account selected.");
  return { provider, publicKey };
}

export async function signWithCasperWalletDirect(proposalId, setWalletStatus, setWalletReceiptHash, intentBasePath = "/cspr-click/unsigned-receipt") {
  setWalletStatus("connecting-casper-wallet");
  const { provider, publicKey } = await connectCasperWalletDirect();
  setWalletStatus("building-casper-wallet-deploy");
  const unsigned = await api(
    `${intentBasePath}/${encodeURIComponent(proposalId)}?signer_public_key=${encodeURIComponent(publicKey)}`,
  );
  if (unsigned.status !== "ready") throw new Error(unsigned.error || "Unsigned deploy package was not ready.");
  const deploy = buildCasperWalletDeploy(unsigned, publicKey);
  const deployEnvelope = DeployUtil.deployToJson(deploy);
  setWalletStatus("awaiting-casper-wallet-signature");
  const signed = await provider.sign(JSON.stringify(deployEnvelope), publicKey);
  if (signed?.cancelled) throw new Error("Signing was cancelled in Casper Wallet.");
  const signedDeploy = attachCasperWalletApproval(deploy, signed, publicKey);
  setWalletStatus("broadcasting-wallet-deploy");
  const broadcast = await api("/casper/broadcast-deploy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(signedDeploy),
    timeoutMs: 90000,
  });
  const walletHash = broadcast?.deploy_hash || broadcast?.transaction_hash || signedDeploy?.deploy?.hash || unsigned.deploy_hash;
  if (walletHash) {
    setWalletStatus(`wallet-finalized:${shortHash(walletHash, 10, 6)}`);
    setWalletReceiptHash?.(walletHash);
  } else {
    setWalletStatus("wallet-broadcasted");
  }
  return broadcast;
}

export function extractWalletHash(result, fallbackHash) {
  return (
    result?.transactionHash ||
    result?.deployHash ||
    result?.hash ||
    result?.transaction_hash ||
    result?.deploy_hash ||
    fallbackHash ||
    ""
  );
}

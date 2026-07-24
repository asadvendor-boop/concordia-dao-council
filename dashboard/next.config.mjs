import {
  deterministicBuildId,
  productionPublicBuildInputs,
} from "./scripts/deterministic-build-id.mjs";

const root = import.meta.dirname;
const publicBuildInputs = productionPublicBuildInputs(process.env);

/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: "/dashboard",
  env: publicBuildInputs,
  generateBuildId: async () => deterministicBuildId(root, publicBuildInputs),
  outputFileTracingRoot: root,
  turbopack: {
    root: root,
  },
  // Removed output: "standalone" — use `npx next start` for deployment
  // Removed unused rewrites proxy — dashboard reads from NEXT_PUBLIC_GATEWAY_URL directly
};

export default nextConfig;

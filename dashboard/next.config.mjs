import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: "/dashboard",
  turbopack: {
    root: __dirname,
  },
  // Removed output: "standalone" — use `npx next start` for deployment
  // Removed unused rewrites proxy — dashboard reads from NEXT_PUBLIC_GATEWAY_URL directly
};

export default nextConfig;

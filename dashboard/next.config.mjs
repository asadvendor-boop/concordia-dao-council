const BUILD_ID_PATTERN = /^concordia-[0-9a-f]{64}$/;

async function configuredBuildId() {
  const buildId = process.env.CONCORDIA_DASHBOARD_BUILD_ID;
  if (typeof buildId !== "string" || !BUILD_ID_PATTERN.test(buildId)) {
    throw new Error(
      "CONCORDIA_DASHBOARD_BUILD_ID must be set by the deterministic build wrapper",
    );
  }
  return buildId;
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  basePath: "/dashboard",
  generateBuildId: configuredBuildId,
  // Removed output: "standalone" — use `npx next start` for deployment
  // Removed unused rewrites proxy — dashboard reads from NEXT_PUBLIC_GATEWAY_URL directly
};

export default nextConfig;

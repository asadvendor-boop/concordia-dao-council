/**
 * Vitest config for the official x402 settlement service.
 *
 * The cross-language schema-drift suite imports the dashboard's provenance
 * module (dashboard/app/_components/provenance.js) AS-IS by relative path.
 * Those files are plain ESM containing JSX in .js files (compiled by Next in
 * the dashboard's own build), so this config adds a scoped esbuild transform
 * for exactly that directory — nothing else in this service is affected, and
 * the dashboard files themselves are never modified.
 */
import { transform } from "esbuild";
import { defineConfig, type Plugin } from "vitest/config";

const DASHBOARD_COMPONENTS_RE = /[\\/]dashboard[\\/]app[\\/]_components[\\/][^\\/]+\.js$/;

function dashboardJsx(): Plugin {
  return {
    name: "concordia-dashboard-jsx",
    enforce: "pre",
    async transform(code, id) {
      if (!DASHBOARD_COMPONENTS_RE.test(id)) return null;
      const result = await transform(code, {
        loader: "jsx",
        jsx: "automatic",
        format: "esm",
        sourcefile: id,
      });
      return { code: result.code, map: null };
    },
  };
}

export default defineConfig({
  plugins: [dashboardJsx()],
  test: {
    environment: "node",
  },
});

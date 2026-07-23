/**
 * Vitest config for the official x402 settlement service.
 *
 * The cross-language schema-drift suite imports the dashboard's PURE
 * validation module (dashboard/app/_components/provenance-pure.js), which is
 * JSX-free and dependency-free by contract — so no transform plugin and no
 * dashboard install is needed. Keep it that way: reintroducing a JSX/dashboard
 * import here would silently couple this service's test run to a sibling
 * dashboard/node_modules that a clean checkout does not have.
 */
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
  },
});

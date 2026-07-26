import { defineConfig, devices } from "@playwright/test";

const PORT = process.env.CONCORDIA_DASHBOARD_TEST_PORT || "3105";
const baseURL = process.env.CONCORDIA_DASHBOARD_BASE_URL || `http://127.0.0.1:${PORT}`;

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  expect: { timeout: 6_000 },
  fullyParallel: false,
  reporter: [["list"]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  webServer: process.env.CONCORDIA_DASHBOARD_BASE_URL
    ? undefined
    : {
        command: `npm run start -- --hostname 127.0.0.1 --port ${PORT}`,
        url: `${baseURL}/dashboard`,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 900 },
      },
    },
  ],
});

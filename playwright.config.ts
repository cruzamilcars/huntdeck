import { defineConfig } from "@playwright/test";

const python = process.platform === "win32" ? "py -3" : "python3";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? [["list"]] : [["list"]],
  use: {
    baseURL: "http://127.0.0.1:3000",
    trace: "on-first-retry",
  },
  webServer: [
    {
      command: `${python} -m uvicorn app.main:app --host 127.0.0.1 --port 8000`,
      cwd: "./apps/api",
      env: { MCP_MOCK_ALL: "1" },
      url: "http://127.0.0.1:8000/api/v1/system/providers",
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
    {
      // Run against a production build. `next dev` (Turbopack) returns 403 for
      // every _next/static/chunks/* script inside headless Chromium while the
      // same URLs serve 200 over plain HTTP, so dev mode is unusable for e2e.
      // Build bakes the NEXT_PUBLIC_* env vars, so the API/supabase overrides
      // must be present here (they also win over apps/web/.env.local).
      command: "npm run build && npm run start",
      cwd: "./apps/web",
      env: {
        NEXT_PUBLIC_API_BASE_URL: "http://127.0.0.1:8000",
        NEXT_PUBLIC_SUPABASE_URL: "",
        NEXT_PUBLIC_SUPABASE_ANON_KEY: "",
        PORT: "3000",
      },
      url: "http://127.0.0.1:3000",
      reuseExistingServer: false,
      timeout: 240_000,
    },
  ],
});
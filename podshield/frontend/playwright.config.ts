import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig, devices } from "@playwright/test";

const here = path.dirname(fileURLToPath(import.meta.url));

/**
 * BASE_URL picks the app under test:
 *
 *   unset                       start the self-contained demo server (fake Podman, real API/DB/UI)
 *   BASE_URL=http://rhel-vm:8000  run against a real install; nothing is started locally
 *
 * Browsers do not need to live on the RHEL VM. Run `npx playwright test` from a laptop with
 * BASE_URL pointing at the VM (firewalld must allow the port, or use an SSH tunnel:
 * `ssh -L 8000:127.0.0.1:8000 user@vm` and BASE_URL=http://127.0.0.1:8000).
 */
const external = process.env.BASE_URL || undefined; // `make` passes an empty string when unset
const port = Number(process.env.E2E_PORT ?? 8765);
const baseURL = external ?? `http://127.0.0.1:${port}`;

const backend = path.resolve(here, "../backend");
const python = process.env.E2E_PYTHON ?? path.join(backend, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./e2e/.results",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false, // tests share one server and one database
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "e2e/.report" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    ...devices["Desktop Chrome"],
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: external
    ? undefined
    : {
        command: `"${python}" -m tests.e2e_server --port ${port}`,
        cwd: backend,
        url: `${baseURL}/api/health`,
        reuseExistingServer: !process.env.CI,
        timeout: 60_000,
        stdout: "ignore",
        stderr: "pipe",
      },
});

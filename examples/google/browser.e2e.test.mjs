import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const ORIGIN = "http://localhost:8766";
const PROJECT_ROOT = fileURLToPath(new URL("../..", import.meta.url));

async function waitForServer(server, output) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`Server exited early: ${output.value}`);
    try {
      const response = await fetch(`${ORIGIN}/health`);
      if (response.ok) return;
    } catch {
      // The process is still starting.
    }
    await delay(250);
  }
  throw new Error(`Server did not become ready: ${output.value}`);
}

function startServer() {
  const output = { value: "" };
  const server = spawn(
    "uv",
    [
      "run",
      "uvicorn",
      "examples.google.e2e_server:api_app",
      "--host",
      "127.0.0.1",
      "--port",
      "8766",
    ],
    { cwd: PROJECT_ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  const collect = (chunk) => {
    output.value = `${output.value}${chunk}`.slice(-8000);
  };
  server.stdout.on("data", collect);
  server.stderr.on("data", collect);
  return { server, output };
}

const fakeGoogleSdk = `
  let callback;
  let attempts = 0;
  window.__googleOptions = [];
  window.google = { accounts: { id: {
    initialize(options) {
      callback = options.callback;
      window.__googleOptions.push({
        client_id: options.client_id,
        nonce: options.nonce,
        auto_select: options.auto_select,
      });
    },
    renderButton(container) {
      const button = document.createElement("button");
      button.id = "google-proof-button";
      button.textContent = "Continue with Google";
      button.onclick = () => {
        attempts += 1;
        callback({ credential: attempts === 1 ? "invalid-proof" : "browser-proof" });
      };
      container.replaceChildren(button);
    }
  } } };
`;

test("Chromium completes the Google button and epok-auth session flow", { timeout: 60_000 }, async () => {
  const sandbox = startServer();
  let browser;
  try {
    await waitForServer(sandbox.server, sandbox.output);
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    await context.route("https://accounts.google.com/gsi/client", (route) =>
      route.fulfill({ status: 200, contentType: "text/javascript", body: fakeGoogleSdk }),
    );
    const page = await context.newPage();
    await page.goto(ORIGIN);
    const firstOptions = await page.evaluate(() => window.__googleOptions[0]);
    assert.equal(firstOptions.client_id, "123456789-browser.apps.googleusercontent.com");
    assert.equal(firstOptions.auto_select, false);
    assert.ok(firstOptions.nonce.length >= 32);
    await page.locator("#google-proof-button").click();
    await page.waitForFunction(() => document.querySelector("#status")?.dataset.tone === "error");
    assert.deepEqual(await context.cookies(ORIGIN), []);

    const nonces = await page.evaluate(() => window.__googleOptions.map((item) => item.nonce));
    assert.equal(nonces.length, 2);
    assert.notEqual(nonces[0], nonces[1]);

    await page.locator("#google-proof-button").click();
    await page.waitForFunction(() => !document.querySelector("#session-result")?.hidden);
    assert.equal(await page.locator("#result-name").textContent(), "Browser proof");
    assert.equal(await page.locator("#result-email").textContent(), "browser@gmail.com");
    assert.match(await page.locator("#status").textContent(), /Acceso confirmado/);
    const cookies = await context.cookies(ORIGIN);
    assert.deepEqual(
      cookies.map((cookie) => cookie.name).sort(),
      ["epok_csrf", "epok_refresh"],
    );
    assert.equal(cookies.every((cookie) => cookie.httpOnly), true);
  } finally {
    await browser?.close();
    if (sandbox.server.exitCode === null) sandbox.server.kill("SIGTERM");
  }
});

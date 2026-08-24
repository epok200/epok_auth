import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const PROJECT_ROOT = fileURLToPath(new URL("../..", import.meta.url));

async function availableOrigin() {
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", resolve);
  });
  const address = probe.address();
  assert.equal(typeof address, "object");
  assert.notEqual(address, null);
  await new Promise((resolve, reject) => {
    probe.close((error) => (error ? reject(error) : resolve()));
  });
  return `http://127.0.0.1:${address.port}`;
}

async function waitForServer(server, output, origin) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`Server exited early: ${output.value}`);
    try {
      const response = await fetch(`${origin}/health`);
      if (response.ok) return;
    } catch {
      // The process is still starting.
    }
    await delay(250);
  }
  throw new Error(`Server did not become ready: ${output.value}`);
}

function startServer(origin) {
  const port = new URL(origin).port;
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
      port,
    ],
    {
      cwd: PROJECT_ROOT,
      env: { ...process.env, EPOK_AUTH_BROWSER_ORIGIN: origin },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const collect = (chunk) => {
    output.value = `${output.value}${chunk}`.slice(-8000);
  };
  server.stdout.on("data", collect);
  server.stderr.on("data", collect);
  return { server, output };
}

async function startSandbox() {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const origin = await availableOrigin();
    const sandbox = startServer(origin);
    try {
      await waitForServer(sandbox.server, sandbox.output, origin);
      return { ...sandbox, origin };
    } catch (error) {
      lastError = error;
      if (sandbox.server.exitCode === null) sandbox.server.kill("SIGTERM");
      if (!/address already in use/i.test(sandbox.output.value)) throw error;
    }
  }
  throw lastError;
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
  const sandbox = await startSandbox();
  const { origin } = sandbox;
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    await context.route("https://accounts.google.com/gsi/client", (route) =>
      route.fulfill({ status: 200, contentType: "text/javascript", body: fakeGoogleSdk }),
    );
    const page = await context.newPage();
    await page.goto(origin);
    const firstOptions = await page.evaluate(() => window.__googleOptions[0]);
    assert.equal(firstOptions.client_id, "123456789-browser.apps.googleusercontent.com");
    assert.equal(firstOptions.auto_select, false);
    assert.ok(firstOptions.nonce.length >= 32);
    await page.locator("#google-proof-button").click();
    await page.waitForFunction(() => document.querySelector("#status")?.dataset.tone === "error");
    assert.deepEqual(await context.cookies(origin), []);

    const nonces = await page.evaluate(() => window.__googleOptions.map((item) => item.nonce));
    assert.equal(nonces.length, 2);
    assert.notEqual(nonces[0], nonces[1]);

    await page.locator("#google-proof-button").click();
    await page.waitForFunction(() => !document.querySelector("#session-result")?.hidden);
    assert.equal(await page.locator("#result-name").textContent(), "Browser proof");
    assert.equal(await page.locator("#result-email").textContent(), "browser@gmail.com");
    assert.match(await page.locator("#status").textContent(), /Acceso confirmado/);
    const cookies = await context.cookies(origin);
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

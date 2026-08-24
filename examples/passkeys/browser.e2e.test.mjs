import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const API_ORIGIN = "http://localhost:8765";
const PROJECT_ROOT = fileURLToPath(new URL("../..", import.meta.url));

async function waitForServer(server, output, url) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (server.exitCode !== null) {
      throw new Error(`E2E server exited early: ${output.value}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // The process is still starting.
    }
    await delay(250);
  }
  throw new Error(`E2E server did not become ready: ${output.value}`);
}

function startServer(application, port) {
  const output = { value: "" };
  const server = spawn(
    "uv",
    [
      "run",
      "uvicorn",
      `examples.passkeys.e2e_server:${application}`,
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
    ],
    {
      cwd: PROJECT_ROOT,
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

function assertSessionCookies(cookies) {
  assert.deepEqual(
    cookies.map((cookie) => cookie.name).sort(),
    ["epok_csrf", "epok_refresh"],
  );
  assert.equal(cookies.every((cookie) => cookie.httpOnly), true);
  assert.equal(cookies.every((cookie) => cookie.sameSite === "Lax"), true);
}

test("Chromium completes the real passkey HTTP flow", { timeout: 60_000 }, async () => {
  const sandbox = startServer("api_app", 8765);
  let browser;
  try {
    await waitForServer(sandbox.server, sandbox.output, `${API_ORIGIN}/health`);
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    await page.goto(API_ORIGIN);

    await page.evaluate(() => {
      Object.defineProperty(navigator.credentials, "create", {
        configurable: true,
        value: () => Promise.reject(new DOMException("Canceled", "NotAllowedError")),
      });
    });
    await page.locator("#register-button").click();
    await page.waitForFunction(() => document.querySelector("#status")?.dataset.tone === "error");
    assert.match(await page.locator("#status").textContent(), /Chrome canceló/);
    assert.deepEqual(await context.cookies(API_ORIGIN), []);
    await page.evaluate(() => {
      delete navigator.credentials.create;
    });

    await page.locator("#register-button").click();
    await page.waitForFunction(() => document.querySelector("#status")?.dataset.tone === "success");
    assert.match(await page.locator("#status").textContent(), /Passkey lista/);
    assert.deepEqual(await context.cookies(API_ORIGIN), []);

    await page.locator("#login-button").click();
    await page.waitForFunction(() => !document.querySelector("#session-result")?.hidden);
    assert.equal(await page.locator("#result-name").textContent(), "Browser proof");
    assert.equal(await page.locator("#result-email").textContent(), "browser@example.com");
    assert.match(await page.locator("#status").textContent(), /Acceso confirmado/);
    const passkeyCookies = await context.cookies(API_ORIGIN);

    const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
    assert.equal(credentials.length, 1);
    assert.equal(credentials[0].isResidentCredential, true);
    assert.ok(credentials[0].signCount >= 1);
    assertSessionCookies(passkeyCookies);
  } finally {
    await browser?.close();
    if (sandbox.server.exitCode === null) {
      sandbox.server.kill("SIGTERM");
    }
  }
});

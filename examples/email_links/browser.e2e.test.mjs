import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const ORIGIN = "http://localhost:8767";
const ROOT = fileURLToPath(new URL("../..", import.meta.url));

async function waitForServer(server, output) {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`E2E server exited: ${output.value}`);
    try {
      const response = await fetch(`${ORIGIN}/health`);
      if (response.ok) return;
    } catch {
      // The process is still starting.
    }
    await delay(250);
  }
  throw new Error(`E2E server did not become ready: ${output.value}`);
}

function startServer() {
  const output = { value: "" };
  const server = spawn(
    "uv",
    [
      "run",
      "uvicorn",
      "examples.email_links.e2e_server:api_app",
      "--host",
      "127.0.0.1",
      "--port",
      "8767",
    ],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  const collect = (chunk) => {
    output.value = `${output.value}${chunk}`.slice(-8000);
  };
  server.stdout.on("data", collect);
  server.stderr.on("data", collect);
  return { server, output };
}

test("Chromium clears the fragment and enforces browser binding", { timeout: 45_000 }, async () => {
  const sandbox = startServer();
  let browser;
  try {
    await waitForServer(sandbox.server, sandbox.output);
    browser = await chromium.launch({ headless: true });
    const ownerContext = await browser.newContext();
    const ownerPage = await ownerContext.newPage();
    const consumeUrls = [];
    ownerPage.on("request", (request) => {
      if (request.url().includes("/login/consume")) consumeUrls.push(request.url());
    });
    await ownerPage.goto(ORIGIN);

    const actionUrl = await ownerPage.evaluate(async () => {
      const requested = await fetch("/api/v1/auth/email-links/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "browser@example.com" }),
      });
      if (!requested.ok) throw new Error(`request failed: ${requested.status}`);
      const delivered = await fetch("/test/latest-link", { cache: "no-store" });
      return (await delivered.json()).url;
    });
    assert.match(actionUrl, /\/magic#token=/);

    const foreignContext = await browser.newContext();
    const foreignPage = await foreignContext.newPage();
    await foreignPage.goto(actionUrl);
    await foreignPage.waitForFunction(
      () => document.querySelector("#status")?.dataset.tone === "error",
    );
    assert.equal(foreignPage.url(), `${ORIGIN}/magic`);
    assert.deepEqual(await foreignContext.cookies(ORIGIN), []);

    await ownerPage.goto(actionUrl);
    await ownerPage.waitForFunction(
      () => document.querySelector("#status")?.dataset.tone === "success",
    );
    assert.equal(ownerPage.url(), `${ORIGIN}/magic`);
    assert.equal(await ownerPage.locator("#result-email").textContent(), "browser@example.com");
    assert.deepEqual(consumeUrls, [`${ORIGIN}/api/v1/auth/email-links/login/consume`]);
    const cookies = await ownerContext.cookies(ORIGIN);
    assert.deepEqual(
      cookies.map((cookie) => cookie.name).sort(),
      ["epok_csrf", "epok_refresh"],
    );
    assert.equal(cookies.every((cookie) => cookie.httpOnly), true);
    assert.equal(cookies.every((cookie) => cookie.sameSite === "Lax"), true);
  } finally {
    await browser?.close();
    if (sandbox.server.exitCode === null) sandbox.server.kill("SIGTERM");
  }
});

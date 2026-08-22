import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const FRONTEND_ORIGIN = "http://localhost:8766";
const API_ORIGIN = "http://localhost:8765";
const API = `${API_ORIGIN}/api/v1/auth`;
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
  const api = startServer("api_app", 8765);
  const frontend = startServer("frontend_app", 8766);
  let browser;
  try {
    await Promise.all([
      waitForServer(api.server, api.output, `${API_ORIGIN}/health`),
      waitForServer(frontend.server, frontend.output, FRONTEND_ORIGIN),
    ]);
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
    await page.goto(FRONTEND_ORIGIN);

    const registration = await page.evaluate(async ({ api }) => {
      const helper = await import("/browser.js");
      const loginResponse = await fetch(`${api}/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "browser@example.com",
          password: "browser passkey proof password",
        }),
      });
      if (!loginResponse.ok) {
        throw new Error(`Password login failed: ${loginResponse.status}`);
      }
      const passwordSession = await loginResponse.json();
      const registered = await helper.registerPasskey({
        baseUrl: api,
        accessToken: passwordSession.access_token,
        name: "Chromium virtual passkey",
      });
      const firstList = await helper.listPasskeys({
        baseUrl: api,
        accessToken: passwordSession.access_token,
      });
      return { passwordSession, registered, firstList };
    }, { api: API });

    const passwordCookies = await context.cookies(API_ORIGIN);
    assertSessionCookies(passwordCookies);

    const logout = await page.evaluate(async ({ api, csrfToken, accessToken }) => {
      const logoutResponse = await fetch(`${api}/logout`, {
        method: "POST",
        credentials: "include",
        headers: { "X-CSRF-Token": csrfToken },
      });
      if (logoutResponse.status !== 204) {
        throw new Error(`Password logout failed: ${logoutResponse.status}`);
      }
      const meAfterLogout = await fetch(`${api}/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      return {
        logoutStatus: logoutResponse.status,
        passwordTokenStatus: meAfterLogout.status,
      };
    }, {
      api: API,
      csrfToken: registration.passwordSession.csrf_token,
      accessToken: registration.passwordSession.access_token,
    });

    assert.deepEqual(await context.cookies(API_ORIGIN), []);

    const result = await page.evaluate(async ({ api, passkeyId }) => {
      const helper = await import("/browser.js");
      const passkeySession = await helper.authenticateWithPasskey({ baseUrl: api });
      const meResponse = await fetch(`${api}/me`, {
        headers: { Authorization: `Bearer ${passkeySession.access_token}` },
      });
      const me = await meResponse.json();
      const revoked = await helper.revokePasskey({
        baseUrl: api,
        accessToken: passkeySession.access_token,
        passkeyId,
      });
      const finalList = await helper.listPasskeys({
        baseUrl: api,
        accessToken: passkeySession.access_token,
      });
      return {
        passkeySession,
        me,
        revoked,
        finalList,
      };
    }, { api: API, passkeyId: registration.registered.id });

    const passkeyCookies = await context.cookies(API_ORIGIN);

    const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
    assert.equal(registration.registered.name, "Chromium virtual passkey");
    assert.equal(registration.firstList.items.length, 1);
    assert.equal(logout.logoutStatus, 204);
    assert.equal(logout.passwordTokenStatus, 401);
    assert.ok(result.passkeySession.access_token);
    assert.equal(result.me.email, "browser@example.com");
    assert.equal(result.revoked, null);
    assert.deepEqual(result.finalList, { items: [] });
    assert.equal(credentials.length, 1);
    assert.equal(credentials[0].isResidentCredential, true);
    assert.ok(credentials[0].signCount >= 1);
    assertSessionCookies(passkeyCookies);
  } finally {
    await browser?.close();
    for (const process of [api.server, frontend.server]) {
      if (process.exitCode === null) {
        process.kill("SIGTERM");
      }
    }
  }
});

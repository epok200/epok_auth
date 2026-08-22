import assert from "node:assert/strict";
import test from "node:test";

import {
  authenticateWithPasskey,
  listPasskeys,
  registerPasskey,
  revokePasskey,
} from "./browser.js";

class TestCredential {
  constructor(kind) {
    this.id = "AQID";
    this.rawId = Uint8Array.from([1, 2, 3]).buffer;
    this.type = "public-key";
    this.authenticatorAttachment = "platform";
    this.kind = kind;
    if (kind === "registration") {
      this.response = {
        clientDataJSON: Uint8Array.from([4, 5]).buffer,
        attestationObject: Uint8Array.from([6, 7]).buffer,
        getTransports: () => ["internal"],
      };
    } else {
      this.response = {
        clientDataJSON: Uint8Array.from([8, 9]).buffer,
        authenticatorData: Uint8Array.from([10, 11]).buffer,
        signature: Uint8Array.from([12, 13]).buffer,
        userHandle: Uint8Array.from([14, 15]).buffer,
      };
    }
  }

  getClientExtensionResults() {
    return {};
  }
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

test("browser helper completes registration, authentication and management", async () => {
  Object.defineProperty(globalThis, "PublicKeyCredential", {
    value: TestCredential,
    configurable: true,
  });
  Object.defineProperty(globalThis, "navigator", {
    value: {
      credentials: {
        create: async ({ publicKey }) => {
          assert.ok(publicKey.challenge instanceof Uint8Array);
          assert.ok(publicKey.user.id instanceof Uint8Array);
          assert.ok(publicKey.excludeCredentials[0].id instanceof Uint8Array);
          return new TestCredential("registration");
        },
        get: async ({ publicKey }) => {
          assert.ok(publicKey.challenge instanceof Uint8Array);
          return new TestCredential("authentication");
        },
      },
    },
    configurable: true,
  });

  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith("/registration/options")) {
      return jsonResponse({
        ceremony_id: "registration-id",
        publicKey: {
          challenge: "AQID",
          user: { id: "BAUG", name: "user@example.com", displayName: "User" },
          excludeCredentials: [{ id: "BwgJ", type: "public-key" }],
        },
      });
    }
    if (url.endsWith("/registration/verify")) {
      return jsonResponse({ id: "passkey-id", name: "Laptop" }, 201);
    }
    if (url.endsWith("/authentication/options")) {
      return jsonResponse({
        ceremony_id: "authentication-id",
        publicKey: { challenge: "AQID", allowCredentials: [] },
      });
    }
    if (url.endsWith("/authentication/verify")) {
      return jsonResponse({ access_token: "access-token" });
    }
    if (options.method === "DELETE") {
      return new Response(null, { status: 204 });
    }
    return jsonResponse({ items: [{ id: "passkey-id" }] });
  };

  const registered = await registerPasskey({
    baseUrl: "https://api.example.com/auth",
    accessToken: "password-token",
    name: "Laptop",
  });
  const authenticated = await authenticateWithPasskey({
    baseUrl: "https://api.example.com/auth",
  });
  const listed = await listPasskeys({
    baseUrl: "https://api.example.com/auth",
    accessToken: "access-token",
  });
  const revoked = await revokePasskey({
    baseUrl: "https://api.example.com/auth",
    accessToken: "access-token",
    passkeyId: "passkey-id",
  });

  assert.equal(registered.id, "passkey-id");
  assert.equal(authenticated.access_token, "access-token");
  assert.equal(listed.items[0].id, "passkey-id");
  assert.equal(revoked, null);
  assert.equal(calls.length, 6);

  const registrationBody = JSON.parse(calls[1].options.body);
  assert.equal(registrationBody.ceremony_id, "registration-id");
  assert.equal(registrationBody.credential.rawId, "AQID");
  assert.equal(registrationBody.credential.response.attestationObject, "Bgc");

  const authenticationBody = JSON.parse(calls[3].options.body);
  assert.equal(authenticationBody.ceremony_id, "authentication-id");
  assert.equal(authenticationBody.credential.response.userHandle, "Dg8");
});

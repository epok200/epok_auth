function base64urlToBytes(value) {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = (value + padding).replaceAll("-", "+").replaceAll("_", "/");
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

function bytesToBase64url(value) {
  const bytes = new Uint8Array(value);
  const binary = Array.from(bytes, (item) => String.fromCharCode(item)).join("");
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function requireWebAuthn() {
  if (!globalThis.PublicKeyCredential || !globalThis.navigator?.credentials) {
    throw new Error("This browser does not support WebAuthn passkeys");
  }
}

function creationOptions(publicKey) {
  return {
    ...publicKey,
    challenge: base64urlToBytes(publicKey.challenge),
    user: {
      ...publicKey.user,
      id: base64urlToBytes(publicKey.user.id),
    },
    excludeCredentials: (publicKey.excludeCredentials ?? []).map((credential) => ({
      ...credential,
      id: base64urlToBytes(credential.id),
    })),
  };
}

function requestOptions(publicKey) {
  return {
    ...publicKey,
    challenge: base64urlToBytes(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials ?? []).map((credential) => ({
      ...credential,
      id: base64urlToBytes(credential.id),
    })),
  };
}

function credentialBase(credential) {
  return {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function registrationPayload(credential) {
  return {
    ...credentialBase(credential),
    response: {
      clientDataJSON: bytesToBase64url(credential.response.clientDataJSON),
      attestationObject: bytesToBase64url(credential.response.attestationObject),
      transports: credential.response.getTransports?.() ?? [],
    },
  };
}

function authenticationPayload(credential) {
  const userHandle = credential.response.userHandle;
  return {
    ...credentialBase(credential),
    response: {
      clientDataJSON: bytesToBase64url(credential.response.clientDataJSON),
      authenticatorData: bytesToBase64url(credential.response.authenticatorData),
      signature: bytesToBase64url(credential.response.signature),
      userHandle: userHandle ? bytesToBase64url(userHandle) : null,
    },
  };
}

async function apiRequest(url, options = {}) {
  const response = await fetch(url, {
    credentials: "include",
    ...options,
    headers: {
      Accept: "application/json",
      ...options.headers,
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail ?? `Authentication request failed (${response.status})`);
  }
  if (response.status === 204) {
    return null;
  }
  return response.json();
}

export async function registerPasskey({ baseUrl, accessToken, name }) {
  requireWebAuthn();
  const headers = { Authorization: `Bearer ${accessToken}` };
  const options = await apiRequest(`${baseUrl}/passkeys/registration/options`, {
    method: "POST",
    headers,
  });
  const credential = await navigator.credentials.create({
    publicKey: creationOptions(options.publicKey),
  });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("The browser did not create a passkey credential");
  }
  return apiRequest(`${baseUrl}/passkeys/registration/verify`, {
    method: "POST",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify({
      ceremony_id: options.ceremony_id,
      name,
      credential: registrationPayload(credential),
    }),
  });
}

export async function authenticateWithPasskey({ baseUrl }) {
  requireWebAuthn();
  const options = await apiRequest(`${baseUrl}/passkeys/authentication/options`, {
    method: "POST",
  });
  const credential = await navigator.credentials.get({
    publicKey: requestOptions(options.publicKey),
  });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("The browser did not return a passkey credential");
  }
  return apiRequest(`${baseUrl}/passkeys/authentication/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ceremony_id: options.ceremony_id,
      credential: authenticationPayload(credential),
    }),
  });
}

export function listPasskeys({ baseUrl, accessToken }) {
  return apiRequest(`${baseUrl}/passkeys`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
}

export function revokePasskey({ baseUrl, accessToken, passkeyId }) {
  return apiRequest(`${baseUrl}/passkeys/${passkeyId}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${accessToken}` },
  });
}

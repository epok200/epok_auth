const API = "/api/v1/auth/google";
const button = document.querySelector("#google-button");
const status = document.querySelector("#status");
const result = document.querySelector("#session-result");
const resultName = document.querySelector("#result-name");
const resultEmail = document.querySelector("#result-email");

function setStatus(message, tone = "neutral") {
  status.textContent = message;
  status.dataset.tone = tone;
}

async function api(path, body) {
  const response = await fetch(`${API}${path}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Google Sign-In no pudo completarse.");
  }
  return payload;
}

async function waitForGoogle() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (window.google?.accounts?.id) return window.google.accounts.id;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("La librería oficial de Google no respondió.");
}

async function verifyCredential(challengeId, credential) {
  try {
    setStatus("Google respondió. Verificando firma, nonce y política...");
    const session = await api("/verify", { challenge_id: challengeId, credential });
    resultName.textContent = session.user.display_name;
    resultEmail.textContent = session.user.email;
    result.hidden = false;
    setStatus("Acceso confirmado con Google y sesión local creada.", "success");
  } catch (error) {
    result.hidden = true;
    await renderGoogleButton();
    setStatus(error.message, "error");
  }
}

async function renderGoogleButton() {
  try {
    const [googleId, options] = await Promise.all([waitForGoogle(), api("/options")]);
    button.replaceChildren();
    googleId.initialize({
      client_id: options.client_id,
      nonce: options.nonce,
      auto_select: false,
      cancel_on_tap_outside: true,
      callback: ({ credential }) => verifyCredential(options.challenge_id, credential),
    });
    googleId.renderButton(button, {
      type: "standard",
      theme: "outline",
      size: "large",
      text: "continue_with",
      shape: "rectangular",
      width: 320,
    });
    setStatus("Listo. Google verificará tu identidad cuando pulses el botón.");
  } catch (error) {
    setStatus(error.message, "error");
  }
}

renderGoogleButton();

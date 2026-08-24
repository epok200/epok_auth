import { authenticateWithPasskey, registerPasskey } from "./browser.js";

const API = "/api/v1/auth";
const DEMO_ACCOUNT = {
  email: "browser@example.com",
  password: "browser passkey proof password",
};

class PasskeySandbox {
  constructor() {
    this.registerButton = document.querySelector("#register-button");
    this.loginButton = document.querySelector("#login-button");
    this.status = document.querySelector("#status");
    this.result = document.querySelector("#session-result");
    this.resultName = document.querySelector("#result-name");
    this.resultEmail = document.querySelector("#result-email");
    this.resultTime = document.querySelector("#result-time");
  }

  start() {
    this.registerButton.addEventListener("click", () => this.createPasskey());
    this.loginButton.addEventListener("click", () => this.loginWithPasskey());
    if (!globalThis.PublicKeyCredential || !navigator.credentials) {
      this.setStatus("Este navegador no soporta WebAuthn passkeys.", "error");
      this.setBusy(true);
    }
  }

  async createPasskey() {
    await this.runAction("Preparando la cuenta temporal...", async () => {
      const session = await this.passwordLogin();
      let registrationError = null;
      try {
        this.setStatus("Confirma la creación en Chrome.", "working");
        await registerPasskey({
          baseUrl: API,
          accessToken: session.access_token,
          name: "Chrome sandbox",
        });
      } catch (error) {
        registrationError = error;
      }

      try {
        await this.logout(session.csrf_token);
      } catch (logoutError) {
        if (registrationError) {
          const message = this.friendlyError(registrationError);
          throw new AggregateError([registrationError, logoutError], message);
        }
        throw logoutError;
      }
      if (registrationError) {
        throw registrationError;
      }

      this.result.hidden = true;
      this.setStatus("Passkey lista. Ahora prueba el acceso sin contraseña.", "success");
    });
  }

  async loginWithPasskey() {
    await this.runAction("Esperando tu passkey...", async () => {
      const session = await authenticateWithPasskey({ baseUrl: API });
      const user = await this.currentUser(session.access_token);
      this.showSession(user);
      this.setStatus("Acceso confirmado con passkey.", "success");
    });
  }

  async runAction(message, action) {
    this.result.hidden = true;
    this.setBusy(true);
    this.setStatus(message, "working");
    try {
      await action();
    } catch (error) {
      this.setStatus(this.friendlyError(error), "error");
    } finally {
      this.setBusy(false);
    }
  }

  async passwordLogin() {
    const response = await fetch(`${API}/login`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(DEMO_ACCOUNT),
    });
    return this.responseBody(response, "No fue posible iniciar la sesión temporal");
  }

  async logout(csrfToken) {
    const response = await fetch(`${API}/logout`, {
      method: "POST",
      credentials: "include",
      headers: { "X-CSRF-Token": csrfToken },
    });
    if (!response.ok) {
      throw new Error(`No fue posible cerrar la sesión temporal (${response.status})`);
    }
  }

  async currentUser(accessToken) {
    const response = await fetch(`${API}/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return this.responseBody(response, "La passkey no produjo una sesión válida");
  }

  async responseBody(response, fallback) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.detail ?? `${fallback} (${response.status})`);
    }
    return body;
  }

  showSession(user) {
    this.resultName.textContent = user.display_name;
    this.resultEmail.textContent = user.email;
    this.resultTime.textContent = new Intl.DateTimeFormat("es-MX", {
      dateStyle: "medium",
      timeStyle: "medium",
    }).format(new Date(user.authenticated_at));
    this.result.hidden = false;
  }

  setBusy(busy) {
    this.registerButton.disabled = busy;
    this.loginButton.disabled = busy;
  }

  setStatus(message, tone) {
    this.status.textContent = message;
    this.status.dataset.tone = tone;
  }

  friendlyError(error) {
    if (error instanceof DOMException && error.name === "NotAllowedError") {
      return "Chrome canceló la operación o no encontró una passkey disponible.";
    }
    return error instanceof Error ? error.message : "La operación no pudo completarse.";
  }
}

new PasskeySandbox().start();

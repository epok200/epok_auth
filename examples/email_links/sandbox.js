const API = "/api/v1/auth/email-links";
const email = document.querySelector("#email");
const requestButton = document.querySelector("#request-link");
const status = document.querySelector("#status");
const result = document.querySelector("#session-result");
const resultName = document.querySelector("#result-name");
const resultEmail = document.querySelector("#result-email");

function setStatus(message, tone = "neutral") {
  status.textContent = message;
  status.dataset.tone = tone;
}

async function post(path, body) {
  const response = await fetch(`${API}${path}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    throw new Error(payload?.detail || "El enlace no pudo validarse.");
  }
  return payload;
}

async function requestLink() {
  requestButton.disabled = true;
  result.hidden = true;
  try {
    setStatus("Creando un enlace de un solo uso...");
    await post("/login", { email: email.value });
    const response = await fetch("/test/latest-link", {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!response.ok) throw new Error("El correo local todavía no está listo.");
    const { url } = await response.json();
    setStatus("Correo aceptado. Abriendo el Magic Link...");
    location.assign(url);
  } catch (error) {
    setStatus(error.message, "error");
    requestButton.disabled = false;
  }
}

async function consumeFragment() {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const token = fragment.get("token");
  if (!token) return;

  history.replaceState(null, "", location.pathname);
  try {
    setStatus("Fragmento borrado. Validando token y navegador...");
    const session = await post("/login/consume", { token });
    resultName.textContent = session.user.display_name;
    resultEmail.textContent = session.user.email;
    result.hidden = false;
    setStatus("Acceso confirmado. La sesión real quedó activa.", "success");
  } catch (error) {
    result.hidden = true;
    setStatus(error.message, "error");
  }
}

requestButton.addEventListener("click", requestLink);
consumeFragment();

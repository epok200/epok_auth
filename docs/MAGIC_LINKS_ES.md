# Magic Links, recuperación e invitaciones

`epok-auth` incluye un flujo completo de enlaces de correo para tres casos:

1. iniciar sesión sin contraseña;
2. recuperar una contraseña local;
3. activar una cuenta previamente creada por el producto.

La librería crea y valida el token, controla su expiración y uso único, persiste solo hashes,
construye el correo, envía por SMTP y emite la sesión normal cuando corresponde. El producto sigue
decidiendo quién puede existir, a qué empresa pertenece y qué permisos de negocio recibe.

## Instalación

SMTP usa únicamente la biblioteca estándar de Python. No requiere un extra:

```bash
uv add "epok-auth[postgres]"
```

Configura los tres destinos frontend. SMTP directo es apropiado para desarrollo y pruebas:

```dotenv
EPOK_AUTH_EMAIL_LINK_LOGIN_URL=https://app.example.com/auth/email-link
EPOK_AUTH_EMAIL_LINK_PASSWORD_RESET_URL=https://app.example.com/auth/reset-password
EPOK_AUTH_EMAIL_LINK_INVITATION_URL=https://app.example.com/auth/invitation

EPOK_AUTH_SMTP_HOST=smtp.gmail.com
EPOK_AUTH_SMTP_PORT=587
EPOK_AUTH_SMTP_USERNAME=security@example.com
EPOK_AUTH_SMTP_PASSWORD=<app-password>
EPOK_AUTH_SMTP_FROM_ADDRESS=security@example.com
EPOK_AUTH_SMTP_APP_NAME=Mi Producto
EPOK_AUTH_SMTP_SECURITY=starttls
```

Para Gmail usa una contraseña de aplicación, no la contraseña normal de la cuenta. No se necesita
un JSON de OAuth para SMTP. Las credenciales pertenecen al entorno o al gestor de secretos del
despliegue y nunca al repositorio.

Los tres destinos deben usar HTTPS, excepto localhost, no pueden incluir query ni fragment y su
Origin debe existir en `EPOK_AUTH_TRUSTED_ORIGINS`.

## FastAPI en una bandera

```python
from fastapi import FastAPI

from epok_auth import AuthSettings, EpokAuth

settings = AuthSettings()
# Adaptador durable del producto. El contrato completo aparece más abajo.
auth = EpokAuth.postgres(
    settings=settings,
    email_link_dispatcher=email_queue,
)
app = FastAPI(lifespan=auth.lifespan)

auth.install(
    app,
    prefix="/api/v1/auth",
    include_admin=True,
    include_email_links=True,
)
```

La configuración SMTP se carga de `EPOK_AUTH_SMTP_*` solo cuando se instala esta capacidad sin un
dispatcher. En producción, `include_email_links=True` exige un dispatcher durable inyectado y no
carga credenciales SMTP en el proceso web.

## API

| Método | Ruta | Resultado |
|---|---|---|
| `POST` | `/email-links/login` | Respuesta genérica `202` y envío si la cuenta es elegible |
| `POST` | `/email-links/login/consume` | Sesión normal, ligada al navegador que pidió el correo |
| `POST` | `/email-links/password-reset` | Respuesta genérica `202` y envío si aplica |
| `POST` | `/email-links/password-reset/consume` | Cambia contraseña, revoca sesiones y no inicia sesión |
| `POST` | `/email-links/invitation/consume` | Activa la cuenta y no inicia sesión |
| `POST` | `/users/{user_id}/invitation` | Administrativa, envía una invitación |

Solicitud de login:

```json
{"email":"person@example.com"}
```

Consumo desde el frontend:

```javascript
const fragment = new URLSearchParams(location.hash.slice(1));
const token = fragment.get("token");
history.replaceState(null, "", location.pathname);

const response = await fetch("/api/v1/auth/email-links/login/consume", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ token }),
});
```

El token viaja en el fragmento `#token=...`, no en el query string. El navegador no envía ese
fragmento al servidor, y el frontend debe borrarlo del historial antes de continuar.

## Reglas de cuenta

El login por correo está apagado por defecto. Un administrador puede activarlo sobre una cuenta:

```json
PATCH /api/v1/auth/users/{user_id}
{"email_link_login_enabled":true}
```

Los roles administrativos nunca pueden usar Magic Link, recuperación por correo ni invitación.
Una invitación solo aplica a una cuenta activa que el producto ya creó y que todavía requiere su
primer cambio de contraseña. Activarla deshabilita la contraseña temporal, habilita Magic Link y no
crea una sesión. La persona solicita después un enlace normal ligado a su navegador.

## Sender directo en desarrollo o worker

SMTP es el adaptador nativo, pero el núcleo no depende de él. Cualquier proveedor implementa un
método asíncrono:

```python
from epok_auth import AuthEmail, EmailLinkMailer


class SesEmailSender:
    async def send(self, email: AuthEmail) -> None:
        await ses.send(
            to=email.recipient,
            kind=email.kind.value,
            action_url=email.action_url,
        )


mailer = EmailLinkMailer(email_link_service, SesEmailSender())
```

El sender vive en el worker o en una instalación de desarrollo. Su método debe regresar solo
cuando el proveedor haya aceptado el correo. En ese momento la librería activa el enlace. Si el
envío falla, el enlace nuevo queda fallido y un enlace activo anterior sigue funcionando.

## Producción con cola durable

El proceso web entrega cada `PendingEmailLink` y aviso `AuthEmail` a un dispatcher inyectado. La
aceptación de la cola no activa el enlace. Solo el worker lo activa después de que el proveedor de
correo acepta el mensaje.

```python
from epok_auth import AuthEmail, PendingEmailLink


class EmailQueue:
    async def dispatch(self, message: AuthEmail | PendingEmailLink) -> None:
        await queue.enqueue(message)


auth = EpokAuth.postgres(
    settings=settings,
    email_link_dispatcher=EmailQueue(),
)
```

El worker inyecta el sender real y distingue los dos contratos:

```python
from epok_auth import EmailLinkMailer, PendingEmailLink

mailer = EmailLinkMailer(email_link_service, provider_sender)

if isinstance(message, PendingEmailLink):
    await mailer.deliver(message)
else:
    await mailer.send_notice(message)
```

El job de `PendingEmailLink` contiene el enlace secreto. La cola debe cifrar datos en tránsito y en
reposo, usar retención corta y nunca registrar, indexar ni usar el payload como identificador. El
worker debe confirmar el job solo después de terminar `deliver()` o `send_notice()`. Si el provider
falla, `EmailLinkMailer` genera un error sanitizado y registra el fallo de entrega sin exponer el
mensaje externo.

## Invariantes de seguridad

- El token tiene 256 bits aleatorios y PostgreSQL guarda solo SHA-256.
- Cada enlace expira, tiene una sola generación activa y se consume una sola vez.
- Un enlace nuevo no invalida al anterior hasta que el proveedor acepta el nuevo correo.
- Login por correo requiere una cookie `HttpOnly` secreta del navegador que hizo la solicitud.
- Recuperación e invitación rechazan un navegador con cookie de sesión para evitar confusión de
  cuentas.
- Cambiar contraseña, estado, roles, scopes, flags de acceso, identidad Google o passkeys invalida
  enlaces anteriores mediante `security_version`.
- Solicitudes públicas usan respuesta genérica, límite persistente por cuenta y `no-store`.
- El producto debe agregar rate limiting perimetral por IP a las rutas públicas de solicitud.
- Los tokens no se registran, no aparecen en `repr` y no se envían en rutas `GET`.
- La contraseña recuperada no inicia sesión automáticamente y revoca todas las sesiones previas.
- El remitente SMTP traduce errores sin devolver detalles sensibles del proveedor.

La aceptación SMTP confirma que el proveedor recibió el mensaje, no que llegó al inbox.

## Límite de cumplimiento

NIST SP 800-63B no considera el correo electrónico un autenticador out-of-band. Por eso esta
capacidad es opt-in, no se presenta como MFA y no satisface por sí sola un nivel AAL superior.
La recuperación por correo es apropiada para cuentas AAL1. No debe ser el único mecanismo para
recuperar administradores, passkeys, Google o MFA en un producto de mayor garantía.

## Pruebas

Prueba visual local:

```bash
npm ci --prefix examples/email_links
uv run uvicorn examples.email_links.e2e_server:api_app --host 127.0.0.1 --port 8767
```

Abre `http://localhost:8767`. El sandbox captura el correo solo en memoria.

Prueba automatizada de Chromium:

```bash
node --test examples/email_links/browser.e2e.test.mjs
```

```bash
uv run pytest tests/email_links -q
uv run pytest -m integration -q
```

Las pruebas cubren unidad, HTTP, abuso, SMTP, expiración, replay, cookie binding, reemplazo,
recuperación, invitación, fencing y PostgreSQL. El flujo criptográfico de passkeys mantiene su prueba
de navegador independiente.

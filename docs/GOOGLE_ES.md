# Google Sign-In con políticas de cuenta

Esta guía conecta el botón oficial de Google con las sesiones revocables de `epok-auth`.
La librería verifica la identidad y aplica una política de vinculación. El producto conserva
la decisión final sobre membresías, tenants, permisos de negocio, onboarding y acceso a datos.

## Mapa de responsabilidades

Hay tres niveles:

1. Google demuestra quién controla la cuenta mediante un ID token firmado.
2. `epok-auth` verifica firma, issuer, audience, expiración y nonce; después vincula o crea una
   cuenta de autenticación según el modo configurado.
3. El producto decide si esa cuenta pertenece al negocio y qué recursos puede usar.

La analogía práctica es un edificio: Google revisa la identificación, la librería administra la
credencial de entrada y el producto decide a qué oficina puede pasar la persona.

## 1. Instalación

Solo Google:

```bash
uv add "epok-auth[google]"
```

Google, PostgreSQL y passkeys:

```bash
uv add "epok-auth[google,postgres,passkeys]"
```

La instalación base no importa `google-auth` ni `CacheControl`. Activar Google sin el extra falla al
iniciar con un mensaje que incluye el comando correcto.

La integración usa la librería oficial `google-auth` para verificar ID tokens y `CacheControl` para
respetar el caché HTTP de certificados. No copia criptografía ni validación OIDC dentro del proyecto.

## 2. Preparar Google Cloud

En Google Cloud crea un OAuth client de tipo Web application y registra el Origin exacto del
frontend, por ejemplo:

```text
https://app.example.com
http://localhost:8766
```

El flujo de Google Identity Services usado aquí necesita el client ID. No necesita client secret,
porque el backend recibe un ID token, no intercambia un authorization code.

Referencias oficiales:

- [Google Identity Services para web](https://developers.google.com/identity/gsi/web/guides/overview)
- [Verificación de ID tokens](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)

## 3. Configuración mínima

```dotenv
EPOK_AUTH_GOOGLE_CLIENT_ID=123456789-example.apps.googleusercontent.com
EPOK_AUTH_GOOGLE_ACCOUNT_MODE=linked_only
EPOK_AUTH_TRUSTED_ORIGINS=https://app.example.com
```

Configuración opcional:

```dotenv
EPOK_AUTH_GOOGLE_HOSTED_DOMAINS=company.example,subsidiary.example
EPOK_AUTH_GOOGLE_CHALLENGE_TTL_SECONDS=300
EPOK_AUTH_GOOGLE_LINK_MAX_AGE_SECONDS=300
EPOK_AUTH_GOOGLE_TOKEN_TIMEOUT_SECONDS=5
EPOK_AUTH_GOOGLE_MAX_CREDENTIAL_CHARS=8192
```

`GOOGLE_HOSTED_DOMAINS` es una allowlist. Cuando existe, se aplica a login, auto-link y link
explícito, incluso a identidades vinculadas anteriormente.

## 4. Elegir el modo de cuenta

El valor predeterminado es `linked_only`.

| Modo | Cuenta desconocida | Correo local existente | Uso recomendado |
|---|---|---|---|
| `linked_only` | Rechazada | No se vincula sola | Sistemas privados y máxima seguridad |
| `preauthorized` | Rechazada | Se vincula solo si un administrador activó `google_auto_link_allowed` | B2B con usuarios provisionados |
| `open` | Puede crear una cuenta de autenticación | Nunca toma el correo sin preautorización | Productos con registro abierto |

### `linked_only`

Solo entra una identidad ya vinculada por `issuer + sub`. El correo de Google no vincula ni crea
cuentas. Es la opción correcta cuando el producto administra un directorio cerrado.

### `preauthorized`

Un administrador crea la cuenta con el correo local exacto y activa:

```json
{
  "email": "person@company.example",
  "display_name": "Person",
  "google_auto_link_allowed": true
}
```

El primer login de Google requiere:

- correo normalizado idéntico;
- `email_verified` verdadero;
- correo autoritativo de Gmail o Google Workspace;
- `hd` dentro de la allowlist cuando se configuró;
- cuenta activa, contraseña temporal pendiente y preautorización todavía vigente.

La transición es atómica: inserta la identidad, invalida la contraseña temporal, deshabilita login
por contraseña, limpia `must_change_password`, consume la preautorización, crea la sesión y registra
los eventos. Un intento concurrente no puede crear una segunda identidad.

Una cuenta que ya estableció su contraseña no puede usar auto-link, aunque el flag se active por
error. Debe vincular Google desde una sesión local reciente.

### `open`

Una cuenta desconocida se crea únicamente para un correo Gmail verificado o un correo Google
Workspace verificado con claim `hd`. Un correo externo sin `hd` no basta, aunque Google reporte
`email_verified`.

La cuenta nueva recibe:

- `default_user_role`;
- scopes vacíos;
- contraseña deshabilitada;
- sesión normal de `epok-auth`.

Esto no concede membresía, tenant, permisos de negocio ni onboarding. El producto debe exigirlos en
sus propias rutas. Si el correo ya existe localmente y no está vinculado, `open` no toma la cuenta:
requiere la misma preautorización explícita que `preauthorized`.

La configuración falla al iniciar si `default_user_role` es igual a `admin_role` mientras `open`
está activo. El producto sigue siendo responsable de no asignar significado privilegiado a otros
roles de registro público.

## 5. FastAPI en una pantalla

```python
from fastapi import FastAPI

from epok_auth import AuthSettings, EpokAuth

settings = AuthSettings()
auth = EpokAuth.postgres(settings=settings)

app = FastAPI(lifespan=auth.lifespan)
auth.install(
    app,
    prefix="/api/v1/auth",
    include_admin=True,
    include_google=True,
)
```

Rutas instaladas:

```text
POST /api/v1/auth/google/options
POST /api/v1/auth/google/verify
POST /api/v1/auth/google/link/options
POST /api/v1/auth/google/link/verify
POST /api/v1/auth/users/{user_id}/google/recover
```

La última ruta aparece solo con `include_admin=True` y exige el rol administrativo configurado.

## 6. Botón oficial de Google

Carga el SDK desde Google. No lo descargues ni lo sirvas desde tu aplicación.

```html
<script src="https://accounts.google.com/gsi/client" async defer></script>
<div id="google-button"></div>
```

El frontend solicita un nonce de un solo uso antes de inicializar el botón:

```javascript
const options = await fetch("/api/v1/auth/google/options", {
  method: "POST",
  credentials: "same-origin",
}).then((response) => response.json());

google.accounts.id.initialize({
  client_id: options.client_id,
  nonce: options.nonce,
  auto_select: false,
  callback: async ({ credential }) => {
    await fetch("/api/v1/auth/google/verify", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge_id: options.challenge_id,
        credential,
      }),
    });
  },
});

google.accounts.id.renderButton(document.querySelector("#google-button"), {
  type: "standard",
  theme: "outline",
  size: "large",
});
```

La primera versión usa botón explícito. One Tap y `auto_select` quedan fuera para que la interacción
y el contexto de cuenta sean visibles.

## 7. Vincular una cuenta existente

El link explícito permite asociar un Google diferente al correo local. Requiere una sesión local
autenticada recientemente:

1. El frontend llama `POST /google/link/options` con Bearer token y Origin.
2. Google recibe el nonce retornado.
3. El frontend llama `POST /google/link/verify` con el mismo Bearer token.
4. La librería ata el desafío a `user_id`, propósito, Origin y client ID antes de insertar la
   identidad.

Una vinculación correcta consume cualquier `google_auto_link_allowed` pendiente sin deshabilitar
la contraseña estable de la cuenta.

Una identidad de Google solo puede pertenecer a una cuenta local y una cuenta local solo puede tener
una identidad por issuer.

## 8. Recuperación administrativa

```text
POST /api/v1/auth/users/{user_id}/google/recover
Authorization: Bearer <admin-access-token>
```

La operación:

1. elimina la identidad de Google;
2. genera una contraseña temporal entregable una sola vez;
3. habilita login por contraseña;
4. exige cambio de contraseña;
5. elimina cualquier preautorización pendiente;
6. revoca todas las sesiones;
7. registra el evento en la misma transacción.

La vinculación vuelve a validar en PostgreSQL la sesión presentada antes de escribir. Si una
recuperación la revocó mientras el navegador terminaba Google, la vinculación pendiente se rechaza
y no puede restaurar la identidad. Las rutas de link, recuperación y refresh comparten un orden de
bloqueo probado para evitar interbloqueos.

Un reset administrativo normal también habilita contraseña y limpia la preautorización, pero no
desvincula Google. Usa `/google/recover` cuando debas retirar el proveedor de la cuenta.

## 9. Qué se persiste

La migración `0003_google_identity` agrega:

- `external_identity`, única por `(issuer, subject)` y `(user_id, issuer)`;
- `google_challenge`, temporal, origin-bound y de un solo uso;
- `password_login_enabled`;
- `google_auto_link_allowed`.

El correo de Google es una fotografía informativa. La clave estable es el `sub` bajo el issuer
canónico `https://accounts.google.com`. Un login posterior no cambia correo local, nombre, roles ni
scopes.

La librería no almacena ID tokens, access tokens ni refresh tokens de Google.

## 10. Operación segura

- Usa HTTPS fuera de localhost.
- Registra Origins exactos tanto en Google Cloud como en `trusted_origins`.
- Aplica rate limiting perimetral a `/options` y `/verify`.
- No registres el credential, nonce ni claims completos.
- Ejecuta la migración antes de activar `include_google`.
- Mantén una ruta de recuperación administrativa probada.
- Exige membresía y autorización de negocio después del login.

Cambiar de `open` o `preauthorized` a `linked_only` no revoca identidades ya vinculadas. Para retirar
acceso usa recuperación o deshabilita la cuenta.

## 11. Sandbox local

Registra `http://localhost:8766` como Authorized JavaScript origin en Google Cloud y ejecuta:

```bash
EPOK_AUTH_GOOGLE_CLIENT_ID=123456789-example.apps.googleusercontent.com \
uv run uvicorn examples.google.main:app --host 127.0.0.1 --port 8766
```

Abre:

```text
http://localhost:8766
```

El sandbox usa `MemoryAuthStore`, modo `open` y una cuenta efímera. Sirve para probar el botón y el
flujo. No representa persistencia de producción.

# Passkeys con WebAuthn

`epok-auth` incluye registro, inicio de sesión sin username, listado y revocación de
passkeys. El backend delega la validación criptográfica WebAuthn a `py_webauthn` y
mantiene en la librería la política de sesiones, challenges, usuarios y auditoría.

## Estándar y dependencia

La implementación sigue el modelo de [Web Authentication Level 3 del
W3C](https://www.w3.org/TR/webauthn-3/) y usa
[`webauthn`](https://github.com/duo-labs/py_webauthn) 3.x de Duo Labs como adaptador
server-side. La dependencia tiene licencia BSD-3-Clause, publica tipos y concentra el
parseo CBOR/COSE, la firma y las validaciones del protocolo. `epok-auth` no mantiene una
implementación criptográfica propia.

El extra fija `webauthn>=3.0,<4`, el lockfile conserva la resolución exacta y CI ejecuta
`pip-audit`. El adaptador está aislado en `epok_auth.passkeys.webauthn`, así que una
actualización mayor puede revisarse sin cambiar el dominio, los stores ni la API HTTP.

## Integración mínima

Instala PostgreSQL y passkeys con un solo comando:

```bash
uv add "epok-auth[postgres,passkeys]==0.2.0"
```

Ese comando aplica al publicar `0.2.0`. Para validar el candidato desde este repositorio,
usa el wheel o sdist generado por `uv build --no-sources`.

Configura el dominio de la relying party. No lleva scheme, puerto ni ruta:

```dotenv
EPOK_AUTH_PASSKEY_RP_ID=example.com
EPOK_AUTH_PASSKEY_RP_NAME=Colors
EPOK_AUTH_TRUSTED_ORIGINS=https://app.example.com
```

El `RP ID` debe ser el hostname exacto del frontend o un dominio padre. Por ejemplo,
`example.com` acepta `https://app.example.com`. En desarrollo, `localhost` ya es el
valor predeterminado de `AuthSettings.development()`.

Habilita las rutas al instalar la integración:

```python
from fastapi import FastAPI

from epok_auth import AuthSettings, EpokAuth

settings = AuthSettings()
auth = EpokAuth.postgres(settings=settings)

app = FastAPI()
auth.install(app, prefix="/api/v1/auth", include_passkeys=True)
```

Aplica la migración antes de iniciar la aplicación:

```bash
uv run epok-auth upgrade-db
uv run epok-auth check-db
```

El repositorio incluye una aplicación de prueba con CORS exacto para los orígenes
configurados:

```bash
uv run --with uvicorn uvicorn examples.passkeys.main:app --reload --port 8000
```

Si falta el extra o `passkey_rp_id`, la instalación de rutas falla al iniciar con un
mensaje accionable. La instalación base de `epok-auth` sigue funcionando sin importar
`webauthn`.

## API disponible

| Método | Ruta | Autenticación | Propósito |
|---|---|---|---|
| `POST` | `/passkeys/registration/options` | Bearer reciente | Crear challenge de registro |
| `POST` | `/passkeys/registration/verify` | Bearer reciente | Verificar y guardar una passkey |
| `POST` | `/passkeys/authentication/options` | Pública | Crear challenge de login discoverable |
| `POST` | `/passkeys/authentication/verify` | Pública | Verificar y emitir una sesión normal |
| `GET` | `/passkeys` | Bearer | Listar passkeys activas del usuario |
| `DELETE` | `/passkeys/{id}` | Bearer reciente | Revocar una passkey |

Todas las rutas anteriores quedan bajo el prefijo entregado a `auth.install()`. Las
respuestas llevan `Cache-Control: no-store`. Un login con passkey entrega el mismo
contrato de sesión, cookies y revocación autoritativa que un login con contraseña.

## Cliente de navegador

El ejemplo listo para copiar está en
[`examples/passkeys/browser.js`](../examples/passkeys/browser.js). No necesita una
dependencia frontend:

```javascript
import {
  authenticateWithPasskey,
  registerPasskey,
} from "./browser.js";

await registerPasskey({
  baseUrl: "https://api.example.com/api/v1/auth",
  accessToken,
  name: "MacBook Touch ID",
});

const session = await authenticateWithPasskey({
  baseUrl: "https://api.example.com/api/v1/auth",
});
```

El navegador decide si usa Touch ID, Windows Hello, Android, iCloud Keychain, Google
Password Manager, una security key o el flujo híbrido disponible. El servidor exige
credenciales discoverable y verificación de usuario.

El repositorio prueba este cliente en dos niveles. El primero aísla la conversión binaria
y las seis llamadas HTTP con Node. El segundo inicia FastAPI, abre Chromium headless,
crea una credencial con el autenticador virtual de Chrome, cierra la sesión de contraseña,
inicia una sesión discoverable y revoca la passkey. CI instala la versión bloqueada de
Playwright desde `examples/passkeys/package-lock.json` y ejecuta ambos niveles.

Si el frontend y la API usan orígenes distintos, la aplicación consumidora debe
configurar CORS para su origen exacto, permitir `Authorization` y habilitar
credenciales. `epok-auth` no instala una política CORS global porque esa decisión
pertenece a cada producto.

## Controles implementados

- challenge aleatorio de 32 bytes, temporal, ligado a ceremonia y origen;
- consumo atómico de un solo uso antes de validar la respuesta;
- rechazo de replay, challenge vencido, `crossOrigin` y `topOrigin`;
- validación exacta de Origin y compatibilidad con RP ID;
- verificación de usuario obligatoria y credencial discoverable;
- `userHandle` ligado al UUID del propietario;
- límite configurable de credenciales por usuario bajo lock transaccional;
- credential ID único y con máximo de 1023 bytes;
- validación de firma, RP ID hash, contador y elegibilidad de backup;
- múltiples passkeys, nombre amigable, última utilización y revocación;
- eventos de registro, fallo, login y revocación;
- PostgreSQL autoritativo y soporte de almacenamiento en memoria solo para pruebas.

La atestación usa `none` de forma intencional. Esto mantiene interoperabilidad y evita
convertir la librería en un sistema de confianza de fabricantes. La autenticación con
passkey es una alternativa resistente al phishing, no una política MFA o step-up por sí
sola.

## Operación segura

- Usa HTTPS en producción. WebAuthn solo permite contextos seguros, con la excepción de
  `localhost` para desarrollo.
- Mantén `trusted_origins` exacto y sin wildcards.
- Aplica rate limiting en el edge a las dos rutas públicas de autenticación.
- Conserva al menos otra vía de acceso o un proceso de recuperación antes de revocar la
  última passkey de una cuenta sin contraseña operable.
- Monitorea los eventos `PASSKEY_LOGIN_FAILED` y `PASSKEY_REGISTRATION_FAILED`.
- Ejecuta `upgrade-db` durante el despliegue antes de servir la versión nueva.

Revocar una passkey impide nuevas autenticaciones con esa credencial, pero no termina
sesiones ya emitidas. Si existe sospecha de compromiso, revoca también las sesiones del
usuario con el endpoint administrativo `POST /users/{user_id}/revoke-sessions`. El flujo
HTTP automatizado conserva este contrato y comprueba ambos comportamientos por separado.

La migración `0002_passkeys` es reversible. Un downgrade elimina credenciales y
challenges WebAuthn, por lo que debe tratarse como pérdida de factores y requiere una
copia de seguridad si se piensa restaurar la versión nueva.

# Guía mínima de uso y prueba

Esta guía documenta la superficie de `0.4.0`, incluidos passkeys, Google Sign-In y Magic Links. Aquí
encontrarás lo mínimo necesario para levantar PostgreSQL, crear el primer administrador, iniciar
FastAPI y probar cada operación disponible.

La ruta recomendada para la primera prueba es usar `AuthSettings`, `EpokAuth.postgres()` y `auth.install()`. Los helpers internos y las clases de persistencia no son necesarios para validar la beta.

Para registrar e iniciar sesión con passkeys, sigue la guía dedicada en
[`PASSKEYS_ES.md`](PASSKEYS_ES.md). Incluye instalación, configuración, API y un cliente
de navegador listo para reutilizar.

Para Google Sign-In, políticas de vinculación y recuperación, sigue
[`GOOGLE_ES.md`](GOOGLE_ES.md).

Para Magic Links, recuperación por correo, invitaciones y SMTP, sigue
[`MAGIC_LINKS_ES.md`](MAGIC_LINKS_ES.md).

## 1. Requisitos

Necesitas Python 3.12 o superior, `uv`, Docker y `curl`. Los comandos del flujo automatizado usan también `jq`; puedes sustituirlo por lectura manual de las respuestas JSON.

Desde la raíz del repositorio:

```bash
uv sync --locked --all-extras --group dev
```

## 2. Levantar PostgreSQL 17

```bash
docker run --name epok-auth-postgres \
  -e POSTGRES_USER=epok_auth \
  -e POSTGRES_PASSWORD=epok_auth \
  -e POSTGRES_DB=epok_auth \
  -p 5432:5432 \
  -d postgres:17-alpine
```

Si el contenedor ya existe:

```bash
docker start epok-auth-postgres
```

Puedes confirmar que PostgreSQL ya acepta conexiones con:

```bash
docker exec epok-auth-postgres pg_isready -U epok_auth -d epok_auth
```

## 3. Configuración local mínima

Genera un secreto y crea el archivo `.env`:

```bash
SECRET="$(uv run epok-auth generate-secret)"

cat > .env <<EOF
EPOK_AUTH_ENVIRONMENT=development
EPOK_AUTH_DATABASE_URL=postgresql://epok_auth:epok_auth@127.0.0.1:5432/epok_auth
EPOK_AUTH_JWT_SECRET=$SECRET
EPOK_AUTH_ISSUER=epok-auth-local
EPOK_AUTH_AUDIENCE=epok-auth-local-api
EPOK_AUTH_TRUSTED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
EPOK_AUTH_SECURE_COOKIES=false
EPOK_AUTH_COOKIE_USE_HOST_PREFIX=false
EOF
```

Valida la configuración:

```bash
uv run epok-auth check-config
```

El resultado esperado comienza con:

```text
epok-auth configuration is valid.
```

## 4. Preparar la base de datos

```bash
uv run epok-auth upgrade-db
uv run epok-auth check-db
```

`upgrade-db` aplica las migraciones empaquetadas. `check-db` verifica que la base migrada y la metadata de la librería no tengan diferencias.

## 5. Crear el administrador inicial

```bash
uv run epok-auth create-admin
```

Usa, por ejemplo:

```text
Email: admin@example.com
Display name: Admin Local
Password: C0lors-beta-2026!
```

La contraseña debe cumplir la longitud configurada y no puede ser una contraseña común. El administrador inicial solo puede crearse una vez.

## 6. Iniciar la aplicación de ejemplo

El repositorio ya contiene `examples/minimal/main.py`.

```bash
uv run --with uvicorn uvicorn examples.minimal.main:app --reload --port 8000
```

Swagger estará disponible en:

```text
http://127.0.0.1:8000/docs
```

Para los ejemplos siguientes:

```bash
BASE="http://127.0.0.1:8000/api/v1/auth"
ORIGIN="http://localhost:3000"
```

## 7. Flujo mínimo completo con `curl`

### 7.1 Iniciar sesión como administrador

```bash
ADMIN_LOGIN="$(curl -sS \
  -c admin.cookies \
  -H "Origin: $ORIGIN" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"C0lors-beta-2026!"}' \
  "$BASE/login")"

printf '%s\n' "$ADMIN_LOGIN" | jq .

ADMIN_ACCESS="$(printf '%s' "$ADMIN_LOGIN" | jq -r '.access_token')"
ADMIN_CSRF="$(printf '%s' "$ADMIN_LOGIN" | jq -r '.csrf_token')"
```

La respuesta entrega un access token, un CSRF token, los vencimientos y el usuario autenticado. Los refresh credentials quedan además en `admin.cookies`.

### 7.2 Consultar la sesión actual

```bash
curl -sS \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  "$BASE/me" | jq .
```

### 7.3 Probar una ruta de negocio protegida

```bash
curl -sS \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  "http://127.0.0.1:8000/api/v1/private" | jq .
```

### 7.4 Crear un usuario

```bash
NEW_USER="$(curl -sS \
  -X POST \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "email":"user@example.com",
    "display_name":"Usuario Beta",
    "roles":["user"],
    "scopes":["colors:read"]
  }' \
  "$BASE/users")"

printf '%s\n' "$NEW_USER" | jq .

USER_ID="$(printf '%s' "$NEW_USER" | jq -r '.user.id')"
TEMP_PASSWORD="$(printf '%s' "$NEW_USER" | jq -r '.temporary_password')"
```

La contraseña temporal se devuelve una sola vez. Guárdala únicamente para completar el cambio de contraseña inicial.

### 7.5 Iniciar sesión con la contraseña temporal

```bash
USER_LOGIN="$(curl -sS \
  -c user.cookies \
  -H "Origin: $ORIGIN" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"user@example.com\",\"password\":\"$TEMP_PASSWORD\"}" \
  "$BASE/login")"

USER_ACCESS="$(printf '%s' "$USER_LOGIN" | jq -r '.access_token')"
USER_CSRF="$(printf '%s' "$USER_LOGIN" | jq -r '.csrf_token')"

printf '%s\n' "$USER_LOGIN" | jq .
```

El campo `user.must_change_password` debe ser `true`.

Una ruta protegida mediante `auth.authenticated` debe rechazar todavía a este usuario:

```bash
curl -i -sS \
  -H "Authorization: Bearer $USER_ACCESS" \
  "http://127.0.0.1:8000/api/v1/private"
```

El resultado esperado es `403` con el código `password_change_required`.

### 7.6 Cambiar la contraseña inicial

```bash
PASSWORD_CHANGE="$(curl -sS \
  -c user.cookies \
  -H "Authorization: Bearer $USER_ACCESS" \
  -H "Origin: $ORIGIN" \
  -H "Content-Type: application/json" \
  -d "{\"current_password\":\"$TEMP_PASSWORD\",\"new_password\":\"Us3r-colors-beta-2026!\"}" \
  "$BASE/change-password")"

USER_ACCESS="$(printf '%s' "$PASSWORD_CHANGE" | jq -r '.access_token')"
USER_CSRF="$(printf '%s' "$PASSWORD_CHANGE" | jq -r '.csrf_token')"

printf '%s\n' "$PASSWORD_CHANGE" | jq .
```

La operación revoca las sesiones anteriores y entrega una sesión nueva. Ahora la ruta privada debe responder correctamente:

```bash
curl -sS \
  -H "Authorization: Bearer $USER_ACCESS" \
  "http://127.0.0.1:8000/api/v1/private" | jq .
```

### 7.7 Rotar la sesión con refresh

```bash
ADMIN_REFRESH="$(curl -sS \
  -X POST \
  -b admin.cookies \
  -c admin.cookies \
  -H "Origin: $ORIGIN" \
  -H "X-CSRF-Token: $ADMIN_CSRF" \
  "$BASE/refresh")"

ADMIN_ACCESS="$(printf '%s' "$ADMIN_REFRESH" | jq -r '.access_token')"
ADMIN_CSRF="$(printf '%s' "$ADMIN_REFRESH" | jq -r '.csrf_token')"

printf '%s\n' "$ADMIN_REFRESH" | jq .
```

Cada refresh válido rota las credenciales. Debes reemplazar tanto el access token como el CSRF token y conservar el cookie jar actualizado.

### 7.8 Cerrar sesión

```bash
curl -i -sS \
  -X POST \
  -b admin.cookies \
  -c admin.cookies \
  -H "Origin: $ORIGIN" \
  -H "X-CSRF-Token: $ADMIN_CSRF" \
  "$BASE/logout"
```

El resultado esperado es `204 No Content`. La familia de sesión queda revocada y las cookies se eliminan.

## 8. Referencia de comandos CLI

### `epok-auth generate-secret`

Genera un secreto JWT aleatorio sin guardarlo.

```bash
uv run epok-auth generate-secret
uv run epok-auth generate-secret --bytes 64
```

El rango permitido es de 32 a 128 bytes. Para una prueba normal, el valor predeterminado es suficiente.

### `epok-auth check-config`

Carga `AuthSettings` desde `.env` y variables `EPOK_AUTH_*`. Finaliza con error si falta una variable obligatoria o existe una configuración insegura.

```bash
uv run epok-auth check-config
```

### `epok-auth upgrade-db`

Aplica las migraciones empaquetadas hasta `head`.

```bash
uv run epok-auth upgrade-db
uv run epok-auth upgrade-db --revision head
```

### `epok-auth check-db`

Comprueba que la base de datos esté migrada y que no exista drift entre PostgreSQL y la metadata declarativa.

```bash
uv run epok-auth check-db
```

### `epok-auth create-admin`

Crea el primer administrador de forma transaccional.

```bash
uv run epok-auth create-admin
```

La segunda ejecución debe fallar porque la librería no permite crear dos administradores iniciales mediante este comando.

## 9. Referencia de `AuthSettings`

### `AuthSettings()`

Carga la configuración desde `.env` y desde variables con prefijo `EPOK_AUTH_`.

```python
from epok_auth import AuthSettings

settings = AuthSettings()
```

El entorno predeterminado es `production`, por lo que una configuración incompleta falla de forma cerrada. Para la primera prueba usa el `.env` de esta guía.

### `AuthSettings.development(**overrides)`

Crea rápidamente una configuración de desarrollo con secreto aleatorio, cookies no seguras y orígenes localhost.

```python
from epok_auth import AuthSettings

settings = AuthSettings.development(
    database_url="postgresql://epok_auth:epok_auth@127.0.0.1:5432/epok_auth"
)
```

Es útil en pruebas pequeñas. El secreto cambia cada vez que inicia el proceso, por lo que no debe utilizarse para conservar sesiones ni para producción.

### `effective_refresh_cookie_name`

Devuelve el nombre real de la cookie refresh. En producción normalmente tendrá el prefijo `__Host-`.

```python
print(settings.effective_refresh_cookie_name)
```

### `effective_csrf_cookie_name`

Devuelve el nombre real de la cookie CSRF.

```python
print(settings.effective_csrf_cookie_name)
```

## 10. Referencia de `EpokAuth`

### `EpokAuth(settings=..., store=..., service=None, passkeys=None, google=None, google_store=None, email_link_service=None, email_link_sender=None, email_link_store=None, email_link_dispatcher=None)`

Construye la integración utilizando un store proporcionado manualmente. Se usa principalmente para adaptadores personalizados o pruebas.

```python
from epok_auth import AuthSettings, EpokAuth
from epok_auth.testing import MemoryAuthStore

store = MemoryAuthStore()
auth = EpokAuth(
    settings=AuthSettings.development(),
    store=store,
)
```

Para la prueba end-to-end usa preferentemente `EpokAuth.postgres()`.

Los adaptadores personalizados que habiliten Google deben declarar `google_store` explícitamente o
inyectar un `GoogleLoginService` completo. Esto permite comprobar que el contrato fue proporcionado
durante `install()` en lugar de fallar durante el primer request. `EpokAuth.postgres()` conecta ese
contrato automáticamente.

### `EpokAuth.postgres(...)`

Crea el store PostgreSQL oficial y devuelve la integración lista para instalar.

```python
settings = AuthSettings()
auth = EpokAuth.postgres(settings=settings)
```

Conecta el lifecycle a FastAPI para cerrar automáticamente el pool y cualquier cliente externo
creado por la facade:

```python
app = FastAPI(lifespan=auth.lifespan)
```

También puedes ejecutar `await auth.aclose()` durante un cierre administrado. La facade solo cierra
los recursos que creó; los stores y servicios inyectados siguen siendo responsabilidad del producto.

Parámetros opcionales:

```python
auth = EpokAuth.postgres(
    settings=settings,
    pool_size=5,
    max_overflow=10,
    pool_timeout=5.0,
    email_link_dispatcher=production_queue,
)
```

`settings.database_url` es obligatorio. El sender y el dispatcher son opcionales salvo cuando se
habilitan enlaces de correo; producción requiere el dispatcher durable.

### `auth.install(app, ...)`

Instala las rutas de autenticación, opcionalmente las rutas administrativas, passkeys, Google
Sign-In, Magic Links y los manejadores de errores.

```python
auth.install(
    app,
    prefix="/api/v1/auth",
    include_admin=True,
    include_passkeys=True,
    include_google=True,
    include_email_links=True,
    admin_prefix="/users",
)
```

Para la primera prueba esta es la función recomendada.
`include_passkeys=True` requiere el extra `passkeys` y `EPOK_AUTH_PASSKEY_RP_ID`.
`include_google=True` requiere el extra `google` y `EPOK_AUTH_GOOGLE_CLIENT_ID`.
`include_email_links=True` requiere los tres destinos frontend. En desarrollo y pruebas acepta un
`email_link_sender` inyectado o las variables `EPOK_AUTH_SMTP_*`. En producción exige un
`email_link_dispatcher` durable; el proceso web no necesita credenciales SMTP cuando el worker se
encarga de la entrega. Consulta [MAGIC_LINKS_ES.md](MAGIC_LINKS_ES.md) para el contrato de cola.
Cada prefijo se instala una sola vez. Varias instancias pueden compartir la misma aplicación siempre
que utilicen prefijos distintos. El lifespan de cualquiera de ellas cierra los recursos creados por
todas las instancias instaladas en esa app. Una instancia que crea o puede crear recursos internos,
como un pool PostgreSQL o el verificador Google lazy, no se puede compartir entre apps. Las
instalaciones duplicadas o ambiguas fallan durante el arranque.

### `auth.router(prefix=...)`

Devuelve únicamente el router de login, refresh, logout, sesión y cambio de contraseña.

```python
app.include_router(auth.router(prefix="/api/v1/auth"))
```

El uso manual no instala por sí solo los manejadores de errores. Usa `install()` salvo que necesites controlar el montaje directamente.

### `auth.admin_router(prefix=...)`

Devuelve el router administrativo protegido por el rol configurado como administrador.

```python
app.include_router(auth.admin_router(prefix="/api/v1/auth/users"))
```

También se instala automáticamente con `auth.install(..., include_admin=True)`.

### `auth.current_user`

Dependencia que valida el access token y entrega un `Principal`. Permite usuarios que todavía deben cambiar su contraseña.

```python
from fastapi import Depends
from epok_auth import Principal


@app.get("/onboarding")
async def onboarding(
    principal: Principal = Depends(auth.current_user),
) -> dict[str, bool]:
    return {"must_change_password": principal.must_change_password}
```

Úsala para `/me`, onboarding y cambio de contraseña. No es la dependencia recomendada para rutas de negocio.

### `auth.authenticated`

Dependencia predeterminada para rutas de negocio. Valida la sesión y rechaza usuarios con contraseña temporal pendiente.

```python
@app.get("/private")
async def private(
    principal: Principal = Depends(auth.authenticated),
) -> dict[str, str]:
    return {"email": principal.email}
```

### `auth.require_roles(*roles)`

Exige que el usuario posea todos los roles indicados.

```python
@app.get("/admin-only")
async def admin_only(
    principal: Principal = Depends(auth.require_roles("admin")),
) -> dict[str, str]:
    return {"admin": principal.email}
```

Los roles usan minúsculas y admiten letras, números, `:`, `.`, `_` y `-`.

### `auth.require_scopes(*scopes)`

Exige que el usuario posea todos los scopes indicados.

```python
@app.post("/colors")
async def create_color(
    principal: Principal = Depends(auth.require_scopes("colors:write")),
) -> dict[str, str]:
    return {"created_by": principal.email}
```

### `auth.require_recent_authentication(max_age_seconds=300)`

Exige que el login original sea reciente. Un refresh no reinicia `authenticated_at`.

```python
@app.delete("/dangerous-operation")
async def dangerous_operation(
    principal: Principal = Depends(auth.require_recent_authentication(max_age_seconds=300)),
) -> dict[str, str]:
    return {"confirmed_by": principal.email}
```

### `auth.protected_router(**kwargs)`

Crea un `APIRouter` donde todas las rutas requieren `auth.authenticated`.

```python
private = auth.protected_router(
    prefix="/api/v1/private",
    tags=["private"],
)


@private.get("")
async def private_endpoint(
    principal: Principal = Depends(auth.authenticated),
) -> dict[str, str]:
    return {"authenticated_user": principal.email}


app.include_router(private)
```

La dependencia del endpoint se mantiene cuando necesitas recibir el `Principal` dentro de la función.

## 11. Referencia de endpoints HTTP

Los ejemplos asumen:

```python
auth.install(app, prefix="/api/v1/auth", include_admin=True)
```

### `POST /api/v1/auth/login`

Inicia una sesión.

```json
{
  "email": "admin@example.com",
  "password": "C0lors-beta-2026!"
}
```

Requiere `Origin` cuando `require_origin=true`. Devuelve `access_token`, `csrf_token`, vencimientos y el usuario. También establece las cookies refresh y CSRF.

### `POST /api/v1/auth/refresh`

Rota la sesión.

Requiere la cookie refresh, la cookie CSRF, el header `X-CSRF-Token` con el mismo valor y un `Origin` confiable. Devuelve una sesión nueva y reemplaza las cookies.

### `POST /api/v1/auth/logout`

Revoca la familia de sesión y elimina las cookies.

Requiere las mismas cookies, CSRF y `Origin` que refresh. Devuelve `204`.

### `GET /api/v1/auth/me`

Devuelve el usuario de la sesión actual.

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" "$BASE/me"
```

Usa `current_user`, por lo que también funciona durante el cambio obligatorio de contraseña.

### `POST /api/v1/auth/change-password`

Cambia la contraseña, revoca las sesiones anteriores y devuelve una sesión nueva.

```json
{
  "current_password": "contraseña actual",
  "new_password": "contraseña nueva y segura"
}
```

Requiere Bearer token y `Origin` confiable.

### `GET /api/v1/auth/users`

Lista usuarios. Requiere el rol administrador.

```bash
curl -H "Authorization: Bearer $ADMIN_ACCESS" "$BASE/users?limit=100&offset=0"
```

### `POST /api/v1/auth/users`

Crea un usuario y devuelve una contraseña temporal.

```json
{
  "email": "user@example.com",
  "display_name": "Usuario Beta",
  "roles": ["user"],
  "scopes": ["colors:read"]
}
```

Si omites `roles`, se utiliza `default_user_role`.

### `GET /api/v1/auth/users/{user_id}`

Obtiene un usuario por UUID.

```bash
curl \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  "$BASE/users/$USER_ID"
```

### `PATCH /api/v1/auth/users/{user_id}`

Actualiza nombre, estado, roles o scopes.

```json
{
  "display_name": "Usuario Colors",
  "roles": ["user", "editor"],
  "scopes": ["colors:read", "colors:write"]
}
```

Los estados válidos son `active` y `disabled`. Deshabilitar un usuario revoca sus sesiones. La librería impide eliminar o deshabilitar al último administrador activo.

### `POST /api/v1/auth/users/{user_id}/reset-password`

Genera una contraseña temporal nueva y revoca las sesiones del usuario.

```bash
curl -X POST \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  "$BASE/users/$USER_ID/reset-password"
```

La contraseña temporal de la respuesta debe tratarse como un secreto de una sola entrega.

### `POST /api/v1/auth/users/{user_id}/revoke-sessions`

Revoca todas las sesiones del usuario.

```bash
curl -X POST \
  -H "Authorization: Bearer $ADMIN_ACCESS" \
  "$BASE/users/$USER_ID/revoke-sessions"
```

La respuesta contiene:

```json
{
  "revoked_sessions": 1
}
```

## 12. Funciones Python de migración

Estas funciones son útiles cuando el producto administra migraciones desde su propio proceso en lugar de utilizar el CLI.

### `upgrade_database(database_url, revision="head")`

```python
from epok_auth.migrate import upgrade_database

upgrade_database("postgresql://epok_auth:epok_auth@127.0.0.1:5432/epok_auth")
```

### `check_database(database_url)`

```python
from epok_auth.migrate import check_database

check_database("postgresql://epok_auth:epok_auth@127.0.0.1:5432/epok_auth")
```

No devuelve datos. Finaliza correctamente cuando no existe drift y lanza una excepción de Alembic cuando detecta diferencias.

### `downgrade_database(database_url, revision="base")`

```python
from epok_auth.migrate import downgrade_database

downgrade_database("postgresql://epok_auth:epok_auth@127.0.0.1:5432/epok_auth")
```

Esta función elimina el esquema al bajar hasta `base`. Úsala únicamente sobre una base de prueba desechable.

## 13. Tipos públicos mínimos

### `Principal`

Representa al usuario autenticado. Sus campos principales son `user_id`, `session_id`, `family_id`, `email`, `display_name`, `roles`, `scopes`, `must_change_password` y `authenticated_at`.

### `UserAccount`

Representa una cuenta persistida. Normalmente se consume mediante las respuestas administrativas, no directamente desde una ruta de negocio.

### `Environment`

Valores disponibles:

```python
Environment.DEVELOPMENT
Environment.TEST
Environment.PRODUCTION
```

### `UserStatus`

Valores disponibles:

```python
UserStatus.ACTIVE
UserStatus.DISABLED
```

### `AuthError` y `AuthErrorCode`

Los errores de autenticación se transforman automáticamente en respuestas JSON cuando utilizas `auth.install()`.

Formato:

```json
{
  "code": "invalid_session",
  "detail": "Session is invalid or expired.",
  "request_id": null
}
```

## 14. Limpieza de la prueba

```bash
rm -f admin.cookies user.cookies

docker rm -f epok-auth-postgres
```

Con este flujo quedan probadas la configuración, las migraciones, el administrador inicial, login, acceso autenticado, contraseña temporal, cambio de contraseña, roles, scopes, refresh, revocación y logout.

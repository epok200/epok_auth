# Reautenticación para acciones sensibles

`epok-auth 0.7.1` permite volver a verificar al usuario de una sesión activa mediante contraseña o
passkey. El resultado confirma identidad y sesión, pero no es un token, no crea otra sesión y no
decide qué acción del producto queda autorizada.

## 1. Mapa de responsabilidades

Hay tres niveles:

1. `epok-auth` verifica la credencial y devuelve un `Reauthentication`.
2. El producto vincula esa prueba con una intención concreta, por ejemplo restaurar una operación.
3. El mismo producto consume la confirmación al ejecutar la acción sensible.

Esta separación evita que una prueba genérica autorice más acciones de las necesarias.

## 2. Instalación

Para contraseña y PostgreSQL:

```bash
uv add "epok-auth[postgres]==0.7.1"
```

Para passkeys:

```bash
uv add "epok-auth[postgres,passkeys]==0.7.1"
```

Aplica la migración antes de servir la nueva versión:

```bash
uv run epok-auth upgrade-db
uv run epok-auth check-db
```

La migración `0006_passkey_reauthentication` agrega `family_id` a los challenges WebAuthn. Su
downgrade elimina únicamente ceremonias de reautenticación en curso.

## 3. Resultado común

Ambos métodos devuelven el mismo value object inmutable:

```python
from epok_auth import Reauthentication, ReauthenticationMethod
```

`Reauthentication` contiene:

- `user_id`, dueño de la credencial verificada;
- `session_id`, sesión exacta que pidió la verificación;
- `family_id`, continuidad de la sesión a través de refresh;
- `method`, `password` o `passkey`;
- `verified_at`, instante autoritativo de la prueba.

El objeto solo vive dentro del backend. No debe serializarse como bearer token ni guardarse en el
navegador.

## 4. Contraseña

El endpoint del producto recibe la contraseña mediante `POST`, obtiene el `Principal` actual y llama
al servicio:

```python
proof = await auth.service.reauthenticate_password(
    principal,
    payload.password,
    context=auth.http.request_context(request),
)
```

La verificación reutiliza la política existente de hash, upgrade, intentos fallidos y lockout. Un
fallo puede bloquear la cuenta y revocar sus sesiones conforme a la configuración vigente. Un éxito
no crea ni rota sesión.

## 5. Passkey

El producto expone dos endpoints propios. El primero crea las opciones WebAuthn:

```python
options = await auth.passkey_service.begin_reauthentication(principal, origin)
```

El navegador firma el challenge. El segundo endpoint verifica la respuesta:

```python
proof = await auth.passkey_service.finish_reauthentication(
    principal,
    payload.ceremony_id,
    payload.credential,
    origin,
    context=auth.http.request_context(request),
)
```

El challenge queda ligado a `user_id` y `family_id`. Un refresh conserva esa familia y puede
terminar la ceremonia. Otra sesión del mismo usuario no puede consumirla. El challenge es temporal,
de un solo uso y se consume antes de validar la firma.

`epok-auth` no instala rutas HTTP genéricas de reautenticación. Cada producto define sus DTO, URLs y
política de confirmación para que el contrato visible exprese la acción real.

## 6. Confirmación propia del producto

Una confirmación segura debe ser específica para una intención. Como mínimo, el producto conserva:

- un identificador aleatorio de un solo uso;
- `user_id` y `family_id` del `Reauthentication`;
- propósito exacto;
- recurso y destino de la acción;
- revisión o versión observada;
- vencimiento corto;
- instante de consumo.

La confirmación y la mutación sensible se consumen en la misma transacción de PostgreSQL. Si la
acción falla, ambas se revierten. Si la confirmación ya venció, cambió la revisión, pertenece a otra
familia o ya fue usada, la acción falla cerrada.

No uses una confirmación global como `recently_authenticated=true`. Tampoco aceptes solo la edad de
`authenticated_at`, porque eso prueba un login pasado y no la intención actual.

## 7. Router FastAPI mínimo

[`examples/reauthentication/router.py`](../examples/reauthentication/router.py) contiene un router
completo y compacto para copiar. Incluye:

- DTO con `SecretStr` para contraseña;
- `auth.authenticated` como dependencia;
- validación de Origin en ambos métodos;
- contexto de auditoría derivado del `Request`;
- `Cache-Control: no-store` en las respuestas exitosas;
- contrato `RestoreConfirmationIssuer` para que el producto persista su confirmación.

La única pieza inyectada es `RestoreConfirmationIssuer`. Su implementación debe escribir la
confirmación en la misma base autoritativa del producto. El ejemplo no incluye un store en memoria
porque ese mecanismo no sería seguro entre procesos ni permitiría consumo atómico con la acción.

## 8. Eventos y manejo de errores

Las verificaciones de credencial que alcanzan el servicio generan:

- `REAUTHENTICATION_SUCCEEDED`;
- `REAUTHENTICATION_FAILED`.

El metadata incluye el método y, para passkeys exitosas, el identificador de la credencial. La API
conserva los `AuthError` existentes para credenciales, sesión, challenge y firma inválidos. El
producto debe traducirlos con su handler central sin revelar si la contraseña, credencial o sesión
fue la causa interna. Un Origin rechazado o un `Principal` inválido puede fallar antes de registrar
un evento de reautenticación.

## 9. Invariantes operativas

- La reautenticación requiere una sesión activa y un usuario autenticable.
- Ningún método crea, reemplaza o renueva una sesión.
- Ningún método cambia `authenticated_at`.
- Los éxitos no emiten eventos de login ni de creación de sesión.
- La librería verifica identidad. El producto autoriza y consume la acción.
- Los endpoints deben usar `Cache-Control: no-store`, HTTPS, Origin exacto y rate limiting.

# Publicación y versionado

Esta guía deja `epok-auth` listo para publicarse desde un checkout limpio de `main` usando `uv` y un token local de PyPI.

## Decisiones del proyecto

La versión se declara una sola vez en `pyproject.toml`:

```toml
[project]
version = "0.1.0b1"
```

`epok_auth.__version__` se obtiene mediante `importlib.metadata`, por lo que no hay una segunda constante que mantener. `uv version` actualiza el proyecto y, salvo que se indique lo contrario, también actualiza `uv.lock`.

Hatchling permanece como backend PEP 517 porque ya empaqueta correctamente el código, `py.typed` y las migraciones Alembic. `uv` administra el entorno, la versión, el lockfile, el build y la publicación.

## Consultar y cambiar la versión

Consultar únicamente la versión actual:

```bash
uv version --short
```

Pasar de una beta a la siguiente:

```bash
uv version --bump beta
```

Ejemplo:

```text
0.1.0b1 -> 0.1.0b2
```

Cerrar una prerelease como versión estable:

```bash
uv version --bump stable
```

Ejemplo:

```text
0.1.0b2 -> 0.1.0
```

Crear el siguiente patch estable:

```bash
uv version --bump patch
```

Después de cualquier cambio de versión, revisa y confirma ambos archivos:

```bash
git diff -- pyproject.toml uv.lock
git add pyproject.toml uv.lock
git commit -m "chore: bump epok-auth to $(uv version --short)"
```

Para la primera publicación de esta beta no ejecutes un bump: la versión preparada es `0.1.0b1`.

## Preparar el token local

Copia el template:

```bash
cp .env.secret.example .env.secret
```

Edita `.env.secret` y coloca el token:

```dotenv
UV_PUBLISH_TOKEN="pypi-..."
```

`.env.secret` está ignorado por Git. El script se detiene si detecta que el archivo está trackeado o dejó de estar ignorado.

Para la primera carga puedes usar el token disponible para tu cuenta. Después de que PyPI cree el proyecto, reemplázalo por un token limitado exclusivamente a `epok-auth`. A largo plazo conviene migrar a Trusted Publishing con OIDC para eliminar tokens permanentes.

## Validación sin publicar

Desde `main`, con el árbol limpio:

```bash
bash scripts/publish.sh --dry-run
```

La validación ejecuta:

```text
uv lock --check
instalación reproducible
Ruff format y lint
Pyright estricto
suite no integrada
uv build --no-sources
wheel y sdist
instalación aislada del wheel
coincidencia de importlib.metadata y epok_auth.__version__
smoke test del CLI
uv publish --dry-run contra PyPI
```

Las pruebas PostgreSQL, cobertura completa y CodeQL deben estar verdes previamente en GitHub Actions.

## Publicar

Desde `main`, con CI verde y `.env.secret` configurado:

```bash
bash scripts/publish.sh
```

El script vuelve a construir todo desde cero y solicita escribir la versión exacta antes de ejecutar la subida. Para esta beta deberás confirmar:

```text
0.1.0b1
```

PyPI trata cada versión como inmutable. Si necesitas cambiar el contenido después de publicarla, crea una versión nueva; no intentes reutilizar el mismo número.

## Crear el tag después de publicar

Cuando la subida haya terminado correctamente:

```bash
VERSION="$(uv version --short)"
git tag -a "v$VERSION" -m "epok-auth $VERSION"
git push origin "v$VERSION"
```

Después puedes crear una GitHub Release utilizando el contenido correspondiente de `CHANGELOG.md`.

## Verificar la instalación publicada

```bash
VERSION="$(uv version --short)"
uv run \
  --with "epok-auth[postgres]==$VERSION" \
  --no-project \
  --refresh-package epok-auth \
  -- python -c 'import epok_auth; print(epok_auth.__version__)'
```

La salida debe coincidir exactamente con `uv version --short`.

## Secuencia para cerrar `0.1.0`

Después de validar la beta dentro de Colors:

```bash
git checkout main
git pull --ff-only
uv version --bump stable
git add pyproject.toml uv.lock
git commit -m "chore: release epok-auth 0.1.0"
git push origin main
```

Espera a que CI y CodeQL estén verdes y después ejecuta:

```bash
bash scripts/publish.sh --dry-run
bash scripts/publish.sh
```

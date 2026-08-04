# Publicación y versionado

Esta guía deja `epok-auth` listo para publicarse desde un checkout limpio y actualizado de `main` usando `uv` y un token local de PyPI.

## Decisiones del proyecto

La versión se declara una sola vez en `pyproject.toml`:

```toml
[project]
version = "0.1.0b1"
```

`epok_auth.__version__` se obtiene mediante `importlib.metadata`, por lo que no hay una segunda constante que mantener. `uv version` actualiza el proyecto y, salvo que se indique lo contrario, también actualiza `uv.lock`.

Hatchling permanece como backend PEP 517 porque empaqueta correctamente el código, `py.typed` y las migraciones Alembic. `uv` administra el entorno, la versión, el lockfile, el build y la publicación.

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

Para la primera publicación no ejecutes un bump: la versión preparada es `0.1.0b1`. Es una beta pública deliberadamente, porque la integración completa con Colors todavía no forma parte de la evidencia de esta release.

## Preparar el token local

Copia el template:

```bash
cp .env.secret.example .env.secret
```

Edita `.env.secret` y coloca el token:

```dotenv
UV_PUBLISH_TOKEN="pypi-..."
```

El archivo admite únicamente esa variable y comentarios. El script lo analiza como datos y **no lo ejecuta como código shell**. Además, se detiene si `.env.secret` está trackeado o dejó de estar ignorado por Git.

Para la primera carga puedes utilizar un token con alcance para toda tu cuenta. Después de que PyPI cree el proyecto, reemplázalo por un token limitado exclusivamente a `epok-auth`. A largo plazo conviene migrar a Trusted Publishing con OIDC para eliminar tokens permanentes.

## Validación sin publicar

Parte de un `main` limpio y actualizado:

```bash
git checkout main
git pull --ff-only
bash scripts/publish.sh --dry-run
```

El script verifica que el commit local coincida exactamente con `origin/main` y ejecuta:

```text
uv lock --check
instalación reproducible
Ruff format y lint
Pyright estricto
suite no integrada
uv build --no-sources
verificación del wheel y del sdist
instalación aislada del wheel
instalación aislada del sdist
coincidencia de importlib.metadata y epok_auth.__version__
smoke test del CLI
uv publish --dry-run contra PyPI
```

Las pruebas PostgreSQL, cobertura completa y CodeQL deben estar verdes previamente en GitHub Actions. La CI también construye e instala de forma aislada tanto el wheel como el source distribution.

## Publicar

Desde `main`, con CI verde y `.env.secret` configurado:

```bash
bash scripts/publish.sh
```

El script vuelve a construir todo desde cero y solicita escribir la versión exacta antes de ejecutar la subida. Para esta beta deberás confirmar:

```text
0.1.0b1
```

PyPI trata cada versión como inmutable. Si necesitas cambiar el contenido después de publicarla, crea una versión nueva; no intentes reutilizar el mismo número. Para la siguiente beta:

```bash
uv version --bump beta
```

## Crear el tag después de publicar

Cuando la subida haya terminado correctamente:

```bash
VERSION="$(uv version --short)"
git tag -a "v$VERSION" -m "epok-auth $VERSION"
git push origin "v$VERSION"
```

El script de publicación rechaza una versión cuyo tag ya exista. El orden deliberado es **publicar primero y etiquetar después**, para no dejar un tag de release apuntando a una carga fallida.

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

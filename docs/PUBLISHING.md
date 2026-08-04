# Publicación y versionado

`epok-auth` se publica desde un checkout limpio y actualizado de `main` mediante un único orquestador Python:

```bash
uv run scripts/publish.py
```

El script usa metadata PEP 723, por lo que `uv` ejecuta el orquestador en un entorno aislado con Typer, Rich y Packaging. No depende de la versión de Python activa en `.venv` ni reemplaza el entorno local del proyecto durante la publicación.

El antiguo comando continúa disponible como alias de compatibilidad:

```bash
bash scripts/publish.sh
```

## Requisitos

La máquina de publicación necesita:

```text
Git
uv
Docker en ejecución
acceso a GitHub y PyPI
```

Docker se utiliza para ejecutar PostgreSQL 17 en un contenedor desechable durante las pruebas de migración, drift, integración, concurrencia y cobertura.

## Fuente única de versión

La versión se declara una sola vez en `pyproject.toml`:

```toml
[project]
version = "0.1.0b1"
```

`epok_auth.__version__` se obtiene mediante `importlib.metadata`, así que no existe una segunda constante que mantener.

Este comando imprime únicamente la versión del proyecto actual:

```bash
uv version --short
```

No muestra la versión instalada de `uv`; para eso se utiliza `uv --version`.

## Cambiar la versión

Siguiente beta:

```bash
uv version --bump beta
```

```text
0.1.0b1 -> 0.1.0b2
```

Cerrar la prerelease como estable:

```bash
uv version --bump stable
```

```text
0.1.0b2 -> 0.1.0
```

Siguiente patch estable:

```bash
uv version --bump patch
```

Después de cambiar la versión:

```bash
git diff -- pyproject.toml uv.lock
git add pyproject.toml uv.lock
git commit -m "chore: bump epok-auth to $(uv version --short)"
git push origin main
```

Espera a que CI y CodeQL estén verdes antes de publicar.

## Token local de PyPI

Crea el archivo local desde el template:

```bash
cp .env.secret.example .env.secret
chmod 600 .env.secret
```

Contenido:

```dotenv
UV_PUBLISH_TOKEN="pypi-..."
```

`.env.secret` está ignorado por Git. El orquestador lo interpreta como datos mediante un parser restringido; nunca lo ejecuta como shell. Solo admite comentarios y una definición de `UV_PUBLISH_TOKEN`.

Después de crear el proyecto en PyPI, utiliza preferentemente un token limitado únicamente a `epok-auth`.

## Modos del pipeline

### Validar la versión actual

```bash
uv run scripts/publish.py --validate-only
```

Ejecuta toda la validación local, el build y los smoke tests, pero no consulta ni modifica PyPI y no crea tags. Es el modo adecuado para volver a probar una versión que ya fue publicada, como `0.1.0b1`.

### Simular una release nueva

```bash
uv run scripts/publish.py --dry-run
```

Ejecuta todas las verificaciones y termina con `uv publish --dry-run`. No sube artefactos ni crea tags. La versión debe ser nueva y no tener un tag existente.

### Publicar

```bash
uv run scripts/publish.py
```

Después de superar todas las compuertas, solicita escribir la versión exacta. Si coincide, publica, crea y empuja el tag anotado y verifica la instalación desde PyPI.

Para publicar sin crear el tag automáticamente:

```bash
uv run scripts/publish.py --no-tag
```

## Validaciones ejecutadas

El comando normal realiza, en orden:

```text
rama main y árbol limpio
main local idéntico a origin/main
.env.secret ignorado y no trackeado
versión PEP 440 válida y tag todavía inexistente
uv lock --check
Ruff format
Ruff lint y reglas de seguridad
Pyright estricto
compileall
pip-audit
suite no integrada en Python 3.12
suite no integrada en Python 3.13
suite no integrada en Python 3.14
PostgreSQL 17 desechable en Docker
migración desde una base vacía
cero drift Alembic
pruebas PostgreSQL y de concurrencia
cobertura branch-aware mínima de 90%
uv build --no-sources
exactamente un wheel y un sdist
instalación aislada del wheel
instalación aislada del sdist
versión runtime igual a la metadata
smoke test del CLI
uv publish --dry-run
confirmación humana de la versión
uv publish
tag anotado y push a origin
instalación pública desde PyPI con reintentos
```

Los comandos de proyecto se ejecutan con `uv run --isolated`, por lo que la validación no cambia el `.venv` que utiliza el desarrollador.

El contenedor PostgreSQL se elimina en un bloque de limpieza aunque una prueba falle o el proceso sea interrumpido.

## Primera ejecución después de esta mejora

`0.1.0b1` ya fue publicada y tiene el tag `v0.1.0b1`. Por tanto, para comprobar ahora el pipeline utiliza:

```bash
uv run scripts/publish.py --validate-only
```

No intentes volver a publicar `0.1.0b1`: las versiones de PyPI son inmutables.

Para una futura beta:

```bash
uv version --bump beta
git add pyproject.toml uv.lock
git commit -m "chore: bump epok-auth to $(uv version --short)"
git push origin main
```

Después:

```bash
uv run scripts/publish.py --dry-run
uv run scripts/publish.py
```

## Recuperación después de una publicación parcial

Si `uv publish` termina correctamente pero la propagación de PyPI tarda, no vuelvas a cargar la misma versión. El script reintenta la instalación pública varias veces; si aun así falla, verifica más tarde con:

```bash
VERSION="$(uv version --short)"
uv run \
  --no-project \
  --refresh-package epok-auth \
  --with "epok-auth[postgres]==$VERSION" \
  -- python -c 'import epok_auth; print(epok_auth.__version__)'
```

Si PyPI fue publicado pero el push del tag falló, el orquestador muestra el comando de recuperación:

```bash
git push origin "v$(uv version --short)"
```

Nunca reutilices el mismo número para artefactos diferentes.

## Cerrar `0.1.0`

Después de validar la beta dentro de Colors:

```bash
git checkout main
git pull --ff-only
uv version --bump stable
git add pyproject.toml uv.lock
git commit -m "chore: release epok-auth 0.1.0"
git push origin main
```

Con CI y CodeQL verdes:

```bash
uv run scripts/publish.py --dry-run
uv run scripts/publish.py
```

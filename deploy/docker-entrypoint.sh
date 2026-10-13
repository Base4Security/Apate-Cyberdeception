#!/bin/sh
# Entrypoint de la imagen de APATE.
#
# Arranca como root solo para dejar el volumen de datos en manos del usuario
# `apate` (un volumen recien montado llega con dueno root), y despues se
# vuelve a ejecutar a si mismo con privilegios reducidos via `setpriv`.
# Nada de la aplicacion corre como root.
set -eu

DATA_DIR="${APATE_DATA_DIR:-/data}"

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    chown -R apate:apate "$DATA_DIR"
    exec setpriv --reuid=apate --regid=apate --init-groups "$0" "$@"
fi

# Datos de ejemplo sinteticos, solo si se piden explicitamente: una
# instalacion real no debe arrancar con operaciones inventadas.
if [ "${APATE_SEED_DEMO:-0}" = "1" ]; then
    python /app/examples/seed_demo.py
fi

# Un comando explicito (`docker run ... <cmd>`) reemplaza al servidor.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

# Un unico worker threaded: Flask-SocketIO con async_mode="threading"
# mantiene estado en memoria por proceso (ver docs/instalacion-produccion.md).
# Sin socket de control: su ruta por defecto cae bajo el HOME de root, que el
# usuario `apate` no puede escribir.
exec gunicorn \
    --workers 1 \
    --worker-class gthread \
    --threads 100 \
    --no-control-socket \
    --bind "0.0.0.0:${PORT:-8080}" \
    apate.web.wsgi:app

# Imagen de la demo online de Parallax Deception (ver docs/despliegue-fly.md).
#
# Python 3.11 a proposito: es la version con la que se desarrolla el
# proyecto y con la que corre la suite. Ninguna dependencia necesita
# compilador -- fpdf2/pypdf/python-evtx/pywinrm son Python puro, y
# cryptography/Pillow publican wheels precompilados -- asi que no hace
# falta build-essential ni una etapa de compilacion aparte.
FROM python:3.11-slim-bookworm@sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b

# Procedencia del binario, para el aviso de licencia de /about (AGPLv3
# art. 13): la imagen no lleva `.git`, asi que el commit tiene que entrar
# por aca o la pantalla dira "revision no declarada".
#   fly deploy --build-arg APATE_BUILD_COMMIT=$(git rev-parse HEAD)
# APATE_SOURCE_URL puede fijarse en build (incluye la referencia en el SBOM)
# o al desplegar. Debe apuntar al fuente correspondiente de ESTA version.
ARG APATE_BUILD_COMMIT=""
ARG APATE_SOURCE_URL=""

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APATE_DATA_DIR=/data \
    APATE_BUILD_COMMIT=${APATE_BUILD_COMMIT} \
    APATE_SOURCE_URL=${APATE_SOURCE_URL} \
    PORT=8080

WORKDIR /app

# Instalacion real (no editable): `pip install .` publica ademas los
# entry points de `apate.plugins` y `apate.identity_providers`, de los
# que dependen PluginRegistry e IdentityProviderRegistry para resolver
# las seis capacidades y el proveedor de identidad local.
COPY pyproject.toml README.md setup.py MANIFEST.in LICENSE NOTICE ./
COPY requirements ./requirements
COPY src ./src
COPY examples ./examples
COPY playground-stack ./playground-stack
RUN pip install --no-cache-dir --require-hashes -r requirements/build.txt \
    && pip install --no-cache-dir --no-build-isolation --require-hashes -r requirements/release.txt \
    && pip install --no-cache-dir --no-build-isolation --no-deps '.[prod]' \
    && pip check

# SBOM de la imagen, generado DESPUES de instalar y contra el entorno ya
# instalado: es el unico momento en que las versiones son las que van a
# correr de verdad. Generarlo antes, o desde el repositorio, produciria un
# inventario que el escaner del cliente cruza contra CVE equivocados. El
# commit ya esta en el entorno, asi que el archivo queda atado a este build.
RUN python -m apate.sbom > /app/apate.cdx.json

# `setpriv` (util-linux) ya viene en la imagen base; el entrypoint lo usa
# para bajar privilegios despues de ajustar el dueño del volumen. Se
# comprueba en tiempo de build para que su ausencia falle aca, y no en el
# arranque de una maquina ya desplegada.
RUN command -v setpriv > /dev/null \
    && useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin apate

COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

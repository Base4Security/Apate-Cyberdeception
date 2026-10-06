# Instalación de producción

Esta guía instala Apate en Linux detrás de un proxy reverso. Windows sigue siendo un entorno de
desarrollo: `python -m apate.web` usa el servidor de desarrollo y no es un servidor de producción.

## Límites de la arquitectura actual

Apate usa Flask-SocketIO con `async_mode="threading"` y mantiene sesiones de Playground y
notificaciones en memoria. Por eso la instalación soportada es **un proceso Gunicorn, un worker y
varios hilos**; no inicies más workers ni varias réplicas de esta instancia. Para escalar harían falta
una cola de mensajes y una revisión explícita de eventlet/gevent, Docker, WinRM y SQLite; no se
incluyen en esta edición.

## Requisitos

- Linux con Python 3.10 o superior, `venv` y un proxy reverso (nginx en este ejemplo).
- Acceso de red a las integraciones que vayas a usar y almacenamiento persistente para los datos.
- Docker solo si vas a desplegar decoys o ejecutar el Playground.

> Dar al proceso acceso al socket Docker del host (`/var/run/docker.sock`) equivale en la práctica a
> darle privilegios de root sobre ese host. Evaluá ese riesgo antes de habilitar las capacidades que
> controlan Docker; no es un requisito para consultar datos ni para usar funciones sin despliegue.

## Instalar y configurar

```bash
sudo useradd --system --home /opt/apate --shell /usr/sbin/nologin apate
sudo mkdir -p /opt/apate /var/lib/apate /etc/apate
sudo chown apate:apate /opt/apate /var/lib/apate
sudo -u apate git clone <URL-DEL-REPOSITORIO> /opt/apate
sudo -u apate python3 -m venv /opt/apate/.venv
sudo -u apate /opt/apate/.venv/bin/pip install '/opt/apate[prod]'
```

Creá `/etc/apate/apate.env`, propiedad de `root:apate` y modo `0640`. Generá ambas claves con un
gestor de secretos del sistema; no las dejes vacías ni las copies al repositorio.

```dotenv
APATE_SECRET_KEY=<clave-aleatoria-larga-para-sesiones>
APATE_SECRET_ENCRYPTION_KEY=<clave-Fernet-estable>
BUDA_CREDENTIAL_ENCRYPTION_KEY=<clave-Fernet-estable-para-perfiles-WinRM>
APATE_DATA_DIR=/var/lib/apate
APATE_TRUSTED_PROXY=1
APATE_MOUNT_EXTERNAL_TOOLS=1
# APATE_PLAYGROUND_PATH=/opt/apate/playground-stack
# APATE_ELASTIC_URL=http://127.0.0.1:9200
# APATE_IDENTITY_PROVIDER=local
```

`APATE_SECRET_KEY`, `APATE_SECRET_ENCRYPTION_KEY` y
`BUDA_CREDENTIAL_ENCRYPTION_KEY` son obligatorias en producción: la primera
evita que las sesiones se invaliden en cada reinicio, la segunda protege los
secretos propios y la tercera permite recuperar las credenciales WinRM de los
perfiles de identidad. Si falta la clave BUDA, Apate crea una
clave local estable bajo `APATE_DATA_DIR` para el desarrollo y deja una
advertencia; es una comodidad para una instalación local, no una configuración
de producción. La variable de entorno siempre tiene prioridad sobre ese
archivo.

Con la instancia nueva y sin usuarios, creá al menos una cuenta de administración desde la
interfaz en `/health/administration/users` antes de exponer el proxy.

Si necesitás una instalación sin navegador (CI, despliegues desatendidos o recuperación de
emergencia), podés usar `create-user` de forma temporal con `APATE_INITIAL_PASSWORD`; luego eliminala
del archivo de entorno:

```bash
set -a; . /etc/apate/apate.env; set +a
APATE_INITIAL_PASSWORD='<contraseña-inicial>' \
  /opt/apate/.venv/bin/flask --app apate.web:create_app create-user administrador
```

**Nota de recuperación:** si por error desactivás al último administrador activo, la pantalla de
usuarios ya no acepta otro login y la recuperación de la gestión de acceso queda exclusivamente en
`create-user`. La pantalla lo impide, pero un registro editado a mano puede dejar la instancia en
ese estado.

**Resetear la contraseña de alguien cierra su sesión abierta.** Es lo que hace falta ante una cuenta
comprometida: bloquear el próximo inicio de sesión no sirve si el intruso ya está adentro. Cada
identidad lleva una versión de credencial que se incrementa al cambiar la contraseña; la sesión
recuerda la versión con la que se inició y deja de valer cuando no coincide.

Con dos matices deliberados: **cambiar tu propia contraseña no te desloguea** (acabás de demostrar que
controlás la cuenta) y **ninguna otra persona se ve afectada**. Actualizar desde una versión anterior
tampoco desloguea a nadie: las sesiones y los registros sin ese campo se leen como versión inicial.

**Desactivar** la cuenta también corta el acceso en el acto (`get()` solo resuelve identidades
activas), y sigue siendo lo indicado cuando la persona ya no debe entrar más. Tené en cuenta el efecto
secundario: el nombre visible de una cuenta desactivada queda tomado y no se puede reutilizar.

## Servidor y servicio

El comando soportado es el siguiente; `--threads 100` selecciona el worker threaded y
`simple-websocket` viene incluido en el extra `prod`.

```bash
/opt/apate/.venv/bin/gunicorn --workers 1 --worker-class gthread --threads 100 --bind 127.0.0.1:8000 apate.web.wsgi:app
```

Ejemplo de `/etc/systemd/system/apate.service`:

```ini
[Unit]
Description=Apate
After=network.target

[Service]
User=apate
Group=apate
WorkingDirectory=/opt/apate
EnvironmentFile=/etc/apate/apate.env
ExecStart=/opt/apate/.venv/bin/gunicorn --workers 1 --worker-class gthread --threads 100 --bind 127.0.0.1:8000 apate.web.wsgi:app
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Activá el servicio con `sudo systemctl daemon-reload`, `sudo systemctl enable --now apate` y revisá
`sudo journalctl -u apate -f` si falla.

> `--worker-class gthread` va explícito a propósito. Gunicorn ya lo elige solo cuando `--threads` es
> mayor que 1, pero de forma implícita: bajar `--threads` a 1 al ajustar el servicio devuelve el worker
> `sync`, y ahí los WebSocket del Playground dejan de funcionar sin ningún error visible. Un worker
> distinto de `gthread`, o más de un `--workers`, rompen las notificaciones en vivo por la misma razón
> que explica "Límites de la arquitectura actual".

## nginx y TLS

nginx termina TLS; Apate nunca recibe certificados ni debe exponerse directamente a Internet. Este
ejemplo debe incluir certificados válidos y una redirección de HTTP a HTTPS:

```nginx
server {
    listen 80;
    server_name apate.example.org;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name apate.example.org;
    ssl_certificate     /etc/letsencrypt/live/apate.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/apate.example.org/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

`APATE_TRUSTED_PROXY=1` habilita `ProxyFix` para una sola capa de proxy y activa la cookie de sesión
`Secure`; no lo uses si Gunicorn acepta conexiones directas de redes no confiables. Mantené Gunicorn
en `127.0.0.1` como muestra el servicio.

## Inicio de sesión corporativo (OIDC)

Opcional. Sin esto, Apate usa su proveedor local: usuarios y contraseñas propias, creados con
`create-user`. Con OIDC, la autenticación la hace el proveedor de identidad de la organización y Apate
nunca ve la contraseña.

**SAML no está soportado**, y es una decisión, no un olvido: su librería habitual en Python depende de
`xmlsec`/`libxml2` instaladas en el sistema, y todo el proyecto evita dependencias que hagan fallar un
`pip install` por faltar una librería del sistema operativo.

### 1. Registrar Apate en el proveedor

Creá una aplicación de tipo *Web* / *Authorization Code*. La URL de retorno es:

```
https://<tu-dominio>/login/oidc/callback
```

Anotá el emisor (*issuer*), el identificador de cliente y su secreto, y las tres URL del proveedor
(autorización, token y JWKS). En un proveedor que publica su descubrimiento, las tres salen de
`https://<emisor>/.well-known/openid-configuration`.

### 2. Configurar Apate

```ini
APATE_IDENTITY_PROVIDER=oidc
APATE_OIDC_ISSUER=https://tu-proveedor.example.com
APATE_OIDC_CLIENT_ID=<identificador-de-cliente>
APATE_OIDC_CLIENT_SECRET=<secreto-de-cliente>
APATE_OIDC_AUTHORIZATION_ENDPOINT=https://tu-proveedor.example.com/authorize
APATE_OIDC_TOKEN_ENDPOINT=https://tu-proveedor.example.com/token
APATE_OIDC_JWKS_URI=https://tu-proveedor.example.com/.well-known/jwks.json
APATE_OIDC_EMERGENCY_USERNAME=rescate
APATE_OIDC_EMERGENCY_PASSWORD_HASH=<hash-generado-abajo>
```

### 3. La cuenta de emergencia — leé esto antes de seguir

Si el proveedor de identidad se cae o queda mal configurado y **no hay una salida local, nadie entra a
Apate, ni siquiera para arreglarlo**. Por eso **no arranca** con OIDC si esta cuenta no está
configurada: es una salida que no se puede olvidar.

Generá el hash sin dejar la contraseña en el historial del shell:

```bash
python -c "from werkzeug.security import generate_password_hash; import getpass; print(generate_password_hash(getpass.getpass()))"
```

Esa cuenta entra por el formulario local con rol de administración. Tratala como una credencial de
emergencia: contraseña larga, guardada donde guardes las de ese tipo, y rotada si se usa.

### 4. Dar de alta a las personas

**El proveedor autentica; Apate autoriza.** Que alguien exista en el directorio corporativo no le da
acceso: hay que darlo de alta explícitamente, con su rol y su equipo. Sin eso recibe un 403 al volver
del proveedor. Es deliberado — si bastara con autenticar, cualquier cuenta del directorio entraría, y
con qué rol y qué equipo sería una decisión tomada por omisión.

```bash
/opt/apate/.venv/bin/flask --app apate.web:create_app provision-oidc-user '<sub>' "Nombre Visible" --role operation --team soc
```

**`<sub>` es el claim `sub` del proveedor, no el correo.** Es lo que viaja en el token y con lo que se
hace el match. Usar el correo es el error clásico: cambia cuando alguien se casa o cambia de área, y
ahí esa persona deja de poder entrar. En Okta y Azure AD el `sub` se ve en el token de prueba de la
consola de administración, o en el endpoint `/userinfo`.

### Diagnóstico

| Síntoma | Causa habitual |
|---|---|
| 400 al volver del proveedor | El `state` no coincide: la sesión se perdió (¿falta `APATE_SECRET_KEY` fija?) o el retorno no salió de esta app |
| 401 al volver | El token no validó: emisor, audiencia o firma incorrectos, o reloj desfasado |
| 403 al volver | El proveedor autenticó a alguien que no está dado de alta en Apate (paso 4) |
| La pantalla pide usuario y contraseña | `APATE_IDENTITY_PROVIDER` no quedó en `oidc` |

## Configuración de entorno

| Variable | Default | Uso en producción |
|---|---|---|
| `APATE_SECRET_KEY` | aleatoria por proceso | **Obligatoria**; firma la cookie de sesión. |
| `APATE_SECRET_ENCRYPTION_KEY` | clave local en datos | **Obligatoria**; cifra secretos recuperables. |
| `BUDA_CREDENTIAL_ENCRYPTION_KEY` | clave local en datos | **Obligatoria**; cifra y recupera credenciales WinRM de BUDA. |
| `APATE_DATA_DIR` | `.apate_data` | Recomendable; directorio persistente de operaciones, SQLite y clave local si aplica. |
| `APATE_RULES_PATH` | `<APATE_DATA_DIR>/rules.yaml` | Opcional; archivo de reglas alternativo. |
| `APATE_BUDA_DATABASE_URI` | `sqlite:///buda.db` relativo al `instance_path` de Flask | **Recomendable**; las narrativas e identidades simuladas viven en esa base. Sin definirla cae dentro del entorno de Python, fuera de `APATE_DATA_DIR`: una reinstalación se las lleva mientras los `PluginBinding` que las referencian sobreviven. Apuntala al almacenamiento persistente, p. ej. `sqlite:////var/lib/apate/buda.db`. |
| `APATE_TRUSTED_PROXY` | `0` | **Obligatoria detrás del nginx de esta guía**; confía una capa `X-Forwarded-*`. |
| `APATE_PLAYGROUND_PATH` | copia vendorizada | Opcional; stack Playground alternativo. |
| `APATE_ELASTIC_URL` | `http://localhost:9200` | Opcional; Elasticsearch del Playground. |
| `APATE_IDENTITY_PROVIDER` | `local` | Opcional; proveedor de identidad registrado. |
| `APATE_SOURCE_URL` | sin valor | **Obligatoria si exponés la aplicación a terceros.** Dirección donde publicás el código fuente correspondiente de la versión que corrés. Ver "Obligación de código fuente" abajo. |
| `APATE_BUILD_COMMIT` | se lee de `.git` si existe | Opcional; revisión mostrada en `/about`. Una imagen no lleva `.git`, así que ahí conviene inyectarla en el build (`--build-arg APATE_BUILD_COMMIT=$(git rev-parse HEAD)`). |
| `APATE_LOCALE` | sin valor | Opcional; idioma de la instalación (`es`/`en`). Sin definir se negocia con el `Accept-Language` del navegador. Cada persona puede elegir el suyo desde la interfaz, y esa preferencia gana sobre esta variable. |
| `APATE_MOUNT_EXTERNAL_TOOLS` | `1` | Dejá `1` para capacidades de red/host e identidad; `0` evita preparar esos recursos. |
| `APATE_INITIAL_PASSWORD` | sin valor | Solo para `create-user` desatendido; quitála después. |
| `APATE_DEBUG` | `0` | Solo desarrollo con `python -m apate.web`; nunca en producción. |
| `APATE_DEV_HOST` | `127.0.0.1` | Solo desarrollo; un valor no local muestra una advertencia. |
| `APATE_DEV_PORT` | `5000` | Solo desarrollo; util en macOS, donde AirPlay Receiver ocupa el 5000. |

## Obligación de código fuente (AGPLv3, artículo 13)

APATE se distribuye bajo AGPLv3. Su artículo 13 dice que quien **ofrece el programa a través de una
red** tiene que darle a sus usuarios remotos una oportunidad de recibir el *código fuente
correspondiente* de la versión que están usando.

**Esa obligación pasa a ser tuya en cuanto desplegás esta guía**, y no la cubre el autor original: si
modificaste el código, el fuente que tenés que ofrecer es el tuyo, no el del repositorio de referencia.
Instalar sin modificar no te exime — seguís siendo quien lo ofrece por red.

La aplicación trae la mitad de la solución hecha: `/about` muestra versión, revisión y licencia, y el
pie de página enlaza ahí desde todas las pantallas, incluida la de login (la ruta es pública a
propósito: quien está frenado en el login ya está interactuando con el programa). Lo que falta es que
le digas **dónde** está tu fuente:

```bash
APATE_SOURCE_URL=https://ejemplo.tld/apate/fuente-v0.1.0.tar.gz
```

Sin esa variable, `/about` dice explícitamente que la instalación no declaró dónde está su fuente, en
lugar de enlazar a un repositorio que puede no ser el que corre. Es información cierta y te señala lo
que falta; **no** es cumplimiento.

Tres detalles que suelen pasarse por alto:

- **El fuente correspondiente incluye el código vendorizado.** DOLOS-T y BUDA viajan bajo AGPLv3 dentro
  de la misma distribución y se sirven por el mismo proceso: el paquete que publiques tiene que
  cubrirlos. El árbol completo del repositorio ya lo hace; un recorte con solo `src/apate/` no.
- **Tiene que corresponder a la versión que corre**, no a la última. Si desplegás desde un commit
  concreto, publicá ese. `APATE_BUILD_COMMIT` deja la revisión visible en `/about` para que un usuario
  pueda comprobar la correspondencia.
- **`NOTICE`** inventaria los componentes de terceros y sus licencias. Es el primer artefacto que pide
  el área legal de un cliente corporativo, y conviene distribuirlo junto con el fuente.

## Diagnóstico rápido

- `systemctl status apate` y `journalctl -u apate -f` muestran errores de arranque.
- Si las sesiones se cierran tras reiniciar, verificá que `APATE_SECRET_KEY` sea estable.
- Si no se pueden leer secretos existentes, restaurá la misma `APATE_SECRET_ENCRYPTION_KEY` con la que
  se escribieron.
- Si un perfil WinRM figura como no recuperable, restaurá la misma
  `BUDA_CREDENTIAL_ENCRYPTION_KEY` o reemplazá sus credenciales desde el catálogo antes de intentar
  conectarlo.
- Si Socket.IO no conecta, comprobá que nginx reenvíe `Upgrade` y `Connection` y que Gunicorn tenga
  exactamente `--workers 1`.

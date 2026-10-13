"""Cliente HTTP para el servidor self-hosted de Canarytokens (Thinkst,
GPLv3, repo `thinkst/canarytokens` + despliegue `thinkst/canarytokens-docker`)
-- segunda de la tanda de tareas para ampliar el ecosistema de
herramientas orquestables (ver docs/roadmap.md).

**Verificado contra una instancia real, no solo contra documentación.**
La búsqueda inicial llevó a `docs.canary.tools` (`/api/v1/canarytoken/create`)
-- esa es la API del *Canary Console* comercial (el appliance de pago),
un producto y una API completamente distintos. Se confirmó leyendo el
código fuente real de `thinkst/canarytokens` (FastAPI) y, para no
quedarse solo con lectura de código, se levantó una instancia real
(`docker compose up redis frontend` desde `thinkst/canarytokens-docker`,
imagen oficial `thinkst/canarytokens`, sin `switchboard`/`nginx` --
esos piden los puertos 53/25 del host) y se probó `/generate`,
`/history` y `/delete` de verdad, con curl, contra esa instancia.
**No verificado:** la entrega real de un trigger (necesita dominio
público + el canal DNS/HTTP de `switchboard`, no viable en un sandbox
local sin dominio) -- la forma de un hit (`DNSTokenHit`) se leyó del
paquete instalado real, no de un trigger observado.

**La API real vive en un path ofuscado, hardcodeado en el código
fuente** (`frontend/app.py::ROOT_API_ENDPOINT = "/d3aece809..."`, no
viene de configuración) -- cualquier self-host corriendo la imagen
oficial sin recompilarla tiene ese path exacto, pero este cliente
**nunca lo asume fijo**: `base_url` tiene que ser la URL base COMPLETA
que el operador configuró para su propia instancia, incluido lo que
sea que monte antes de `/generate`/`/history`/`/delete`.

**Sin API key global, pero con un secreto por token.** `POST
{base_url}/generate` no exige ninguna clave de administrador -- pero sí
exige, verificado probando (no está en el schema JSON de la request,
es una validación custom que solo salió corriendo la instancia real):
`memo`, y además `webhook_url` o `email` (uno de los dos). Cada token
creado devuelve su propio `auth_token`, un secreto 1:1 con ese token,
necesario para cualquier gestión posterior (`/history`, `/delete`) --
mismo criterio de credencial que la API key de LLM/la contraseña WinRM
de BUDA: nunca se expone en un template, en un payload de evento, ni en
un log (ver `apate.plugins.canarytoken_plugin` para dónde vive).

**Sin webhook, a propósito -- decisión de arquitectura, no un detalle
menor.** APATE nunca completa `webhook_url` al crear un token: siempre
usa `email` para satisfacer la validación de arriba. Dos razones,
confirmadas contra el código real de Canarytokens, no solo por
precaución:
1. Un endpoint HTTP entrante en una app sin autenticación (M13j) es
   superficie de red nueva que APATE no tiene hoy.
2. El servidor de Canarytokens entrega el webhook con `advocate`, una
   librería que **bloquea por defecto direcciones IP privadas/
   reservadas** (protección SSRF, `channel_output_webhook.py`) -- en el
   despliegue típico (APATE y Canarytokens en la misma red privada o
   localhost), el propio servidor de Canarytokens probablemente
   *rechazaría* entregar el webhook. Y peor para una demo: `webhook_url`
   se valida (con un ping real) al momento de crear el token -- si no es
   alcanzable, `/generate` falla ahí mismo, antes de desplegar nada.

Por eso este cliente expone **polling** (`fetch_hits()` contra
`/history`) como única vía de detección, no un receptor de webhooks.

**Hallazgo de seguridad bloqueante, resuelto con una allowlist, no una
denylist.** `GET /history` devuelve el `canarydrop` completo -- que
incluye el propio `auth` del token en texto plano, y (según el tipo de
token) campos como `aws_secret_access_key`/`webdav_password`/
`slack_api_key`/`crowdstrike_client_secret`/`cc_number`. `fetch_hits()`
**nunca lee `data["canarydrop"]` en absoluto** -- ni siquiera para
extraer un campo puntual -- y `CanarytokenHit.from_raw()` solo puede
producir los campos que declara como atributos del dataclass (una
allowlist estructural, no una lista de claves a excluir de un dict
completo: agregar un tipo de token nuevo a Canarytokens con un secreto
nuevo en su Hit no puede filtrarse por acá sin que alguien edite este
archivo a mano para agregarlo)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import requests

from ..i18n import gettext as _
from .exceptions import CanarytokenAPIError

DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True)
class CanarytokenCreated:
    """Lo que `POST /generate` devuelve, reducido a los cuatro campos
    comunes a los tipos de token verificados/leídos en el código real
    (`DNSTokenResponse`/`Log4ShellTokenResponse`/
    `WindowsDirectoryTokenResponse`, todos con esta misma forma).
    Deliberadamente NO incluye contenido específico de otros tipos (ej.
    la clave de AWS falsa de un `aws_keys` token): ese contenido es el
    señuelo en sí, mismo criterio que ya aplica `HoneytokenPlugin` --
    nunca se expone el valor sintético completo fuera de donde se
    planta, solo la referencia para administrarlo. Para tipos que
    necesitan descargar/incrustar un artefacto real (un .docx, una
    clave de AWS), el operador completa ese paso en la interfaz real de
    Canarytokens -- fuera de alcance de esta integración."""

    token: str
    auth_token: str
    token_url: str
    hostname: str


@dataclass(frozen=True)
class CanarytokenHit:
    """Un evento de disparo ('hit'), reducido a un conjunto fijo de
    campos -- ver el docstring del módulo sobre por qué esto es una
    allowlist estructural, no un filtro sobre un dict completo. Ninguno
    de estos campos es sensible: son los mismos que ya trae
    `DNSTokenHit` (verificado contra el paquete real instalado, sección
    del docstring del módulo) y no incluyen nada del `canarydrop`."""

    time_of_hit: float
    source_ip: str
    input_channel: str
    token_type: str
    is_tor_relay: bool
    useragent: str

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "CanarytokenHit":
        return cls(
            time_of_hit=float(raw.get("time_of_hit") or 0.0),
            source_ip=str(raw.get("src_ip") or ""),
            input_channel=str(raw.get("input_channel") or ""),
            token_type=str(raw.get("token_type") or ""),
            is_tor_relay=bool(raw.get("is_tor_relay")),
            useragent=str(raw.get("useragent") or ""),
        )


def _post(url: str, *, json_body: dict[str, Any], timeout: float) -> requests.Response:
    try:
        return requests.post(url, json=json_body, timeout=timeout)
    except requests.RequestException as exc:
        raise CanarytokenAPIError(
            _(
                "No se pudo conectar con el servidor de Canarytokens en '%(url)s': %(error)s",
                url=url,
                error=exc,
            )
        ) from exc


def create_token(
    base_url: str,
    *,
    token_type: str,
    memo: str,
    email: str,
    extra_fields: Optional[dict[str, Any]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> CanarytokenCreated:
    """`POST {base_url}/generate`. `extra_fields` se agrega tal cual al
    cuerpo de la request -- Canarytokens tiene 34 tipos de token, cada
    uno con sus propios campos opcionales (ej. `redirect_url` para un
    token de redirección); en vez de hardcodear cada combinación, este
    cliente deja que el operador declare `extra_fields` en
    `PluginBinding.config` y confía en que la propia validación
    pydantic de Canarytokens rechace lo que no corresponda a
    `token_type` (mismo criterio de "mapeo declarativo, no motor de
    transformación" que ya se usó en el puente de telemetría genérico).
    Nunca incluye `webhook_url` -- ver docstring del módulo."""

    payload: dict[str, Any] = {"token_type": token_type, "memo": memo, "email": email}
    payload.update(extra_fields or {})

    response = _post(f"{base_url.rstrip('/')}/generate", json_body=payload, timeout=timeout)
    try:
        data = response.json()
    except ValueError as exc:
        raise CanarytokenAPIError(
            _("Respuesta no válida del servidor de Canarytokens: %(error)s", error=exc)
        ) from exc

    if response.status_code != 200 or data.get("error"):
        message = data.get("error_message") or f"HTTP {response.status_code}"
        raise CanarytokenAPIError(_("No se pudo crear el canarytoken: %(detail)s", detail=message))

    token = data.get("token")
    auth_token = data.get("auth_token")
    if not token or not auth_token:
        raise CanarytokenAPIError(
            _(
                "La respuesta del servidor de Canarytokens no incluyó 'token'/'auth_token' -- "
                "no se puede administrar este canarytoken sin esos dos valores."
            )
        )
    return CanarytokenCreated(
        token=token,
        auth_token=auth_token,
        token_url=data.get("token_url") or "",
        hostname=data.get("hostname") or "",
    )


def delete_token(base_url: str, *, token: str, auth_token: str, timeout: float = DEFAULT_TIMEOUT) -> None:
    """`POST {base_url}/delete`. Verificado contra una instancia real:
    `{"message": "success"}` con HTTP 200; una consulta posterior a
    `/history` con el mismo par devuelve 403 ("Token not found...")."""

    response = _post(
        f"{base_url.rstrip('/')}/delete",
        json_body={"token": token, "auth": auth_token},
        timeout=timeout,
    )
    if response.status_code != 200:
        raise CanarytokenAPIError(
            _("No se pudo eliminar el canarytoken (HTTP %(status)s).", status=response.status_code)
        )


def fetch_hits(base_url: str, *, token: str, auth_token: str, timeout: float = DEFAULT_TIMEOUT) -> list[CanarytokenHit]:
    """`GET {base_url}/history?token=...&auth=...` -- el mecanismo de
    polling elegido en vez de un webhook entrante (ver docstring del
    módulo). Devuelve solo lo que `CanarytokenHit` declara: nunca toca
    `data["canarydrop"]`, que es donde vive el `auth`/los secretos
    específicos de tipo."""

    try:
        response = requests.get(
            f"{base_url.rstrip('/')}/history",
            params={"token": token, "auth": auth_token},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise CanarytokenAPIError(
            _(
                "No se pudo conectar con el servidor de Canarytokens en '%(url)s': %(error)s",
                url=base_url,
                error=exc,
            )
        ) from exc

    if response.status_code != 200:
        raise CanarytokenAPIError(
            _(
                "No se pudo consultar el historial del canarytoken (HTTP %(status)s).",
                status=response.status_code,
            )
        )
    try:
        data = response.json()
    except ValueError as exc:
        raise CanarytokenAPIError(
            _("Respuesta no válida del servidor de Canarytokens: %(error)s", error=exc)
        ) from exc

    raw_hits = (data.get("history") or {}).get("hits") or []
    return [CanarytokenHit.from_raw(hit) for hit in raw_hits if isinstance(hit, dict)]

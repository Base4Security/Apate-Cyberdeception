"""Adaptador de plugin para Canarytokens (Thinkst, GPLv3, self-hosted
con Docker) -- segunda de la tanda de tareas para ampliar el
ecosistema de herramientas orquestables (ver docs/roadmap.md y
apate.plugins.canarytoken_client para la investigación completa contra
una instancia real de la API).

**Por qué importa:** cubre superficies que APATE hoy no tiene en
absoluto -- `HoneytokenPlugin` (M7) solo administra archivos en disco;
Canarytokens agrega cloud (claves AWS falsas), documentos Word/PDF/
Excel con beacon, tokens DNS, direcciones de correo, sitios clonados,
códigos QR, entre otros (34 tipos reales, ver `token_type`). Encaje
conceptual directo con lo ya construido: un canarytoken **es** una
miga -- entra natural en `PluginBinding.leads_to_plugin_id`
(breadcrumbs, tanda anterior con referencia CounterCraft) apuntando a
la capacidad de red/identidad a la que "lleva".

**Empaquetado: dentro del repo, mismo patrón que
`mock`/`honeytoken`/`dolost`/`buda` -- decisión explícita, no default
sin evaluar.** Se consideró un paquete separado, instalable aparte
(la Fase 5 post-BlackHat ya prueba que `PluginRegistry` descubre por
`entry_points()`, exactamente el mecanismo que usaría un tercero real).
Se descartó: el logro real de esa fase fue que el descubrimiento deja
de importar clases a mano, no que los cuatro plugins de fábrica dejen
de vivir en el repo -- separar este quinto plugin demostraría un hecho
de *empaquetado* (se puede instalar aparte), no un hecho nuevo sobre el
*contrato* (ya demostrado igual de bien por los cuatro existentes, que
usan el mismo `entry_points()` que usaría un paquete externo). El costo
de separar sí es inmediato: reintroduce el `pip install -e ../otro-repo`
que la vendorización de DOLOS-T/BUDA eliminó a propósito para sostener
la instalación de un solo comando (objetivo declarado para BlackHat
Arsenal). El cliente HTTP (`canarytoken_client.py`) se mantiene
autocontenido -- sin acoplarse a nada interno de APATE más allá del
contrato estándar de `DeceptionPlugin` -- para que extraerlo después,
si aparece una razón real, sea copiar dos archivos y agregar un
`pyproject.toml`, no un rediseño.

**Configuración requerida en `PluginBinding.config` antes de
`deploy()`:**

- `base_url` (str, obligatorio): URL base COMPLETA de la instancia
  self-hosted, incluido cualquier path de API que monte (ver docstring
  de `canarytoken_client` sobre por qué el path real no se puede
  asumir fijo -- en el repo público está hardcodeado a un valor
  ofuscado que puede diferir por despliegue).
- `token_type` (str, obligatorio): uno de los ~34 tipos reales de
  Canarytokens (`"dns"`, `"aws_keys"`, `"ms_word"`, `"qr_code"`...).
  Sin validar contra una lista cerrada acá -- la propia API de
  Canarytokens valida esto con su esquema pydantic real; duplicar esa
  lista acá la desactualizaría en cuanto agreguen un tipo nuevo.
- `memo` (str, obligatorio): la nota asociada al token en Canarytokens.
- `email` (str, obligatorio): satisface la validación real de la API
  ("memo + (webhook_url o email)", ver `canarytoken_client`) sin
  registrar nunca un `webhook_url` -- decisión de arquitectura
  documentada ahí, no un descuido.
- `extra_fields` (dict, opcional): campos específicos del `token_type`
  elegido (ej. `redirect_url` para un token de redirección), pasados
  tal cual al cuerpo de `/generate` -- ver `canarytoken_client.
  create_token()`.
- `ttp_id` (str, opcional): a diferencia de `HoneytokenPlugin`, que
  tiene un default razonable (T1552.001, credenciales en archivo,
  aplica a cualquier honeytoken de archivo), Canarytokens cubre 34
  tipos heterogéneos sin que su propia API exponga un mapeo MITRE
  oficial -- inventar un mapeo por tipo sin una fuente verificada
  repetiría exactamente el error que este proyecto evita a propósito
  (ver el resto del código: cada mapeo TTP que existe está marcado
  como verificado o como juicio interpretativo explícito). Sin
  `ttp_id` configurado, un hit se traduce igual a un evento
  `interaction`, simplemente sin promoverse a `ttp_observed`.

**Tras `deploy()` exitoso, la instancia agrega a `self.config` (el
llamador -- la ruta web -- es quien copia esto de vuelta a
`PluginBinding.config` y persiste, mismo patrón que
`HoneytokenPlugin`/`_apate_created_directory`):** `token` (identificador
público del canarytoken, seguro de mostrar), `auth_token` (el secreto
por token -- **nunca al template, nunca en un payload de evento, nunca
en un log**, mismo criterio que la API key de LLM/la contraseña WinRM
de BUDA), `token_url`, `hostname`.

**Dónde vive `auth_token`, decisión explícita.** Se guarda en
`PluginBinding.config["auth_token"]` -- la misma `Operation`, el mismo
archivo JSON en disco que ya guarda el resto de la configuración de
cualquier binding -- **sin cifrado nuevo**. No es un descuido: se
evaluó contra los dos precedentes reales del proyecto, que van en
direcciones distintas según la severidad real del secreto --
credenciales WinRM de BUDA (RCE real contra un servidor real) se
cifran con Fernet en una columna dedicada de su propia base SQLAlchemy;
la API key de LLM (un secreto de servicio, sin alcance de ejecución
remota) se guarda en texto plano en `config_llm.json`, protegida solo
por nunca devolverse al template. `auth_token` se parece mucho más al
segundo caso: administra un señuelo sintético, no otorga acceso a
infraestructura real. Construir un mecanismo de cifrado genérico para
`PluginBinding.config` -- que hoy no existe -- para un solo campo de un
solo plugin sería una pieza nueva de infraestructura no pedida; queda
documentado como candidato real si el proyecto necesita cifrar más de
un campo de este tipo en el futuro.

**`rotate()` no tiene equivalente natural -- documentado como tal, sin
inventar un comportamiento.** Se investigó el código real de
Canarytokens: `/edit`/`/settings` cambian metadata (memo, alertas), no
el valor/identidad del token en sí; no existe ningún endpoint para
"regenerar el mismo token" (a diferencia de BUDA, que sí tiene
stop/start real para aproximar un rotate). Renovar de verdad implica
retirar y desplegar uno nuevo -- una decisión del operador (arriesga
invalidar un artefacto ya entregado/plantado), no algo que `rotate()`
deba hacer en su lugar. `rotate()` publica un evento explicando esto y
no cambia el estado (sigue `DEPLOYED`), consistente con la tabla de
`docs/plugin-event-contract.md`.

**Entrega de eventos: polling contra `/history`, nunca un webhook
entrante -- ver el argumento completo (con el hallazgo real de
`advocate` bloqueando IPs privadas) en `canarytoken_client`.**
`check_hits()` (fuera del contrato de `DeceptionPlugin`, igual que
`HoneytokenPlugin.check_access()`/`BudaPlugin.check_activity()`)
implementa el polling. **Deduplicación por timestamp, persistida en
`PluginBinding.config["last_hit_time"]`** (mismo patrón que
`ExternalTelemetrySource.last_fetch_at`, tarea anterior de esta misma
tanda) -- `/history` siempre devuelve el historial completo, no solo lo
nuevo desde la última consulta, así que sin este cursor cada llamada
volvería a publicar (y persistir en telemetría) los mismos hits ya
vistos."""

from __future__ import annotations

from typing import Any, Optional

from ..i18n import gettext as _
from ..i18n import lazy_gettext
from .base import DeceptionPlugin, EventType, PluginEvent, PluginLifecycleState
from .canarytoken_client import create_token, delete_token, fetch_hits
from .exceptions import PluginConfigError
from .registry import PluginDescription


class CanarytokenPlugin(DeceptionPlugin):
    """Adapta un servidor Canarytokens self-hosted a la interfaz
    `DeceptionPlugin` de M2. Ver el docstring del módulo para el diseño
    completo (configuración requerida, dónde vive `auth_token`, por qué
    `rotate()` es un no-op documentado, por qué la detección es por
    polling)."""

    plugin_description = PluginDescription(
        kind="canarytoken",
        display_name=lazy_gettext("Canarytokens (Thinkst)"),
        description=lazy_gettext(
            "Migas multi-superficie (cloud, documentos, DNS, QR, email...) contra un servidor "
            "Canarytokens self-hosted -- detección por polling, sin webhook entrante."
        ),
        surface="Multi-superficie (cloud/documentos/DNS/identidad)",
    )

    def deploy(self) -> None:
        self._require_state(PluginLifecycleState.CREATED, action="deploy")
        base_url = self._base_url()
        token_type, memo, email = self._required_creation_fields()

        created = create_token(
            base_url,
            token_type=token_type,
            memo=memo,
            email=email,
            extra_fields=self.config.get("extra_fields"),
        )
        self.config["token"] = created.token
        self.config["auth_token"] = created.auth_token
        self.config["token_url"] = created.token_url
        self.config["hostname"] = created.hostname

        self._publish(
            EventType.INTERACTION,
            {"kind": "deploy", "token_type": token_type, "detail": f"Canarytoken '{token_type}' creado."},
            resource_id=f"canarytoken:{created.token}",
        )
        self.state = PluginLifecycleState.DEPLOYED

    def rotate(self) -> None:
        """Sin equivalente natural en Canarytokens -- ver docstring del
        módulo. No cambia self.state ni el token en sí: solo deja
        constancia explícita en un evento, para que quede registrado
        que se intentó rotar y por qué no hay nada que rotar de
        verdad."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="rotate")
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "rotate",
                "detail": (
                    "Canarytokens no tiene forma de regenerar el valor de un token existente "
                    "manteniendo su identidad -- no hay un 'rotate' real acá. Para renovar esta miga, "
                    "retirala y desplegá una nueva a propósito (retire() + deploy())."
                ),
            },
        )
        # rotate() no cambia self.state: sigue DEPLOYED (nada cambió de verdad).

    def retire(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="retire")
        token, auth_token = self._deployed_identity()

        delete_token(self._base_url(), token=token, auth_token=auth_token)
        self._publish(
            EventType.INTERACTION,
            {"kind": "retire", "detail": "Canarytoken eliminado."},
            resource_id=f"canarytoken:{token}",
        )
        for key in ("token", "auth_token", "token_url", "hostname", "last_hit_time"):
            self.config.pop(key, None)
        self.state = PluginLifecycleState.RETIRED

    def check_hits(self, *, since: Optional[float] = None) -> list[PluginEvent]:
        """Consulta `/history` (polling, ver docstring del módulo) y
        publica un evento por cada hit con `time_of_hit > since`. No
        forma parte del contrato de `DeceptionPlugin` -- pensado para
        llamarse desde una acción manual del operador (o un loop
        externo), igual que `HoneytokenPlugin.check_access()`/
        `BudaPlugin.check_activity()`. Devuelve también el mayor
        `time_of_hit` visto (o `since` si no hubo hits nuevos) para que
        el llamador actualice el cursor persistido -- ver
        `apate.web.blueprints.operations.canarytoken_check_hits()`."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="check_hits")
        token, auth_token = self._deployed_identity()

        hits = fetch_hits(self._base_url(), token=token, auth_token=auth_token)
        cursor = since or 0.0
        events: list[PluginEvent] = []
        for hit in sorted(hits, key=lambda h: h.time_of_hit):
            if since is not None and hit.time_of_hit <= since:
                continue
            payload: dict[str, Any] = {
                "kind": "trigger",
                "detail": f"Canarytoken disparado via '{hit.input_channel or 'canal desconocido'}'.",
                "time_of_hit": hit.time_of_hit,
                "token_type": hit.token_type,
                "is_tor_relay": hit.is_tor_relay,
            }
            if hit.source_ip:
                payload["source_ip"] = hit.source_ip
            if hit.useragent:
                payload["useragent"] = hit.useragent
            ttp_id = self.config.get("ttp_id")
            if ttp_id:
                payload["ttp_id"] = ttp_id
            event_type = EventType.TTP_OBSERVED if ttp_id else EventType.INTERACTION
            events.append(self._publish(event_type, payload, resource_id=f"canarytoken:{token}"))
            cursor = max(cursor, hit.time_of_hit)
        self.config["last_hit_time"] = cursor
        return events

    def restore_deployed_state(self) -> None:
        """Rehidrata una instancia efímera (la ruta web construye una
        instancia nueva por request) sin volver a llamar a la API --
        misma simplificación deliberada que ya documenta
        `DolosTPlugin` (M11 fase 1): sin un bit de estado propio
        persistido, se reconcilia contra la presencia de `token`/
        `auth_token` ya guardados en config, no contra una consulta en
        vivo a Canarytokens en cada request."""

        if not self.config.get("token") or not self.config.get("auth_token"):
            raise PluginConfigError(
                _(
                    "No se puede reconciliar el estado: falta 'token'/'auth_token' en la "
                    "configuración (¿este canarytoken nunca se desplegó?)."
                )
            )
        self.state = PluginLifecycleState.DEPLOYED

    # -- Helpers internos -----------------------------------------------

    def _base_url(self) -> str:
        base_url = self.config.get("base_url")
        if not base_url:
            raise PluginConfigError(
                _(
                    "CanarytokenPlugin requiere 'base_url' en la configuración "
                    "(PluginBinding.config): la URL base completa de la instancia self-hosted, "
                    "incluido su path de API real -- no asumas un path fijo (ver docstring de "
                    "apate.plugins.canarytoken_client)."
                )
            )
        return base_url

    def _required_creation_fields(self) -> tuple[str, str, str]:
        token_type = self.config.get("token_type")
        memo = self.config.get("memo")
        email = self.config.get("email")
        missing = [name for name, value in (("token_type", token_type), ("memo", memo), ("email", email)) if not value]
        if missing:
            raise PluginConfigError(
                _(
                    "CanarytokenPlugin requiere %(fields)s en la configuración "
                    "(PluginBinding.config) antes de poder crear el token. La API real de "
                    "Canarytokens exige 'memo' y, además, 'email' o 'webhook_url' -- APATE "
                    "siempre usa 'email' (nunca 'webhook_url', ver docstring del módulo).",
                    fields=", ".join(f"'{m}'" for m in missing),
                )
            )
        return token_type, memo, email

    def _deployed_identity(self) -> tuple[str, str]:
        token = self.config.get("token")
        auth_token = self.config.get("auth_token")
        if not token or not auth_token:
            raise PluginConfigError(
                _(
                    "Este binding no tiene un canarytoken desplegado todavía "
                    "(falta 'token'/'auth_token')."
                )
            )
        return token, auth_token

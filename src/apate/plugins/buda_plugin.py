"""Adaptador de plugin para BUDA (M8c) - documento de diseno, seccion
4.5; contrato exacto en docs/plugin-event-contract.md.

Llama directo a las funciones Python reales de BUDA (paquete `BUDA`,
dependencia editable local -- ver pyproject.toml): `start_narrative()`/
`stop_narrative()` de `BUDA.utils.narrative_worker` para el ciclo de
vida (motor WinRM/LLM reutilizado tal cual, no tocado), y
`BUDA.utils.events.drain_events()` para leer actividad estructurada
(M8b). Sin ninguna capa HTTP intermedia.

Requiere contexto de aplicacion Flask activo: `start_narrative()`/
`stop_narrative()` (BUDA.utils.narrative_worker) usan internamente
`flask.current_app` -- verificado en el codigo real de BUDA, no
asumido. Esto significa que `deploy()`/`rotate()`/`retire()` de este
adaptador solo se pueden llamar dentro de un `with app.app_context():`
(o durante el manejo de un request real) sobre la app de APATE que
montó los blueprints de BUDA (ver apate.web.external.mount_buda) --
sin eso, BUDA levanta `RuntimeError: Working outside of application
context`, no un error de este adaptador.
"""

from __future__ import annotations

from typing import Any

from BUDA.app import db as _buda_db
from BUDA.models import Narrative as BudaNarrative
from BUDA.utils.events import drain_events
from BUDA.utils.narrative_worker import start_narrative, stop_narrative

from ..i18n import gettext as _
from ..i18n import lazy_gettext
from .base import DeceptionPlugin, EventType, PluginEvent, PluginLifecycleState
from .exceptions import PluginConfigError
from .registry import PluginDescription


class BudaPlugin(DeceptionPlugin):
    """Adapta BUDA (superficie identidad/comportamiento) a la interfaz
    DeceptionPlugin de M2. `config` requiere `narrative_id`: el id de
    la `Narrative` de BUDA (ya creada vía su propia UI/API, montada en
    `/buda`) que este plugin va a desplegar/rotar/retirar."""

    plugin_description = PluginDescription(
        kind="buda",
        display_name=lazy_gettext("Comportamiento de usuario simulado"),
        description=lazy_gettext(
            "Simula comportamiento de usuarios reales sobre servidores WinRM reales -- "
            "narrativas con perfiles de usuario y actividades asistidas por LLM."
        ),
        surface="Identidad / comportamiento",
    )

    def deploy(self) -> None:
        self._require_state(PluginLifecycleState.CREATED, action="deploy")
        narrative_id = self._narrative_id()

        result = start_narrative(narrative_id)
        self._publish(
            EventType.INTERACTION,
            {"kind": "deploy", "detail": result.get("message", "Narrativa de BUDA iniciada."), "narrative_id": narrative_id},
            resource_id=f"narrative:{narrative_id}",
        )
        self.state = PluginLifecycleState.DEPLOYED

    def restore_deployed_state(self) -> None:
        """Rehidrata el estado desde la fuente persistida de BUDA."""

        narrative = _buda_db.session.get(BudaNarrative, self._narrative_id())
        if narrative is not None and narrative.is_running:
            self.state = PluginLifecycleState.DEPLOYED

    def rotate(self) -> None:
        """BUDA tampoco tiene un concepto nativo de "rotar" una
        narrativa en curso -- solo start/stop
        (`routes/narratives.py`). Se aproxima deteniendola y
        volviendola a iniciar (misma narrativa, nueva ejecucion del
        hilo en background), documentado como aproximacion igual que
        en DolosTPlugin.rotate()."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="rotate")
        narrative_id = self._narrative_id()

        stop_narrative(narrative_id)
        result = start_narrative(narrative_id)
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "rotate",
                "detail": result.get("message", "Narrativa de BUDA reiniciada (sin rotacion nativa en BUDA)."),
                "narrative_id": narrative_id,
            },
            resource_id=f"narrative:{narrative_id}",
        )
        # rotate() no cambia el estado del ciclo de vida: sigue DEPLOYED.

    def retire(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="retire")
        narrative_id = self._narrative_id()

        result = stop_narrative(narrative_id)
        self._publish(
            EventType.INTERACTION,
            {"kind": "retire", "detail": result.get("message", "Narrativa de BUDA detenida."), "narrative_id": narrative_id},
            resource_id=f"narrative:{narrative_id}",
        )
        self.state = PluginLifecycleState.RETIRED

    def check_activity(self) -> list[PluginEvent]:
        """Traduce la actividad estructurada de BUDA (M8b,
        `drain_events()`) a `PluginEvent` sobre el bus. No forma parte
        del contrato de `DeceptionPlugin` -- especifico de este
        adaptador. A diferencia de `DolosTPlugin.check_activity()`, no
        hace falta deduplicar acá: `drain_events()` es una cola real
        que se vacía en cada llamada (M8b), no un snapshot que se
        vuelve a leer entero."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="check_activity")

        published: list[PluginEvent] = []
        for raw_event in drain_events(narrative_id=self._narrative_id()):
            event_type = EventType.TTP_OBSERVED if raw_event.get("ttp_id") else EventType.INTERACTION
            payload = {key: value for key, value in raw_event.items() if value is not None}
            profile_id = raw_event.get("user_profile_id") or raw_event.get("profile_id")
            resource_id = f"profile:{profile_id}" if profile_id is not None else f"narrative:{self._narrative_id()}"
            published.append(self._publish(event_type, payload, resource_id=resource_id))
        return published

    def _narrative_id(self) -> Any:
        narrative_id = self.config.get("narrative_id")
        if narrative_id is None:
            raise PluginConfigError(
                _(
                    "BudaPlugin requiere 'narrative_id' en la configuracion "
                    "(PluginBinding.config): el id de la Narrative de BUDA a operar."
                )
            )
        return narrative_id

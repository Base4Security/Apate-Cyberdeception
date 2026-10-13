"""Catálogo de plantillas de operación (referencia declarada: CounterCraft
Campaign Builder, cuyo catálogo de plantillas autogenera una campaña
esqueleto que el analista completa y activa).

**Criterio central, no negociable (pedido explícito de la tarea): una
plantilla precarga un formulario, nunca crea una `Operation` sola.**
Mismo mecanismo y mismo criterio que "Reoperar" (M12g,
`apate.web.blueprints.operations._render_new_operation_form(prefill=...)`)
-- este módulo solo calcula el `prefill`, la creación real sigue siendo
el mismo POST atómico de siempre a `create_operation()`.

**Fuente única, no duplicada.** Antes de escribir este módulo se
revisó `examples/seed_demo.py`: sus 3 operaciones de ejemplo (APT28,
FIN7, Lazarus Group) ya eran plantillas realistas y bien construidas,
solo que invisibles desde la UI (viven en un script de desarrollo). En
vez de mantener una segunda lista paralela que se desincronice con el
tiempo (el mismo problema que M12h resolvió con el registro de
plugins), `apate/data/operation_templates.json` es ahora la ÚNICA
fuente -- `examples/seed_demo.py` la consume completa (operación +
escenario + plugins + transiciones, para crear datos de demo reales
por POST) y este módulo consume solo la parte relevante para el wizard
(`operation`, pasos 1/2/5), más una vista de solo lectura de lo que
sigue (`describe_next_steps()`) para los pasos 3/4.

**Por qué el `dict` "operation" de cada plantilla es directamente el
`prefill` del wizard, sin transformación:** sus claves ya son
exactamente los `name="..."` de `operations/form.html` (`adversary_name`,
`expected_ttps`, `objectives`, `roles`, etc.) -- las mismas que
`examples/seed_demo.py` ya usaba para el `POST` real a `/operations/new`.
Un mismo dict sirve para las dos cosas: se postea tal cual (seed) o se
usa tal cual como `prefill=` (catálogo web) -- no hay dos formatos que
mantener sincronizados a mano.

**Pasos 3/4 (escenarios y capacidades), límite conocido, documentado a
propósito en vez de resuelto con más código:** una plantilla completa
idealmente los incluiría, pero crearlos junto con la operación exige
un `POST` no atómico (operación, después escenario, después cada
plugin) -- exactamente lo que M12e ya decidió evitar para no dejar
operaciones a medio armar si el operador abandona el flujo a mitad de
camino. La solución chica y honesta: `describe_next_steps()` expone el
escenario/capacidades de la plantilla como texto informativo (qué
sigue típicamente después de crear la operación), nunca aplicado
automáticamente -- el operador los agrega desde el detalle de la
operación, como ya hace hoy con cualquier operación creada en blanco.

**Relación con el selector de grupo APT (M12j), resuelta explícita:**
ese selector ya precarga TTPs/motivación/notas desde un grupo real de
`apate.attack` -- un subconjunto de lo que una plantilla precarga acá.
No compiten: una plantilla es la capa MÁS ANCHA (perfil de adversario
completo + RoE/entorno + objetivos estratégicos/roles + narrativa), el
selector de grupo APT sigue disponible dentro del wizard ya precargado
por si el operador quiere cambiar el adversario sin perder el resto de
lo que la plantilla cargó -- mismo campo, mismo JS de M12j, sin
cambios: como ya reemplaza checkboxes sin sumarlos y solo sugiere
motivación/notas si están vacíos, elegir un grupo después de una
plantilla simplemente reemplaza las TTPs, sin duplicar lógica nueva.

**Por qué no hay una plantilla por objetivo estratégico aparte:** se
evaluó y se descartó -- un objetivo sin un adversario/narrativa
concreto detrás es un esqueleto genérico de bajo valor comparado con
un escenario nombrado real, y multiplicaría el catálogo sin agregar
información nueva (cada plantilla ya declara sus `objectives` reales).
En su lugar, cada plantilla muestra sus objetivos como tags en la
tarjeta del catálogo -- con solo 3 plantillas, un filtro interactivo
por objetivo no se justifica todavía (revisitar si el catálogo crece)."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Optional

from flask import has_request_context
from flask_babel import get_locale

from apate.i18n import DEFAULT_LOCALE, SUPPORTED_LOCALES

_DATA_DIRECTORY = Path(__file__).resolve().parent.parent / "data"
_DATA_PATHS = {
    "es": _DATA_DIRECTORY / "operation_templates.json",
    "en": _DATA_DIRECTORY / "operation_templates.en.json",
}


def _load(locale: str) -> list[dict[str, Any]]:
    data = json.loads(_DATA_PATHS[locale].read_text(encoding="utf-8"))
    return list(data["templates"])


# Cargado una sola vez al importar el modulo, mismo patron que
# `apate.attack.catalog`/`apate.engage.catalog`.
_TEMPLATES_BY_LOCALE = {locale: _load(locale) for locale in SUPPORTED_LOCALES}


def _resolve_locale(locale: str | None) -> str:
    """El locale pedido o el activo durante una request web.

    El catálogo también se usa desde el seed, fuera de una request; en ese
    caso el español conserva el comportamiento histórico. Un llamador que
    necesita una variante concreta (como el seed en inglés) la pasa de forma
    explícita para no depender de una preferencia de sesión ajena.
    """

    if locale is None:
        locale = str(get_locale()) if has_request_context() else DEFAULT_LOCALE
    if locale not in SUPPORTED_LOCALES:
        raise ValueError(f"Locale de plantillas no soportado: {locale!r}")
    return locale


def list_templates(locale: str | None = None) -> list[dict[str, Any]]:
    """Las plantillas del catálogo, en el orden del dataset. Copia de
    la lista cacheada -- quien la reciba no puede mutar el catálogo
    compartido (mismo criterio que `apate.attack.list_groups()`)."""

    return list(_TEMPLATES_BY_LOCALE[_resolve_locale(locale)])


def get_template(template_id: str, locale: str | None = None) -> Optional[dict[str, Any]]:
    """La plantilla con ese `id`, o `None` si no existe -- nunca lanza,
    mismo criterio que `apate.attack.get_group()`."""

    for template in _TEMPLATES_BY_LOCALE[_resolve_locale(locale)]:
        if template["id"] == template_id:
            return template
    return None


def resolve_operation_fields(template: dict[str, Any]) -> dict[str, Any]:
    """El sub-dict `operation` de la plantilla, con `end_date_days`
    resuelto a una fecha ISO absoluta (`end_date`) a partir de hoy --
    ver docstring del módulo sobre por qué el dataset no guarda una
    fecha absoluta hardcodeada. Mismo dict, sin transformación
    adicional, sirve como `prefill=` del wizard (este módulo) y como
    cuerpo del `POST /operations/new` real (`examples/seed_demo.py`)."""

    fields = dict(template["operation"])
    days = fields.pop("end_date_days", None)
    if days is not None:
        fields["end_date"] = (date.today() + timedelta(days=days)).isoformat()
    return fields


def describe_next_steps(template: dict[str, Any]) -> dict[str, Any]:
    """Vista de solo lectura del escenario/capacidades que la plantilla
    sugiere para los pasos 3/4 -- informativa nada más, nunca aplicada
    automáticamente (ver docstring del módulo). `plugin_kinds` es una
    lista simple de los `kind` declarados (ej. `["dolost", "buda"]`),
    suficiente para el texto de la tarjeta sin exponer la configuración
    técnica completa (hostnames/IPs/etc., solo relevante para
    `examples/seed_demo.py`)."""

    scenario = template.get("scenario") or {}
    plugins = template.get("plugins") or []
    return {
        "scenario_description": scenario.get("description", ""),
        "scenario_related_ttps": scenario.get("related_ttps", ""),
        "plugin_kinds": [plugin.get("kind", "") for plugin in plugins],
    }

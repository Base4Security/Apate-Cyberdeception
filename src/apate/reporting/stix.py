"""Exportación del informe post-operación (M6) a un bundle STIX 2.1 -
cierre verificable del paso 6/7 de la metodología CTI-a-ciberengaño
("retroalimentación CTI", hasta ahora cubierto solo con
`to_json()`/`to_markdown()`/`to_pdf()`, formatos propios que ninguna
otra herramienta sabe ingerir).

**Formato elegido: STIX 2.1, no MISP.** Se evaluaron los dos, con el
dato real de APATE en la mano, no por "STIX suena mejor": los IoCs
normalizados (`apate.telemetry.IoC`, tipo+valor: ip/hash/credential/
domain/url) y las TTPs observadas mapean directo a objetos STIX reales
(`indicator`/`attack-pattern`) con soporte nativo de referencia externa
a MITRE ATT&CK (`external_references`, `kill_chain_phases`) -- esa
referencia es justo el "mapeo completo a ATT&CK" que la tarea pide, y
MISP no tiene un objeto de primera clase equivalente para eso (su
taxonomía de galaxy/cluster de ATT&CK es un mecanismo aparte, menos
directo). No se construyó también un export a MISP: una vez modelado
STIX no "sale gratis" un segundo formato -- el MISP Objects/Attributes
JSON tiene su propio esquema, no es un subconjunto de STIX, hubiera
sido un tercer mapeo completo a mantener sin que la tarea lo pidiera
como obligatorio.

**Sin la librería oficial `stix2` de OASIS como dependencia de
runtime.** STIX 2.1 es JSON con una forma conocida y acotada -- un
bundle con unos pocos `attack-pattern`/`indicator`/`note`/`report` no
justifica sumar una dependencia nueva (mismo criterio real que ya
usó el proyecto para `fpdf2`/`pypdf`: dependencia nueva solo si la
tarea puntual la necesita de verdad, no evaluado en abstracto). Se
serializa a mano con `json`/`uuid`/`datetime` de la librería estándar,
igual que `to_json()`. **`stix2` sí se usa, pero como dependencia de
TEST, no de runtime** (`pyproject.toml`, extra `dev`) -- exclusivamente
para validar en la suite que el bundle generado efectivamente parsea
con la implementación de referencia de OASIS (`stix2.parse()`, que
valida tipos/propiedades requeridas/formato de timestamps de verdad),
sin que `apate.reporting`/`apate` en general dependan de eso para
funcionar. Ver `tests/test_reporting_stix.py`.

**Qué se mapea, con honestidad -- y qué NO, a propósito:**
- Cada TTP en `expected_ttps ∪ observed_ttps` -> un `attack-pattern`,
  con `external_references` a MITRE ATT&CK (URL derivada del ID, sin
  necesitar el catálogo) y, SOLO si el ID resuelve contra el catálogo
  curado de `apate.attack` (41 técnicas padre, M12j), `name`/
  `kill_chain_phases` reales. Una sub-técnica o un TTP fuera del
  catálogo (`AdversaryProfile.expected_ttps` es `list[str]` libre desde
  siempre) no inventa un nombre ni una táctica -- el `attack-pattern`
  igual se genera (con el ID como `name`), la referencia externa sigue
  siendo correcta, pero sin datos curados que no se pueden verificar.
- Cada `IoC` -> un `indicator` con un patrón STIX real (`ipv4-addr`/
  `ipv6-addr`, `domain-name`, `url`, `file:hashes.'<algoritmo>'`,
  `user-account:credential`) -- no un objeto observable aparte:
  `indicator.pattern` alcanza y es exactamente como se representa un
  indicador de un solo observable en la práctica. El algoritmo de hash
  no se registra en `apate.telemetry.IoC` (solo tipo+valor) -- se
  infiere por longitud hexadecimal (32/40/64/128 -> MD5/SHA-1/SHA-256/
  SHA-512), documentado como inferencia, no un dato certero; sin
  coincidencia, `Custom-Hash` (vocabulario abierto de STIX, no rompe
  el esquema).
- El efecto Ver-Pensar-Hacer, la métrica de éxito planificada y el
  resultado medido (`PluginEffectSummary`, sin equivalente STIX
  limpio: no es una TTP, no es un indicador, no es un observable) ->
  un `note` por cada plugin con contenido real, usando el mecanismo de
  extensión que el propio estándar prevé para esto (texto libre
  adjunto a otros objetos vía `object_refs`) en vez de forzarlo dentro
  de un tipo que no lo representa o inventar una propiedad custom
  (`x_...`) que ninguna otra herramienta va a saber leer igual.
- Las actividades de MITRE Engage (`DeceptionEffect.engage_activity_ids`)
  quedan **fuera del bundle, a propósito** -- son la explicación
  metodológica del PLAN de engaño, no CTI que otra herramienta deba
  ingerir. `apate.reporting` ya expone esa información completa via
  `apate.engage`/el detalle de la operación; forzarla a un `note`
  del informe hubiera sido ruido sin valor real para quien consume el
  bundle (un SIEM/SOAR/EDR, no un lector de la operación en APATE).

**Clasificación TLP (segunda de la tanda de mejoras de UI/UX con
referencia CounterCraft, ver docs/roadmap.md).** `operation_report_to_
stix_bundle()` acepta `tlp_classifications` opcional
(`apate.telemetry.classifications.TlpClassification`, overlay manual
del operador -- ver ese módulo para el criterio completo). Los cuatro
niveles clásicos tienen un objeto `marking-definition` de STIX 2.1 con
**ID fijo y estándar** (los mismos que expone la librería `stix2` de
OASIS como `stix2.TLP_RED`/`TLP_AMBER`/`TLP_GREEN`/`TLP_WHITE`,
confirmados contra esa librería antes de hardcodearlos) -- no se genera
un UUID nuevo por bundle, son objetos "bien conocidos" que cualquier
consumidor STIX real ya reconoce por ese id exacto. Solo los `IoC`
(`indicator`) pueden llevar `object_marking_refs` en esta iteración: un
`IoC` no tiene id propio (se deduplica por tipo+valor,
`apate.telemetry.classifications.ioc_subject_key()`), así que la
clasificación guardada con `subject_type="ioc"` resuelve directo contra
el `indicator` correspondiente. **Limitación conocida, documentada acá
a propósito:** el bundle no tiene ningún objeto STIX por evento
individual (`TelemetryRecord`) -- solo agregados
(`attack-pattern`/`indicator`/`note`/`report`) -- así que una
clasificación TLP puesta sobre un evento (`subject_type="event"`) sin
ningún IoC coincidente no tiene representación en el bundle todavía; no
se fuerza creando un objeto STIX nuevo solo para colgarle el marking.
Cada `marking-definition` usado se agrega una única vez a `objects`,
sin importar cuántos indicators lo referencien. **Un `marking-
definition` nunca entra en `report.object_refs`** -- STIX 2.1 exige que
esa lista solo contenga SCO/SDO/SRO (confirmado con
`stix2.parse(allow_custom=False)` rechazándolo de verdad durante el
desarrollo de este mapeo, no asumido de la lectura de la especificación);
un marking se referencia únicamente vía `object_marking_refs` del
objeto que marca."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from ..attack import Technique, list_techniques
from ..i18n import gettext as _
from ..telemetry.classifications import TlpClassification, TlpLevel, ioc_subject_key

if TYPE_CHECKING:
    from .models import OperationReport

_STIX_SPEC_VERSION = "2.1"
_ATTACK_TECHNIQUE_URL = "https://attack.mitre.org/techniques/"

# IDs fijos de los cuatro `marking-definition` clasicos de TLP --
# confirmados contra la libreria de referencia de OASIS
# (`stix2.TLP_RED.id` etc., pyproject.toml extra dev) antes de
# hardcodearlos. Nunca generar un UUID nuevo para estos: son objetos
# "bien conocidos" de la especificacion, cualquier consumidor STIX real
# ya los reconoce por ese id exacto.
_TLP_MARKING_IDS: dict[TlpLevel, str] = {
    TlpLevel.RED: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    TlpLevel.AMBER: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    TlpLevel.GREEN: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    TlpLevel.WHITE: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
}
# Timestamp de creacion real y fijo de estos cuatro objetos segun la
# especificacion OASIS (el mismo que serializa `stix2.TLP_RED` etc.) --
# no `report.generated_at`: no los "crea" APATE, son objetos estaticos
# publicados por el estandar.
_TLP_MARKING_CREATED = "2017-01-20T00:00:00.000Z"

# IoC.type (apate.telemetry) -> como construir un patron STIX valido
# para ese tipo. "hash"/"credential" necesitan logica propia (algoritmo
# inferido / SCO sin "value" simple), el resto es directo.
_SIMPLE_IOC_PATTERNS = {
    "domain": "domain-name:value",
    "url": "url:value",
}


def _stix_timestamp(value: datetime) -> str:
    """STIX 2.1 exige timestamps en UTC terminados en "Z" -- `datetime.
    isoformat()` de Python produce "+00:00", no valido para el esquema."""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _new_id(object_type: str) -> str:
    return f"{object_type}--{uuid.uuid4()}"


def _escape_pattern_string(value: str) -> str:
    """Escapa un valor para usarlo como string literal dentro de un
    patron STIX (`[tipo:propiedad = '...']`) -- backslash y comilla
    simple son los dos caracteres que rompen la sintaxis del Patterning
    Language si van sin escapar."""

    return value.replace("\\", "\\\\").replace("'", "\\'")


def _hash_algorithm(value: str) -> str:
    """Infiere el algoritmo por longitud hexadecimal -- `IoC` (apate.
    telemetry) no registra que algoritmo se uso, solo tipo="hash" +
    valor. `Custom-Hash` (vocabulario abierto de hash-algorithm-ov) si
    no coincide con ninguna longitud conocida, en vez de inventar un
    algoritmo que no se puede verificar."""

    if not value or any(c not in "0123456789abcdefABCDEF" for c in value):
        return "Custom-Hash"
    return {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(len(value), "Custom-Hash")


def _ioc_pattern(ioc_type: str, value: str) -> Optional[str]:
    escaped = _escape_pattern_string(value)
    if ioc_type in _SIMPLE_IOC_PATTERNS:
        return f"[{_SIMPLE_IOC_PATTERNS[ioc_type]} = '{escaped}']"
    if ioc_type == "ip":
        sco_type = "ipv6-addr" if ":" in value else "ipv4-addr"
        return f"[{sco_type}:value = '{escaped}']"
    if ioc_type == "hash":
        return f"[file:hashes.'{_hash_algorithm(value)}' = '{escaped}']"
    if ioc_type == "credential":
        return f"[user-account:credential = '{escaped}']"
    return None


def _attack_pattern_url(ttp_id: str) -> str:
    """URL real de MITRE ATT&CK para `ttp_id`, derivable del ID solo
    (sin el catalogo curado) -- una sub-tecnica ("T1078.004") usa
    `/T1078/004/`, no `/T1078.004/`."""

    if "." in ttp_id:
        parent_id, sub_id = ttp_id.split(".", 1)
        return f"{_ATTACK_TECHNIQUE_URL}{parent_id}/{sub_id}/"
    return f"{_ATTACK_TECHNIQUE_URL}{ttp_id}/"


def _attack_pattern_object(ttp_id: str, *, catalog: dict[str, Technique], created_by_ref: str, timestamp: str) -> dict[str, Any]:
    technique = catalog.get(ttp_id)
    obj: dict[str, Any] = {
        "type": "attack-pattern",
        "spec_version": _STIX_SPEC_VERSION,
        "id": _new_id("attack-pattern"),
        "created": timestamp,
        "modified": timestamp,
        "created_by_ref": created_by_ref,
        "name": technique.name if technique else ttp_id,
        "external_references": [
            {"source_name": "mitre-attack", "external_id": ttp_id, "url": _attack_pattern_url(ttp_id)}
        ],
    }
    if technique is not None:
        obj["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": technique.tactic}]
    return obj


def _tlp_marking_object(level: TlpLevel) -> dict[str, Any]:
    """Objeto `marking-definition` con ID fijo -- ver el bloque de
    constantes `_TLP_MARKING_IDS`/`_TLP_MARKING_CREATED` para el
    porqué de no generar un UUID/timestamp nuevos acá."""

    return {
        "type": "marking-definition",
        "spec_version": _STIX_SPEC_VERSION,
        "id": _TLP_MARKING_IDS[level],
        "created": _TLP_MARKING_CREATED,
        "definition_type": "tlp",
        "name": f"TLP:{level.value.upper()}",
        "definition": {"tlp": level.value},
    }


def _indicator_object(
    ioc_type: str, value: str, *, created_by_ref: str, timestamp: str, marking_ref: Optional[str] = None
) -> Optional[dict[str, Any]]:
    pattern = _ioc_pattern(ioc_type, value)
    if pattern is None:
        return None
    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": _STIX_SPEC_VERSION,
        "id": _new_id("indicator"),
        "created": timestamp,
        "modified": timestamp,
        "created_by_ref": created_by_ref,
        "name": _("IoC observado durante la operación (%(ioc_type)s)", ioc_type=ioc_type),
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": timestamp,
        "indicator_types": ["malicious-activity"],
    }
    if marking_ref is not None:
        indicator["object_marking_refs"] = [marking_ref]
    return indicator


def _note_object(content: str, *, object_refs: list[str], created_by_ref: str, timestamp: str) -> dict[str, Any]:
    return {
        "type": "note",
        "spec_version": _STIX_SPEC_VERSION,
        "id": _new_id("note"),
        "created": timestamp,
        "modified": timestamp,
        "created_by_ref": created_by_ref,
        "content": content,
        "object_refs": object_refs,
    }


def _plugin_effect_note_content(effect: dict[str, Any]) -> Optional[str]:
    """`None` si no hay nada real que anotar (los tres campos
    planificados vacios y sin medicion) -- no se genera una nota vacia
    de relleno."""

    has_plan = bool(effect["expected_adversary_belief"] or effect["expected_adversary_action"] or effect["success_metric"])
    if not has_plan and not effect["is_measured"]:
        return None

    sin_registrar = _("(sin registrar)")
    lines = [
        _(
            "Efecto de engaño planificado para el plugin '%(plugin_id)s' (sin equivalente STIX directo):",
            plugin_id=effect["plugin_id"],
        )
    ]
    lines.append(
        _("- Adversario debe creer (Pensar): %(value)s", value=effect["expected_adversary_belief"] or sin_registrar)
    )
    lines.append(
        _("- Adversario debe hacer (Hacer): %(value)s", value=effect["expected_adversary_action"] or sin_registrar)
    )
    lines.append(_("- Métrica de éxito: %(value)s", value=effect["success_metric"] or sin_registrar))
    if effect["is_measured"]:
        # "?" no pasa por el catalogo: un signo de pregunta no tiene
        # traduccion, es igual en cualquier idioma soportado.
        lines.append(
            _(
                "- Resultado medido: %(outcome)s (por %(measured_by)s, %(measured_at)s)",
                outcome=effect["measured_outcome"],
                measured_by=effect["measured_by"] or "?",
                measured_at=effect["measured_at"] or "?",
            )
        )
    else:
        lines.append(_("- Resultado medido: sin medir todavía."))
    return "\n".join(lines)


def operation_report_to_stix_bundle(
    report: "OperationReport",
    *,
    tlp_classifications: Optional[list[TlpClassification]] = None,
) -> dict[str, Any]:
    """Bundle STIX 2.1 (`{"type": "bundle", "id": ..., "objects": [...]}`)
    sobre los mismos datos que `report.to_dict()` -- ninguna comparación
    de TTPs/IoCs se recalcula acá, mismo criterio que `to_markdown()`/
    `to_pdf()`. Ver docstring del módulo para el mapeo completo,
    campo por campo, y qué queda deliberadamente afuera -- incluida la
    sección sobre `tlp_classifications` (solo aplica a IoCs, no a
    eventos)."""

    data = report.to_dict()
    timestamp = _stix_timestamp(report.generated_at)
    catalog = {technique.id: technique for technique in list_techniques()}
    ioc_tlp_levels = {
        classification.subject_key: classification.level
        for classification in (tlp_classifications or [])
        if classification.subject_type == "ioc"
    }

    identity = {
        "type": "identity",
        "spec_version": _STIX_SPEC_VERSION,
        "id": _new_id("identity"),
        "created": timestamp,
        "modified": timestamp,
        "name": "APATE",
        "identity_class": "system",
        "description": _("Capa de orquestación y decisión para operaciones de ciberengaño."),
    }
    created_by_ref = identity["id"]

    ttp_ids = sorted(set(data["expected_ttps"]) | set(data["observed_ttps"]))
    attack_patterns = [
        _attack_pattern_object(ttp_id, catalog=catalog, created_by_ref=created_by_ref, timestamp=timestamp)
        for ttp_id in ttp_ids
    ]

    indicators = []
    markings_used: dict[TlpLevel, dict[str, Any]] = {}
    for ioc in data["iocs"]:
        level = ioc_tlp_levels.get(ioc_subject_key(ioc["type"], ioc["value"]))
        marking_ref = None
        if level is not None:
            marking_ref = _TLP_MARKING_IDS[level]
            markings_used.setdefault(level, _tlp_marking_object(level))
        indicator = _indicator_object(
            ioc["type"], ioc["value"], created_by_ref=created_by_ref, timestamp=timestamp, marking_ref=marking_ref
        )
        if indicator is not None:
            indicators.append(indicator)
    marking_objects = list(markings_used.values())

    report_object_id = _new_id("report")
    notes = []
    for effect in data["plugin_effects"]:
        content = _plugin_effect_note_content(effect)
        if content is not None:
            notes.append(_note_object(content, object_refs=[report_object_id], created_by_ref=created_by_ref, timestamp=timestamp))

    # marking_objects deliberadamente afuera de object_refs: STIX 2.1
    # exige que `report.object_refs` solo contenga SCO/SDO/SRO -- un
    # `marking-definition` no es ninguno de los tres (confirmado con
    # `stix2.parse(allow_custom=False)`, que lo rechaza de verdad). Un
    # marking se referencia solo via `object_marking_refs` del objeto
    # que marca, nunca desde `report.object_refs`.
    object_refs = [identity["id"]] + [obj["id"] for obj in (*attack_patterns, *indicators, *notes)]
    report_object = {
        "type": "report",
        "spec_version": _STIX_SPEC_VERSION,
        "id": report_object_id,
        "created": timestamp,
        "modified": timestamp,
        "created_by_ref": created_by_ref,
        "name": _("Informe post-operación — %(name)s", name=data["operation_name"]),
        "description": _(
            "Inteligencia generada por la operación de engaño '%(name)s' (id: %(id)s, estado: %(status)s).",
            name=data["operation_name"],
            id=data["operation_id"],
            status=data["operation_status"],
        ),
        "published": timestamp,
        "report_types": ["threat-report"],
        "object_refs": object_refs,
    }

    return {
        "type": "bundle",
        "id": _new_id("bundle"),
        "objects": [identity, *attack_patterns, *indicators, *marking_objects, *notes, report_object],
    }

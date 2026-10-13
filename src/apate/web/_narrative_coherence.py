"""Coherencia de la ficción de una operación (referencia declarada:
CounterCraft -- "construir la organización que un APT no pueda
resistir": la ficción presentada al adversario tiene que ser creíble
como CONJUNTO, no un montón de señuelos sueltos sin relación entre sí).

**Confirmado antes de construir esto: las piezas de esa ficción ya
existían en APATE, pero repartidas y sin que nadie las mirara juntas.**
`Narrative` (paso 5) es la historia y el sesgo cognitivo que se busca
explotar; los `UserProfile` de BUDA son los empleados ficticios; los
`Hostname`/`Description` de cada decoy de DOLOS-T y los servicios de
OpenCanary son la infraestructura ficticia; los `directory`/nombres de
archivo de cada `HoneytokenPlugin` y los Canarytokens son documentos o
migas ficticias; `Scenario`/`AdversaryProfile.target_assets` dicen qué
se supone que hay para robar. Nada en el modelo ni en la UI las cruzaba
antes de este módulo.

**Esto es análisis y presentación, NUNCA validación automática ni
corrección -- decisión explícita, misma que ya rechazó los scores
sintéticos en `apate.web._portfolio` y en `apate.reporting.dry_run`.**
No hay ningún "score de coherencia" en ningún lado, y **no se usa un LLM
para juzgar si la ficción es creíble** -- sería exactamente el tipo de
decisión automática que el proyecto evita por diseño (sección 8 del
documento de diseño).

**Honestidad explícita sobre qué es computable de verdad.** Buena parte
de la coherencia narrativa es subjetiva y NO es determinable con los
datos que hay -- "¿'Juan Pérez, contador' encaja con una narrativa de
fintech?" no tiene una respuesta programática. Lo que este módulo hace
de verdad es **poner las piezas juntas para que el operador las evalúe**
(`build_narrative_coherence()["pieces"]`), más un puñado de chequeos
objetivos *débiles* y explícitamente marcados como tales
(`["checks"]`, severity siempre `"info"`, nunca `"gap"` -- ninguno de
estos chequeos es lo bastante confiable como para llamarlo un hueco
objetivo, a diferencia de los de `apate.reporting.dry_run`): presencia
de un bloque sin el otro (narrativa sin empleados, infraestructura sin
empleados) y superposición de palabras clave (naive, sin NLP) entre
activos objetivo declarados y lo efectivamente desplegado. Si al
construir esto la parte "automática" da poco, ese es un resultado
honesto sobre el dominio, no una limitación de la implementación --
por eso la mitad del valor de esta vista es la tabla de piezas, no la
lista de chequeos.

**Solo lectura, como el ensayo en seco (`apate.reporting.dry_run`) --
pero, a diferencia de ese módulo, no puede ser puro sobre `Operation`
sola.** Los nombres/roles reales de los empleados ficticios viven en la
base de BUDA (`UserProfile`), no en `Operation` -- por eso esta función
vive en `apate.web` (no en `apate.reporting`, capa de dominio pura) y
recibe los mismos cinco paneles que ya calcula `operations.detail()`
para el árbol/camino de engaño (M-anterior) -- sin ninguna consulta nueva
a Docker/BUDA propia, reusa exactamente lo que la vista ya trajo. La
agrupación es semántica: Canarytoken va con documentos/migas por ser un
lure; OpenCanary va con infraestructura por ser un decoy de red/host. No
muta nada: ni la `Operation`, ni los paneles, ni dispara ningún
deploy/rotate/retire."""

from __future__ import annotations

import re
from typing import Any, Optional

from ..core.models import Operation, PluginBinding
from ..i18n import gettext as _

# Palabras demasiado comunes en español como para aportar señal en la
# superposicion de palabras clave (chequeo naive, sin NLP real) -- lista
# corta a proposito, solo lo que aparecio ruidoso probando con datos
# reales de demo, no un stopword list exhaustivo.
_STOPWORDS = {
    "para", "como", "esta", "este", "esto", "esos", "esas", "sobre",
    "hacia", "desde", "entre", "donde", "cuando", "todo", "toda",
    "todos", "todas", "otro", "otra", "otros", "otras", "cada", "que",
}


def _tokenize(text: str) -> set[str]:
    """Tokeniza texto libre para el chequeo de superposicion de palabras
    clave: minusculas, solo secuencias alfanumericas (con acentos) de 4+
    caracteres, sin stopwords cortas. Deliberadamente simple -- esto NO
    es NLP, es una senal debil (ver docstring del modulo)."""

    tokens = re.findall(r"[a-zA-ZÀ-ÿ0-9]{4,}", text.lower())
    return {t for t in tokens if t not in _STOPWORDS}


def _resolve_kind(binding: PluginBinding) -> Optional[str]:
    # Mismo heuristico auto-contenido que apate.reporting.dry_run/
    # apate.web._deception_path -- ver esos modulos para el por que.
    return binding.plugin_kind or (binding.plugin_id.split("-", 1)[0] or None)


def _gather_employees(operation: Operation, buda_panels: dict[str, dict]) -> list[dict[str, Any]]:
    employees: list[dict[str, Any]] = []
    for binding in operation.plugins:
        if _resolve_kind(binding) != "buda":
            continue
        panel = buda_panels.get(binding.plugin_id, {})
        for profile in panel.get("user_profiles", []):
            employees.append({"plugin_id": binding.plugin_id, "name": profile["name"], "role": profile.get("role") or ""})
    return employees


def _gather_infrastructure(
    operation: Operation, opencanary_panels: dict[str, dict]
) -> list[dict[str, Any]]:
    """Infraestructura ficticia de DOLOS-T y OpenCanary.

    DOLOS-T sale directo de ``binding.config``. OpenCanary se agrupa en
    esta categoria porque sus servicios de red/host son infraestructura
    señuelo, no una miga documental; sus paneles ya normalizan servicios
    sin que este modulo consulte Docker otra vez.
    """

    infrastructure: list[dict[str, Any]] = []
    for binding in operation.plugins:
        kind = _resolve_kind(binding)
        if kind == "dolost":
            for decoy in binding.config.get("decoys", []):
                infrastructure.append(
                    {
                        "plugin_id": binding.plugin_id,
                        "hostname": decoy.get("Hostname", ""),
                        "description": decoy.get("Description", ""),
                    }
                )
        elif kind == "opencanary":
            panel = opencanary_panels.get(binding.plugin_id, {})
            for service, config in panel.get("services", {}).items():
                if isinstance(config, dict) and not config.get("enabled", True):
                    continue
                port = config.get("port") if isinstance(config, dict) else None
                infrastructure.append(
                    {
                        "plugin_id": binding.plugin_id,
                        "hostname": f"{service}:{port}" if port else service,
                        "description": _("Servicio señuelo de OpenCanary"),
                    }
                )
    return infrastructure


def _gather_documents(
    operation: Operation,
    honeytoken_panels: dict[str, dict],
    canarytoken_panels: dict[str, dict],
) -> list[dict[str, Any]]:
    """Documentos y migas: honeytokens nativos más Canarytokens.

    Canarytoken vive aca por su funcion narrativa de lure/breadcrumb;
    se expone solo memo/tipo/hostname y nunca ``auth_token``.
    """

    documents: list[dict[str, Any]] = []
    for binding in operation.plugins:
        kind = _resolve_kind(binding)
        if kind == "honeytoken":
            panel = honeytoken_panels.get(binding.plugin_id, {})
            filenames = panel.get("filenames") or []
            directory = panel.get("directory", "")
            if filenames or directory:
                documents.append({"plugin_id": binding.plugin_id, "directory": directory, "filenames": filenames})
        elif kind == "canarytoken":
            panel = canarytoken_panels.get(binding.plugin_id, {})
            if panel.get("configured"):
                label = panel.get("memo") or panel.get("hostname") or binding.plugin_id
                documents.append(
                    {
                        "plugin_id": binding.plugin_id,
                        "directory": _("Canarytoken · %(token_type)s", token_type=panel.get("token_type") or _("tipo sin definir")),
                        "filenames": [label],
                    }
                )
    return documents


def _document_tokens(document: dict[str, Any]) -> set[str]:
    text = document["directory"] + " " + " ".join(document["filenames"])
    return _tokenize(text)


def _infrastructure_tokens(infrastructure: list[dict[str, Any]]) -> set[str]:
    tokens: set[str] = set()
    for item in infrastructure:
        tokens |= _tokenize(item["hostname"] + " " + item["description"])
    return tokens


def _scenario_tokens(operation: Operation) -> set[str]:
    tokens: set[str] = set()
    for scenario in operation.scenarios:
        tokens |= _tokenize(scenario.description)
    return tokens


def _checks(
    operation: Operation,
    *,
    employees: list[dict[str, Any]],
    infrastructure: list[dict[str, Any]],
    documents: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    narrative = operation.narrative

    narrative_has_content = bool(
        narrative.description.strip() or narrative.psychological_impact.strip() or narrative.story_elements
    )
    if narrative_has_content and not employees:
        checks.append(
            {
                "category": "narrative_without_employees",
                "severity": "info",
                "message": _("Hay una narrativa cargada con contenido real, pero ningún empleado ficticio (perfil de identidad simulada) vinculado -- la historia no tiene ningún protagonista humano que la sostenga."),
            }
        )

    if infrastructure and not employees:
        checks.append(
            {
                "category": "infrastructure_without_employees",
                "severity": "info",
                "message": _("Hay %(count)s pieza(s) de infraestructura ficticia (decoy) sin ningún empleado ficticio vinculado en la operación -- nadie 'sería dueño' de esos hosts en la ficción.", count=len(infrastructure)),
            }
        )
    if employees and not infrastructure:
        checks.append(
            {
                "category": "employees_without_infrastructure",
                "severity": "info",
                "message": _("Hay %(count)s empleado(s) ficticio(s) sin ninguna infraestructura (decoy) vinculada en la operación -- la ficción tiene personas pero no un entorno donde actuar.", count=len(employees)),
            }
        )

    # Chequeo de superposicion de palabras clave -- naive, sin NLP (ver
    # docstring del modulo). Solo tiene sentido si hay contra que
    # comparar: sin infraestructura/documentos/escenarios desplegados
    # todavia, marcar cada activo como "sin representacion" seria puro
    # ruido (nada podria representarlo todavia).
    deployed_tokens = _infrastructure_tokens(infrastructure) | _scenario_tokens(operation)
    if deployed_tokens:
        for asset in operation.adversary_profile.target_assets:
            asset_tokens = _tokenize(asset)
            if asset_tokens and asset_tokens.isdisjoint(deployed_tokens):
                checks.append(
                    {
                        "category": "target_asset_without_representation",
                        "severity": "info",
                        "message": _("El activo objetivo declarado '%(asset)s' no comparte ninguna palabra clave con los escenarios ni la infraestructura desplegada -- chequeo de texto simple, puede ser una coincidencia del heurístico y no un problema real; revisar a criterio.", asset=asset),
                    }
                )

    comparison_tokens = _scenario_tokens(operation) | {
        token for asset in operation.adversary_profile.target_assets for token in _tokenize(asset)
    }
    if comparison_tokens:
        for document in documents:
            document_tokens = _document_tokens(document)
            if document_tokens and document_tokens.isdisjoint(comparison_tokens):
                label = document["directory"] or ", ".join(document["filenames"]) or document["plugin_id"]
                checks.append(
                    {
                        "category": "honeytoken_without_relation",
                        "severity": "info",
                        "message": _("El honeytoken '%(label)s' no comparte ninguna palabra clave con los escenarios ni los activos objetivo declarados -- chequeo de texto simple, puede colgar de la nada o puede ser una coincidencia del heurístico; revisar a criterio.", label=label),
                    }
                )

    return checks


def build_narrative_coherence(
    operation: Operation,
    *,
    dolost_panels: dict[str, dict],
    buda_panels: dict[str, dict],
    honeytoken_panels: dict[str, dict],
    canarytoken_panels: dict[str, dict] | None = None,
    opencanary_panels: dict[str, dict] | None = None,
) -> dict[str, Any]:
    """Junta las piezas de la ficción de `operation` (narrativa, activos
    objetivo, empleados/infraestructura/documentos ficticios, escenarios)
    para que el operador las evalúe en conjunto, más un puñado de
    chequeos objetivos débiles (ver docstring del módulo). Solo lectura:
    no muta `operation` ni los paneles, no dispara ningún deploy."""

    canarytoken_panels = canarytoken_panels or {}
    opencanary_panels = opencanary_panels or {}
    employees = _gather_employees(operation, buda_panels)
    infrastructure = _gather_infrastructure(operation, opencanary_panels)
    documents = _gather_documents(operation, honeytoken_panels, canarytoken_panels)
    narrative = operation.narrative
    narrative_has_content = bool(
        narrative.description.strip() or narrative.psychological_impact.strip() or narrative.story_elements
    )

    has_content = bool(
        narrative_has_content
        or operation.adversary_profile.target_assets
        or employees
        or infrastructure
        or documents
        or operation.scenarios
    )

    return {
        "has_content": has_content,
        "narrative": narrative,
        "narrative_has_content": narrative_has_content,
        "target_assets": list(operation.adversary_profile.target_assets),
        "employees": employees,
        "infrastructure": infrastructure,
        "documents": documents,
        "scenarios": list(operation.scenarios),
        "checks": _checks(operation, employees=employees, infrastructure=infrastructure, documents=documents),
    }

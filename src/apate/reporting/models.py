"""Informe post-operacion (M6) y kit de taller colaborativo (M12i) -
documento de diseno, seccion 4.3 ("Retroalimentacion CTI"), pasos 3/4/7
de la metodologia CTI-a-ciberengano.

`OperationReport`/`WorkshopKit` son las unicas estructuras de datos
internas de cada documento; `to_markdown()` (y `to_json()` donde
aplica) se construyen a partir de `to_dict()` para no duplicar la
logica de que campos lleva el documento en cada formato de salida --
si un campo nuevo se agrega, alcanza con tocar to_dict().

**i18n (tanda 3):** el texto visible de `to_markdown()` usa `apate.i18n.
gettext` (alias `_`), igual que el resto de la aplicacion -- ver
`src/apate/i18n.py` para por que el mismo `_()` sirve con o sin
contexto de Flask. Los valores dinamicos (nombres, IDs, listas ya
formateadas) viajan como `%(nombre)s` interpolado por `gettext()`, no
concatenados en el `msgid`, para que el catalogo tenga una entrada por
frase y no una por combinacion de datos.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from ..core.models import AdversaryProfile, Scenario
from ..i18n import gettext as _
from ..telemetry.models import IoC

if TYPE_CHECKING:
    from ..telemetry.classifications import TlpClassification


@dataclass
class PluginEffectSummary:
    """Planificado (`DeceptionEffect`, paso 4 de la metodologia) vs.
    medido (`DeceptionEffect.measured_outcome`, Fase 2 post-BlackHat,
    ver docs/roadmap.md) para un `PluginBinding` puntual. A diferencia
    de las TTPs de `OperationReport` (comparadas por conjuntos),
    `success_metric`/`measured_outcome` son texto libre -- no hay
    interseccion posible, la comparacion es simplemente mostrar los
    dos lados uno al lado del otro y si ya se cargo un resultado o
    no (`is_measured`)."""

    plugin_id: str
    expected_adversary_belief: str
    expected_adversary_action: str
    success_metric: str
    measured_outcome: str
    measured_at: Optional[datetime]
    measured_by: str
    evidence_event_ids: list[str] = field(default_factory=list)

    @property
    def is_measured(self) -> bool:
        return bool(self.measured_outcome)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "expected_adversary_belief": self.expected_adversary_belief,
            "expected_adversary_action": self.expected_adversary_action,
            "success_metric": self.success_metric,
            "measured_outcome": self.measured_outcome,
            "measured_at": self.measured_at.isoformat() if self.measured_at else None,
            "measured_by": self.measured_by,
            "evidence_event_ids": list(self.evidence_event_ids),
            "is_measured": self.is_measured,
        }


@dataclass
class OperationReport:
    """Compara lo esperado (AdversaryProfile.expected_ttps, paso 1 de
    la metodologia) contra lo efectivamente observado
    (TelemetryCollector.list_ttps/list_iocs, M4) para una Operacion.
    Las TTPs se guardan ya como tres conjuntos derivados
    (matched/not_observed/unexpected) en vez de recalcularlos en cada
    formato de salida.

    `plugin_effects` (Fase 2 post-BlackHat) suma la comparacion
    planificado-vs-medido del efecto de engaño (paso 4) por cada
    `PluginBinding` de la operacion -- no depende de telemetria (a
    diferencia de las TTPs de arriba), es directamente lo que ya esta
    cargado en cada `DeceptionEffect`."""

    operation_id: str
    operation_name: str
    operation_status: str
    generated_at: datetime
    expected_ttps: list[str] = field(default_factory=list)
    observed_ttps: list[str] = field(default_factory=list)
    matched_ttps: list[str] = field(default_factory=list)
    ttps_not_observed: list[str] = field(default_factory=list)
    unexpected_ttps: list[str] = field(default_factory=list)
    iocs: list[IoC] = field(default_factory=list)
    event_count: int = 0
    plugin_effects: list[PluginEffectSummary] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "operation_name": self.operation_name,
            "operation_status": self.operation_status,
            "generated_at": self.generated_at.isoformat(),
            "expected_ttps": list(self.expected_ttps),
            "observed_ttps": list(self.observed_ttps),
            "matched_ttps": list(self.matched_ttps),
            "ttps_not_observed": list(self.ttps_not_observed),
            "unexpected_ttps": list(self.unexpected_ttps),
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "event_count": self.event_count,
            "plugin_effects": [pe.to_dict() for pe in self.plugin_effects],
        }

    def to_json(self, *, indent: int = 2) -> str:
        """Formato pensado para alimentar un programa de CTI externo
        (roadmap M6)."""

        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_pdf(self) -> bytes:
        """Tercera representación de salida (M13h), sobre los mismos
        datos que `to_dict()` -- ver `apate.reporting.pdf` para la
        generación en sí (import perezoso: `apate.reporting` no
        depende de `fpdf2` a nivel de módulo, solo quien llame a este
        método lo necesita instalado)."""

        from .pdf import operation_report_to_pdf

        return operation_report_to_pdf(self)

    def to_stix_bundle(self, *, tlp_classifications: Optional[list["TlpClassification"]] = None) -> dict[str, Any]:
        """Bundle STIX 2.1 (dict, no serializado) -- ver
        `apate.reporting.stix` para el mapeo completo campo por campo y
        la decisión de formato/dependencias. Import a nivel de módulo
        (no perezoso como `to_pdf()`): `apate.reporting.stix` no
        depende de nada externo a la librería estándar, así que no hay
        una dependencia opcional que evitar cargar de más.

        `tlp_classifications` (segunda de la tanda de mejoras de UI/UX
        con referencia CounterCraft, ver docs/roadmap.md) es opcional y
        no se calcula acá -- quien llama (la ruta web de descarga del
        informe) es quien tiene acceso al repositorio de
        clasificaciones, `OperationReport` no lo conoce."""

        from .stix import operation_report_to_stix_bundle

        return operation_report_to_stix_bundle(self, tlp_classifications=tlp_classifications)

    def to_stix(self, *, indent: int = 2, tlp_classifications: Optional[list["TlpClassification"]] = None) -> str:
        """Cuarta representación de salida -- pensada para alimentar
        directamente un SIEM/SOAR/EDR u otra herramienta de CTI, a
        diferencia de `to_json()` (formato propio de APATE, ninguna
        otra herramienta lo interpreta)."""

        return json.dumps(
            self.to_stix_bundle(tlp_classifications=tlp_classifications), indent=indent, ensure_ascii=False
        )

    def to_markdown(self) -> str:
        """Formato pensado para lectura humana directa (roadmap M6)."""

        data = self.to_dict()
        lines = [
            _("# Informe post-operación — %(name)s", name=data["operation_name"]),
            "",
            _("- **ID de operación:** `%(id)s`", id=data["operation_id"]),
            _("- **Estado:** %(status)s", status=data["operation_status"]),
            _("- **Generado:** %(generated_at)s", generated_at=data["generated_at"]),
            _("- **Eventos registrados:** %(count)s", count=data["event_count"]),
            "",
            _("## TTPs"),
            "",
            _("- **Esperadas** (perfil de adversario): %(value)s", value=_join_or_none(data["expected_ttps"])),
            _("- **Observadas** (telemetría): %(value)s", value=_join_or_none(data["observed_ttps"])),
            _("- **Coincidentes:** %(value)s", value=_join_or_none(data["matched_ttps"])),
            _("- **Esperadas y NO observadas:** %(value)s", value=_join_or_none(data["ttps_not_observed"])),
            _("- **Observadas y NO esperadas:** %(value)s", value=_join_or_none(data["unexpected_ttps"])),
            "",
            _("## IoCs"),
            "",
        ]
        if data["iocs"]:
            lines.append(_("| Tipo | Valor |"))
            lines.append("|---|---|")
            lines.extend(f"| {ioc['type']} | {ioc['value']} |" for ioc in data["iocs"])
        else:
            lines.append(_("Sin IoCs observados."))
        lines.append("")
        lines.append(_("## Efecto de engaño: planificado vs. medido"))
        lines.append("")
        lines.extend(_plugin_effects_markdown(data["plugin_effects"]))
        return "\n".join(lines)


def _join_or_none(values: list[str]) -> str:
    return ", ".join(values) if values else _("(ninguna)")


def _sin_registrar(value: str) -> str:
    return value or _("(sin registrar)")


def _plugin_effects_markdown(plugin_effects: list[dict[str, Any]]) -> list[str]:
    """Compartido entre `OperationReport.to_markdown()` y
    `WorkshopKit.to_markdown()` (Fase 2 post-BlackHat) -- misma
    seccion, mismos datos (`PluginEffectSummary.to_dict()`), para no
    mantener dos formatos de salida distintos para lo mismo."""

    if not plugin_effects:
        return [_("Sin plugins vinculados a esta operación."), ""]

    lines = []
    for pe in plugin_effects:
        lines.append(_("### Plugin: `%(plugin_id)s`", plugin_id=pe["plugin_id"]))
        lines.append("")
        lines.append(
            _("- **Adversario debe pensar (planificado):** %(value)s", value=_sin_registrar(pe["expected_adversary_belief"]))
        )
        lines.append(
            _("- **Adversario debe hacer (planificado):** %(value)s", value=_sin_registrar(pe["expected_adversary_action"]))
        )
        lines.append(_("- **Métrica de éxito (planificada):** %(value)s", value=_sin_registrar(pe["success_metric"])))
        if pe["is_measured"]:
            lines.append(_("- **Resultado medido:** %(value)s", value=pe["measured_outcome"]))
            lines.append(
                _(
                    "- **Medido por:** %(measured_by)s — %(measured_at)s",
                    measured_by=_sin_registrar(pe["measured_by"]),
                    measured_at=pe["measured_at"],
                )
            )
            if pe["evidence_event_ids"]:
                lines.append(_("- **Eventos de evidencia:** %(ids)s", ids=", ".join(pe["evidence_event_ids"])))
        else:
            lines.append(_("- **Resultado medido:** sin medir todavía."))
        lines.append("")
    return lines


@dataclass
class WorkshopKit:
    """Material exportable para la dinamica de taller colaborativo que
    describe la metodologia CTI-a-ciberengano (M12i, ver
    docs/analisis-engage-integral.md) -- pensado para imprimir/completar
    a mano con los stakeholders presentes, no un informe de lo ya
    configurado (a diferencia de `OperationReport`, que compara contra
    lo efectivamente observado). Por eso, a diferencia del informe de
    M6, no exige que la Operacion este `CLOSED`: tiene sentido usarlo
    tambien en `PLANNING`/`ACTIVE`, antes o durante el taller.

    El heatmap de TTPs reusa `generate_report()` (M6) tal cual cuando
    hay un `TelemetryCollector` disponible -- `observed_ttps`/
    `matched_ttps`/`ttps_not_observed`/`unexpected_ttps` quedan en
    `None` (no `[]`) si no se paso telemetria, para distinguir
    explicitamente "no se comparo contra nada" de "se comparo y no
    hubo coincidencias".

    `plugin_effects` (Fase 2 post-BlackHat) NO depende de telemetria
    -- a diferencia del heatmap de arriba, nunca queda en `None`: es
    directamente lo que ya esta cargado en cada `DeceptionEffect` de
    la operacion, tenga o no tenga telemetria un `TelemetryCollector`
    a mano. Tiene sentido como material de taller igual que el resto
    del kit: muestra que ya se planifico/midio y que sigue sin medirse,
    pie para la discusion en vivo."""

    operation_id: str
    operation_name: str
    operation_status: str
    generated_at: datetime
    adversary_profile: AdversaryProfile
    scenarios: list[Scenario] = field(default_factory=list)
    expected_ttps: list[str] = field(default_factory=list)
    observed_ttps: Optional[list[str]] = None
    matched_ttps: Optional[list[str]] = None
    ttps_not_observed: Optional[list[str]] = None
    unexpected_ttps: Optional[list[str]] = None
    plugin_effects: list[PluginEffectSummary] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "operation_name": self.operation_name,
            "operation_status": self.operation_status,
            "generated_at": self.generated_at.isoformat(),
            "adversary_profile": self.adversary_profile.to_dict(),
            "scenarios": [s.to_dict() for s in self.scenarios],
            "expected_ttps": list(self.expected_ttps),
            "observed_ttps": None if self.observed_ttps is None else list(self.observed_ttps),
            "matched_ttps": None if self.matched_ttps is None else list(self.matched_ttps),
            "ttps_not_observed": None if self.ttps_not_observed is None else list(self.ttps_not_observed),
            "unexpected_ttps": None if self.unexpected_ttps is None else list(self.unexpected_ttps),
            "plugin_effects": [pe.to_dict() for pe in self.plugin_effects],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_pdf(self) -> bytes:
        """Tercera representación de salida (M13h) -- a diferencia de
        `to_markdown()`, deja cajas en blanco dibujadas de verdad para
        las preguntas Ver/Pensar/Hacer/Éxito de cada escenario, no un
        renglón de guiones bajos: es el formato pensado para el caso de
        uso real de este kit (imprimir y completar a mano en el
        taller). Ver `apate.reporting.pdf` para la generación en sí
        (import perezoso, mismo criterio que `OperationReport.to_pdf()`)."""

        from .pdf import workshop_kit_to_pdf

        return workshop_kit_to_pdf(self)

    def to_markdown(self) -> str:
        """Formato pensado para imprimir/repartir en el taller -- el
        caso de uso real de este kit (a diferencia de `to_json()`, que
        se suma solo por simetria con `OperationReport`, sin un
        consumidor concreto todavia)."""

        data = self.to_dict()
        lines = [
            _("# Kit de taller — %(name)s", name=data["operation_name"]),
            "",
            _("- **ID de operación:** `%(id)s`", id=data["operation_id"]),
            _("- **Estado:** %(status)s", status=data["operation_status"]),
            _("- **Generado:** %(generated_at)s", generated_at=data["generated_at"]),
            "",
            _("## Paso 1 · Ficha de perfil de amenaza"),
            "",
            _("- **Nombre / actor:** %(value)s", value=data["adversary_profile"]["name"]),
            _("- **Motivación:** %(value)s", value=_sin_registrar(data["adversary_profile"]["motivation"])),
            _("- **Nivel de habilidad:** %(value)s", value=data["adversary_profile"]["skill_level"]),
            _(
                "- **Activos críticos objetivo:** %(value)s",
                value=_join_or_none(data["adversary_profile"]["target_assets"]),
            ),
            _("- **TTPs esperadas:** %(value)s", value=_join_or_none(data["adversary_profile"]["expected_ttps"])),
            _("- **Notas:** %(value)s", value=data["adversary_profile"]["notes"] or _("(sin notas)")),
            "",
            _("## Heatmap de TTPs"),
            "",
        ]
        if data["observed_ttps"] is None:
            lines.append(_("- **Esperadas:** %(value)s", value=_join_or_none(data["expected_ttps"])))
            lines.append(
                _(
                    "- Sin telemetría cargada todavía -- el heatmap completo (observadas/coincidentes) "
                    "está disponible una vez que la operación tenga eventos registrados."
                )
            )
        else:
            lines.append(_("- **Esperadas:** %(value)s", value=_join_or_none(data["expected_ttps"])))
            lines.append(_("- **Observadas** (telemetría): %(value)s", value=_join_or_none(data["observed_ttps"])))
            lines.append(_("- **Coincidentes:** %(value)s", value=_join_or_none(data["matched_ttps"])))
            lines.append(
                _("- **Esperadas y NO observadas:** %(value)s", value=_join_or_none(data["ttps_not_observed"]))
            )
            lines.append(
                _("- **Observadas y NO esperadas:** %(value)s", value=_join_or_none(data["unexpected_ttps"]))
            )
        lines.append("")
        lines.append(_("## Paso 3 · Escenarios y Paso 4 · Ver-Pensar-Hacer"))
        lines.append("")
        if not data["scenarios"]:
            lines.append(
                _("Sin escenarios cargados todavía -- completar durante el taller (paso 3 de la metodología).")
            )
        else:
            for scenario in data["scenarios"]:
                lines.append(_("### Escenario: %(description)s", description=scenario["description"]))
                lines.append("")
                lines.append(_("- **TTPs relacionadas:** %(value)s", value=_join_or_none(scenario["related_ttps"])))
                lines.append(_("- **Nivel de engaño:** %(value)s", value=scenario["deception_level"]))
                lines.append("")
                lines.append(_("**¿Qué debe VER el adversario?** ______________________________"))
                lines.append("")
                lines.append(_("**¿Qué debe PENSAR (creer)?** ______________________________"))
                lines.append("")
                lines.append(_("**¿Qué debe HACER?** ______________________________"))
                lines.append("")
                lines.append(_("**¿Cómo se mide el éxito?** ______________________________"))
                lines.append("")
        lines.append(_("## Efecto de engaño ya vinculado: planificado vs. medido"))
        lines.append("")
        lines.extend(_plugin_effects_markdown(data["plugin_effects"]))
        return "\n".join(lines)

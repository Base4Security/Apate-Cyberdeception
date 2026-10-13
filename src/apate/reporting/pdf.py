"""Generación de PDF para el informe post-operación (M6) y el kit de
taller (M12i) - M13h, ver docs/roadmap.md sección M13h.

Tercera representación de salida sobre los mismos datos que ya arman
`to_dict()` -- ninguna comparación de TTPs/IoCs se recalcula acá, se
lee tal cual de `OperationReport`/`WorkshopKit` ya construidos (mismo
criterio que `to_markdown()`/`to_json()`, que tampoco duplican esa
lógica).

**Librería: `fpdf2`, no `reportlab`/`WeasyPrint`.** Evaluada a
propósito contra el objetivo declarado de una demo confiable en vivo
(filosofía de dependencias mínimas y justificadas): `fpdf2` es 100% Python puro, sin ninguna
extensión C propia -- nada que pueda fallar de forma no reproducible
por faltar un compilador o una librería de sistema (a diferencia de
WeasyPrint, que necesita Pango/Cairo instalados aparte del propio
`pip install`). Trae `Pillow`/`fonttools`/`defusedxml` como
dependencias transitivas -- `Pillow` sí tiene extensiones C, pero
publica wheels precompilados para prácticamente cualquier plataforma
soportada, así que el riesgo real de que `pip install` falle en el
entorno de la demo es bajo, y de todos modos APATE no llama a Pillow
directamente. `reportlab` se descartó por ser una superficie mucho más
grande de la que este hito necesita (motor de gráficos completo,
soporte de charts, etc.) para lo que acá es texto + una tabla simple +
un par de rectángulos en blanco.

**Import perezoso, no a nivel de módulo.** `apate.reporting` hoy no
depende de nada externo a la librería estándar (solo `apate.core`/
`apate.telemetry`, ambos igual de minimalistas) -- alguien que solo
necesite `generate_report()`/`to_json()`/`to_markdown()` de forma
programática no tiene por qué instalar `fpdf2`. El import de `fpdf`
vive dentro de las funciones de este módulo, no arriba del archivo.

**Codificación de texto, decisión explícita para no romper una demo en
vivo por un caracter inesperado.** Las fuentes "core" de PDF (Helvetica
acá) no soportan Unicode completo -- por defecto `fpdf2` sólo acepta
texto codificable en Latin-1 estricto, que ni siquiera incluye la raya
larga "—" que ya usan `to_markdown()`/`to_json()`. Se configuró
`core_fonts_encoding = "windows-1252"` (superset de Latin-1 que sí
cubre raya larga y comillas tipográficas, sigue siendo una fuente
core, sin necesidad de empaquetar un archivo de fuente TTF de terceros)
más `_pdf_safe()`, que ademas reemplaza con "?" cualquier caracter que
ni siquiera windows-1252 pueda codificar (emoji, CJK, lo que sea que un
operador haya escrito en un campo de texto libre como notas del
adversario) en vez de dejar que `FPDFUnicodeEncodingException` tire
abajo la descarga entera.

**i18n (tanda 3):** mismo criterio que `apate.reporting.models` --
texto visible envuelto en `_()` de `apate.i18n`, reusando exactamente
los mismos `msgid` que `to_markdown()` donde la frase es igual, para
que el catálogo tenga una sola entrada por frase en vez de una por
formato de salida."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..i18n import gettext as _

if TYPE_CHECKING:
    from .models import OperationReport, WorkshopKit


def _pdf_safe(text: str) -> str:
    """Nunca lanza -- un caracter fuera de windows-1252 (emoji, CJK,
    lo que sea) se reemplaza por "?" en vez de tirar abajo la
    generación completa del PDF por un campo de texto libre que un
    operador escribió con algo inesperado."""

    return text.encode("windows-1252", errors="replace").decode("windows-1252")


def _new_document(title: str):
    from fpdf import FPDF

    pdf = FPDF(format="A4")
    pdf.core_fonts_encoding = "windows-1252"
    pdf.set_title(_pdf_safe(title))
    pdf.set_margin(18)
    pdf.add_page()
    return pdf


def _heading(pdf, text: str, *, size: int = 16) -> None:
    pdf.set_font("Helvetica", style="B", size=size)
    pdf.multi_cell(0, 8, _pdf_safe(text), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)


def _subheading(pdf, text: str) -> None:
    pdf.set_font("Helvetica", style="B", size=13)
    pdf.multi_cell(0, 7, _pdf_safe(text), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _field(pdf, label: str, value: str) -> None:
    pdf.set_font("Helvetica", style="B", size=10)
    pdf.write(6, _pdf_safe(f"{label}: "))
    pdf.set_font("Helvetica", size=10)
    pdf.multi_cell(0, 6, _pdf_safe(value), new_x="LMARGIN", new_y="NEXT")


def _join_or_none(values: list[str]) -> str:
    return ", ".join(values) if values else _("(ninguna)")


def _sin_registrar(value: str) -> str:
    return value or _("(sin registrar)")


def _blank_box(pdf, prompt: str, *, height: float = 16) -> None:
    """Caja en blanco real (rectángulo dibujado, no subrayado de texto)
    para completar a mano -- el caso de uso central del kit de taller
    (M12i): a diferencia de `to_markdown()`, que deja una línea de
    guiones bajos como placeholder de texto plano, esta es la versión
    pensada para imprimir de verdad."""

    pdf.set_font("Helvetica", style="B", size=10)
    pdf.multi_cell(0, 6, _pdf_safe(prompt), new_x="LMARGIN", new_y="NEXT")
    x, y = pdf.get_x(), pdf.get_y()
    pdf.rect(x, y, pdf.epw, height)
    pdf.set_y(y + height + 3)


def operation_report_to_pdf(report: "OperationReport") -> bytes:
    """PDF del informe post-operación (M6) -- misma información que
    `report.to_markdown()`, ninguna comparación de TTPs/IoCs se
    recalcula acá."""

    data = report.to_dict()
    # El título del documento (metadata del PDF en sí, no un elemento
    # visible del cuerpo) no pasa por `_()`: `pdf.set_title()` lo
    # codifica con `_pdf_safe()` más abajo, y mantenerlo en español fijo
    # evita depender del contexto de Flask en un dato que ni siquiera se
    # ve en la página.
    pdf = _new_document(f"Informe post-operacion - {data['operation_name']}")

    _heading(pdf, _("Informe post-operación — %(name)s", name=data["operation_name"]))
    _field(pdf, _("ID de operación"), data["operation_id"])
    _field(pdf, _("Estado"), data["operation_status"])
    _field(pdf, _("Generado"), data["generated_at"])
    _field(pdf, _("Eventos registrados"), str(data["event_count"]))
    pdf.ln(2)

    _subheading(pdf, _("TTPs"))
    _field(pdf, _("Esperadas (perfil de adversario)"), _join_or_none(data["expected_ttps"]))
    _field(pdf, _("Observadas (telemetría)"), _join_or_none(data["observed_ttps"]))
    _field(pdf, _("Coincidentes"), _join_or_none(data["matched_ttps"]))
    _field(pdf, _("Esperadas y NO observadas"), _join_or_none(data["ttps_not_observed"]))
    _field(pdf, _("Observadas y NO esperadas"), _join_or_none(data["unexpected_ttps"]))
    pdf.ln(2)

    _subheading(pdf, _("IoCs"))
    if data["iocs"]:
        pdf.set_font("Helvetica", size=10)
        with pdf.table(col_widths=(1, 2), text_align="LEFT") as table:
            header = table.row()
            header.cell(_pdf_safe(_("Tipo")))
            header.cell(_pdf_safe(_("Valor")))
            for ioc in data["iocs"]:
                row = table.row()
                row.cell(_pdf_safe(ioc["type"]))
                row.cell(_pdf_safe(ioc["value"]))
    else:
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(0, 6, _pdf_safe(_("Sin IoCs observados.")), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    _subheading(pdf, _("Efecto de engaño: planificado vs. medido"))
    _plugin_effects_to_pdf(pdf, data["plugin_effects"])

    return bytes(pdf.output())


def _plugin_effects_to_pdf(pdf, plugin_effects: list[dict]) -> None:
    """Compartido entre `operation_report_to_pdf()` y
    `workshop_kit_to_pdf()` (Fase 2 post-BlackHat) -- misma seccion,
    mismos datos, para no mantener dos layouts distintos para lo
    mismo."""

    if not plugin_effects:
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(0, 6, _pdf_safe(_("Sin plugins vinculados a esta operación.")), new_x="LMARGIN", new_y="NEXT")
        return

    for pe in plugin_effects:
        pdf.set_font("Helvetica", style="B", size=11)
        pdf.multi_cell(0, 6, _pdf_safe(_("Plugin: %(plugin_id)s", plugin_id=pe["plugin_id"])), new_x="LMARGIN", new_y="NEXT")
        _field(pdf, _("Adversario debe pensar (planificado)"), _sin_registrar(pe["expected_adversary_belief"]))
        _field(pdf, _("Adversario debe hacer (planificado)"), _sin_registrar(pe["expected_adversary_action"]))
        _field(pdf, _("Métrica de éxito (planificada)"), _sin_registrar(pe["success_metric"]))
        if pe["is_measured"]:
            _field(pdf, _("Resultado medido"), pe["measured_outcome"])
            if pe.get("evidence_event_ids"):
                _field(pdf, _("Eventos de evidencia"), ", ".join(pe["evidence_event_ids"]))
            _field(
                pdf,
                _("Medido por"),
                _("%(measured_by)s — %(measured_at)s", measured_by=_sin_registrar(pe["measured_by"]), measured_at=pe["measured_at"]),
            )
        else:
            _field(pdf, _("Resultado medido"), _("sin medir todavía."))
        pdf.ln(2)


def workshop_kit_to_pdf(kit: "WorkshopKit") -> bytes:
    """PDF del kit de taller (M12i) -- el caso de uso real de este
    hito: pensado para imprimir y completar a mano con los
    stakeholders presentes en el taller, así que las preguntas
    Ver/Pensar/Hacer/Éxito de cada escenario (paso 4 de la metodología)
    quedan con una caja dibujada de verdad (`_blank_box()`), no un
    renglón de guiones bajos como en `to_markdown()`."""

    data = kit.to_dict()
    pdf = _new_document(f"Kit de taller - {data['operation_name']}")

    _heading(pdf, _("Kit de taller — %(name)s", name=data["operation_name"]))
    _field(pdf, _("ID de operación"), data["operation_id"])
    _field(pdf, _("Estado"), data["operation_status"])
    _field(pdf, _("Generado"), data["generated_at"])
    pdf.ln(2)

    _subheading(pdf, _("Paso 1 · Ficha de perfil de amenaza"))
    profile = data["adversary_profile"]
    _field(pdf, _("Nombre / actor"), profile["name"])
    _field(pdf, _("Motivación"), _sin_registrar(profile["motivation"]))
    _field(pdf, _("Nivel de habilidad"), profile["skill_level"])
    _field(pdf, _("Activos críticos objetivo"), _join_or_none(profile["target_assets"]))
    _field(pdf, _("TTPs esperadas"), _join_or_none(profile["expected_ttps"]))
    _field(pdf, _("Notas"), profile["notes"] or _("(sin notas)"))
    pdf.ln(2)

    _subheading(pdf, _("Heatmap de TTPs"))
    if data["observed_ttps"] is None:
        _field(pdf, _("Esperadas"), _join_or_none(data["expected_ttps"]))
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(
            0,
            6,
            _pdf_safe(
                _(
                    "Sin telemetría cargada todavía -- el heatmap completo (observadas/coincidentes) está "
                    "disponible una vez que la operación tenga eventos registrados."
                )
            ),
            new_x="LMARGIN",
            new_y="NEXT",
        )
    else:
        _field(pdf, _("Esperadas"), _join_or_none(data["expected_ttps"]))
        _field(pdf, _("Observadas (telemetría)"), _join_or_none(data["observed_ttps"]))
        _field(pdf, _("Coincidentes"), _join_or_none(data["matched_ttps"]))
        _field(pdf, _("Esperadas y NO observadas"), _join_or_none(data["ttps_not_observed"]))
        _field(pdf, _("Observadas y NO esperadas"), _join_or_none(data["unexpected_ttps"]))
    pdf.ln(2)

    _subheading(pdf, _("Paso 3 · Escenarios y Paso 4 · Ver-Pensar-Hacer"))
    if not data["scenarios"]:
        pdf.set_font("Helvetica", size=10)
        pdf.multi_cell(
            0,
            6,
            _pdf_safe(_("Sin escenarios cargados todavía -- completar durante el taller (paso 3 de la metodología).")),
            new_x="LMARGIN",
            new_y="NEXT",
        )
    else:
        for scenario in data["scenarios"]:
            pdf.set_font("Helvetica", style="B", size=11)
            pdf.multi_cell(
                0,
                6,
                _pdf_safe(_("Escenario: %(description)s", description=scenario["description"])),
                new_x="LMARGIN",
                new_y="NEXT",
            )
            _field(pdf, _("TTPs relacionadas"), _join_or_none(scenario["related_ttps"]))
            _field(pdf, _("Nivel de engaño"), scenario["deception_level"])
            pdf.ln(1)
            _blank_box(pdf, _("¿Qué debe VER el adversario?"))
            _blank_box(pdf, _("¿Qué debe PENSAR (creer)?"))
            _blank_box(pdf, _("¿Qué debe HACER?"))
            _blank_box(pdf, _("¿Cómo se mide el éxito?"))
            pdf.ln(3)

    _subheading(pdf, _("Efecto de engaño ya vinculado: planificado vs. medido"))
    _plugin_effects_to_pdf(pdf, data["plugin_effects"])

    return bytes(pdf.output())

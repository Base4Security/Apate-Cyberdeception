"""Auditoría automatizada de invariantes de accesibilidad del shell web.

No reemplaza una revisión con lector de pantalla ni la verificación visual:
falla la suite ante regresiones objetivas que pueden comprobarse sobre el
HTML renderizado sin sumar una dependencia de producción (IDs duplicados,
landmarks ausentes y referencias ARIA rotas).
"""

from collections import Counter
from html.parser import HTMLParser

from apate.core import (
    AdversaryProfile,
    DeceptionEffect,
    Narrative,
    Operation,
    PluginBinding,
    RulesOfEngagement,
    Scenario,
)


class _AccessibilityAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: list[str] = []
        self.aria_references: list[tuple[str, str]] = []
        self.headings: list[int] = []
        self.html_lang = ""
        self.main_count = 0
        self.skip_target = ""
        self.dialogs = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        values = dict(attrs)
        element_id = values.get("id")
        if element_id:
            self.ids.append(element_id)
        for attribute in ("aria-labelledby", "aria-describedby", "aria-controls"):
            for reference in (values.get(attribute) or "").split():
                self.aria_references.append((attribute, reference))
        if tag == "html":
            self.html_lang = values.get("lang") or ""
        elif tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.headings.append(int(tag[1]))
        elif tag == "main":
            self.main_count += 1
        elif tag == "a" and "skip-link" in (values.get("class") or "").split():
            self.skip_target = values.get("href") or ""
        elif tag == "dialog":
            self.dialogs += 1
            assert values.get("aria-label") or values.get("aria-labelledby"), "Todo dialog necesita nombre accesible"

    def assert_valid(self, route: str):
        duplicates = [element_id for element_id, count in Counter(self.ids).items() if count > 1]
        assert not duplicates, f"[{route}] IDs duplicados: {duplicates}"
        assert self.html_lang == "es", route
        assert self.main_count == 1, route
        assert self.skip_target.startswith("#") and self.skip_target[1:] in self.ids, route
        assert self.headings.count(1) == 1, f"[{route}] Se esperaban exactamente 1 h1, hay {self.headings.count(1)}"
        # Solo se controla BAJAR mas de un nivel (h2 -> h4 se saltea h3, y un
        # lector de pantalla pierde el nivel intermedio). Subir cualquier
        # cantidad es legitimo: cerrar una subseccion y abrir una seccion
        # nueva es exactamente h4 -> h2.
        for previous, current in zip(self.headings, self.headings[1:]):
            assert current - previous <= 1, f"[{route}] Salto de encabezados de h{previous} a h{current}"
        assert self.dialogs >= 3
        missing = [(attribute, reference) for attribute, reference in self.aria_references if reference not in self.ids]
        assert not missing, f"Referencias ARIA rotas: {missing}"


def test_representative_pages_pass_structural_accessibility_audit(client, app):
    # La operacion lleva expected_ttps, un escenario y un binding a proposito:
    # varias secciones ricas solo se renderizan cuando hay datos que mostrar.
    # El heatmap agregado del Portafolio, en particular, EXCLUYE toda
    # operacion sin expected_ttps (decision documentada en M13g), asi que con
    # una operacion vacia esta auditoria recorria la ruta sin llegar nunca al
    # contenido -- un falso verde: el salto de encabezados que motivo este
    # chequeo vivia justo ahi. Confirmado reintroduciendo un <h5> suelto en
    # el heatmap: con la operacion vacia el test pasaba igual.
    operation = Operation(
        name="Auditoría accesible",
        adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1078", "T1005"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    scenario = Scenario(description="Escenario auditado", related_ttps=["T1078"])
    operation.add_scenario(scenario)
    operation.bind_plugin(
        PluginBinding(
            plugin_id="mock-auditoria",
            plugin_kind="mock",
            surface="network",
            scenario_id=scenario.id,
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"]),
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    client.post(f"/operations/{operation.id}/attention/signals",
                data={"title": "Señal accesible", "severity": "high", "note": "Evidencia"})
    signal = app.config["ATTENTION_REPOSITORY"].list_signals(operation.id)[0]
    client.post(f"/operations/{operation.id}/attention/cases",
                data={"title": "Caso accesible", "signal_ids": signal.id})
    case = app.config["ATTENTION_REPOSITORY"].list_cases(operation.id)[0]
    routes = (
        "/",
        "/operations/",
        "/operations/new",
        f"/operations/{operation.id}",
        "/operations/portfolio",
        "/rules/",
        "/telemetry/",
        f"/telemetry/{operation.id}",
        "/health/",
        "/playground/",
        "/capabilities/",
        "/operations/templates",
        "/attention",
        f"/operations/{operation.id}/attention/cases/{case.id}",
    )

    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, route
        audit = _AccessibilityAudit()
        audit.feed(response.get_data(as_text=True))
        audit.assert_valid(route)

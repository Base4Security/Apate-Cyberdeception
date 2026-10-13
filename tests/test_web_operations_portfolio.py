"""Tests para la vista de portafolio (M13g) -- ver docs/roadmap.md
seccion M13g. Cobertura agregada entre TODAS las operaciones, extension
de M13a a nivel de portafolio.

Dos niveles: unitario sobre `apate.web._portfolio` (fixtures de
`OperationReport`/`Operation` armados a proposito, sin pasar por HTTP
ni por `generate_report()` real donde no hace falta) e integracion
sobre `GET /operations/portfolio` real."""

from datetime import datetime, timezone

from apate.assets import Asset
from apate.core import AdversaryProfile, DeceptionEffect, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.plugins import EventType, PluginEvent
from apate.reporting import OperationReport
from apate.telemetry import SQLiteTelemetryRepository, TelemetryCollector, TelemetryRecord
from apate.engage import get_activity
from apate.web._portfolio import (
    _portfolio_engage_coverage,
    _portfolio_asset_coverage,
    _portfolio_measured_effect_notes,
    _portfolio_plugin_kind_counts,
    _portfolio_ttp_heatmap,
    _resolve_portfolio_plugin_kind,
    build_portfolio,
)


def _make_report(**overrides) -> OperationReport:
    defaults = dict(
        operation_id="op-1",
        operation_name="Operacion",
        operation_status="active",
        generated_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return OperationReport(**defaults)


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba M13g",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _make_ttp_record(operation_id: str, ttp_id: str) -> TelemetryRecord:
    event = PluginEvent(
        event_type=EventType.TTP_OBSERVED,
        plugin_id="honeypot-mock-1",
        surface="network",
        operation_id=operation_id,
        payload={"ttp_id": ttp_id},
    )
    return TelemetryRecord.from_event(event)


def _cell(heatmap: dict, ttp_id: str) -> dict:
    for column in heatmap["columns"]:
        for cell in column["cells"]:
            if cell["technique"].id == ttp_id:
                return cell
    raise AssertionError(f"{ttp_id} no aparece en el catalogo curado")


# -- _portfolio_ttp_heatmap(): agregacion por conteo, status dominante ------


def test_ttp_heatmap_counts_matched_across_multiple_reports():
    # T1078 coincide en dos de tres reportes.
    reports = [
        _make_report(matched_ttps=["T1078"]),
        _make_report(matched_ttps=["T1078"]),
        _make_report(ttps_not_observed=["T1078"]),
    ]

    cell = _cell(_portfolio_ttp_heatmap(reports), "T1078")

    assert cell["status"] == "matched"
    assert cell["count"] == 2
    assert cell["matched_count"] == 2
    assert cell["not_observed_count"] == 1
    assert cell["unexpected_count"] == 0


def test_ttp_heatmap_dominant_status_priority_matched_over_not_observed_over_unexpected():
    # T1005: nunca matched, pero not_observed en un reporte y unexpected en otro.
    reports = [_make_report(ttps_not_observed=["T1005"]), _make_report(unexpected_ttps=["T1005"])]

    cell = _cell(_portfolio_ttp_heatmap(reports), "T1005")

    assert cell["status"] == "not-observed"
    assert cell["count"] == 1


def test_ttp_heatmap_neutral_cell_for_technique_unrelated_to_any_report():
    reports = [_make_report(matched_ttps=["T1078"])]

    # T1057 (catalogo curado) no aparece en ningun conjunto de ningun reporte.
    cell = _cell(_portfolio_ttp_heatmap(reports), "T1057")

    assert cell["status"] is None
    assert cell["count"] == 0


def test_ttp_heatmap_uncatalogued_ttp_listed_with_aggregated_count():
    # T1046 confirmado fuera del catalogo curado (ver test_web_operations_ttp_heatmap.py).
    reports = [_make_report(unexpected_ttps=["T1046"]), _make_report(unexpected_ttps=["T1046"])]

    heatmap = _portfolio_ttp_heatmap(reports)

    assert heatmap["uncatalogued"] == [{"id": "T1046", "status": "unexpected", "count": 2, "label": "observada, no esperada"}]


def test_ttp_heatmap_empty_reports_list_has_no_crash_and_all_neutral_cells():
    heatmap = _portfolio_ttp_heatmap([])

    assert heatmap["uncatalogued"] == []
    for column in heatmap["columns"]:
        for cell in column["cells"]:
            assert cell["status"] is None
            assert cell["count"] == 0


# -- build_portfolio(): filtro de que operaciones entran --------------------


class _FakeTelemetry:
    """Doble minimo de TelemetryCollector -- alcanza para build_portfolio()
    sin necesitar un TelemetryCollector real ni tocar disco.
    list_events_by_operation() vacío de propósito: la Fase 7 obtiene
    heatmap y métricas desde la misma consulta agrupada."""

    repository = object()

    def list_events(self, operation_id):
        return []

    def list_iocs(self, operation_id):
        return []

    def list_ttps(self, operation_id):
        return []

    def list_ttps_by_operation(self, operation_ids):
        return {}

    def list_events_by_operation(self, operation_ids):
        return {}


def test_build_portfolio_excludes_operations_without_expected_ttps_from_ttp_count():
    with_ttps = _make_operation(
        name="Con TTPs", adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1078"])
    )
    without_ttps = _make_operation(name="Sin TTPs", adversary_profile=AdversaryProfile(name="APT2"))

    result = build_portfolio([with_ttps, without_ttps], _FakeTelemetry())

    assert result["considered_count"] == 2
    assert result["ttp_operations_count"] == 1
    assert result["excluded_count"] == 1


def test_build_portfolio_empty_operations_list_does_not_crash():
    result = build_portfolio([], _FakeTelemetry())

    assert result["considered_count"] == 0
    assert result["ttp_operations_count"] == 0
    assert result["excluded_count"] == 0
    assert result["ttp_heatmap"]["uncatalogued"] == []
    # engage_coverage sigue mostrando el catalogo completo de Goals/
    # Approaches/Activities "engagement" (mismo criterio que las
    # columnas del heatmap, siempre presentes) -- lo que tiene que dar
    # cero es el conteo de cada actividad, no la estructura en si.
    all_counts = [
        activity["operation_count"]
        for goal in result["engage_coverage"]
        for approach in goal["approaches"]
        for activity in approach["activities"]
    ]
    assert all_counts and all(count == 0 for count in all_counts)
    assert result["plugin_kind_counts"]["unclassified_count"] == 0


# -- _portfolio_asset_coverage(): inventario, plan y cobertura -------------


def test_portfolio_asset_coverage_counts_distinct_operations_and_separates_uncovered_from_not_targeted():
    covered = Asset(identifier="ASSET-CRIT", name="ERP crítico", asset_type="service", criticality="critical")
    planned_critical = Asset(identifier="ASSET-CRIT-SIN-CAP", name="Base crítica", asset_type="service", criticality="critical")
    planned_without_capacity = Asset(identifier="ASSET-HIGH", name="Correo", asset_type="service", criticality="high")
    never_planned = Asset(identifier="ASSET-LOW", name="Impresora", asset_type="device", criticality="low")
    op1 = _make_operation(
        name="Con cobertura",
        adversary_profile=AdversaryProfile(name="Actor", target_assets=[covered.identifier]),
    )
    # Dos bindings de la misma operación siguen contando como una sola.
    op1.plugins.extend(
        [
            PluginBinding(plugin_id="decoy-1", surface="network", protected_asset_ids=[covered.identifier]),
            PluginBinding(plugin_id="decoy-2", surface="network", protected_asset_ids=[covered.identifier]),
        ]
    )
    op2 = _make_operation(
        name="Objetivo sin capacidad",
        adversary_profile=AdversaryProfile(
            name="Actor", target_assets=[planned_without_capacity.identifier, planned_critical.identifier]
        ),
    )

    coverage = _portfolio_asset_coverage(
        [op1, op2], [never_planned, planned_without_capacity, covered, planned_critical]
    )

    assert [(entry["asset"].identifier, len(entry["covered_operation_ids"])) for entry in coverage["covered"]] == [
        ("ASSET-CRIT", 1)
    ]
    assert [entry["asset"].identifier for entry in coverage["targeted_uncovered"]] == [
        "ASSET-CRIT-SIN-CAP",
        "ASSET-HIGH",
    ]
    assert [entry["asset"].identifier for entry in coverage["not_targeted"]] == ["ASSET-LOW"]


def test_portfolio_asset_coverage_keeps_free_text_references_visible_without_inventory_criticality():
    operation = _make_operation(
        adversary_profile=AdversaryProfile(name="Actor", target_assets=["Segmento manual"])
    )
    operation.plugins.append(
        PluginBinding(plugin_id="decoy-manual", surface="network", protected_asset_ids=["Otro manual"])
    )

    coverage = _portfolio_asset_coverage([operation], [])

    assert coverage["inventory_count"] == 0
    assert [(item["reference"], bool(item["target_operation_ids"]), bool(item["covered_operation_ids"])) for item in coverage["unresolved_references"]] == [
        ("Otro manual", False, True),
        ("Segmento manual", True, False),
    ]


def test_build_portfolio_uses_real_telemetry_bulk_query(tmp_path):
    # Fase 4 post-BlackHat (ver docs/roadmap.md): a diferencia de los
    # tests de arriba (con _FakeTelemetry, telemetria vacia), este usa
    # un TelemetryCollector/SQLiteTelemetryRepository reales para
    # confirmar que build_portfolio() de verdad refleja TTPs
    # observadas vía list_events_by_operation(), no solo que no explota.
    op1 = _make_operation(name="Op1", adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1078"]))
    op2 = _make_operation(name="Op2", adversary_profile=AdversaryProfile(name="APT2", expected_ttps=["T1078"]))
    telemetry = TelemetryCollector(repository=SQLiteTelemetryRepository(tmp_path / "telemetry.db"))
    telemetry.repository.append(_make_ttp_record(op1.id, "T1078"))
    # op2 no tiene telemetria: T1078 esperada pero no observada.

    result = build_portfolio([op1, op2], telemetry)

    cell = _cell(result["ttp_heatmap"], "T1078")
    assert cell["matched_count"] == 1
    assert cell["not_observed_count"] == 1
    assert cell["status"] == "matched"


def test_build_portfolio_reads_full_records_once_for_heatmap_and_metrics():
    operation = _make_operation(
        adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1078"])
    )

    class TrackingTelemetry:
        repository = object()

        def __init__(self):
            self.calls = []

        def list_events_by_operation(self, operation_ids):
            self.calls.append(operation_ids)
            return {operation.id: [_make_ttp_record(operation.id, "T1078")]}

    telemetry = TrackingTelemetry()

    result = build_portfolio([operation], telemetry)

    assert telemetry.calls == [[operation.id]]
    assert result["operational_metrics"]["event_count"] == 1
    assert _cell(result["ttp_heatmap"], "T1078")["matched_count"] == 1


# -- _portfolio_engage_coverage(): cuenta operaciones distintas, no bindings -


def test_engage_coverage_counts_distinct_operations_not_raw_bindings():
    # "Lures" (EAC0005) planificada dos veces en la MISMA operacion --
    # cuenta 1, no 2 (ver docstring de _portfolio_engage_coverage).
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(engage_activity_ids=["EAC0005"])))
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-2", surface="data", effect=DeceptionEffect(engage_activity_ids=["EAC0005"])))

    coverage = _portfolio_engage_coverage([op])

    counts = {
        activity["activity"].id: activity["operation_count"]
        for goal in coverage
        for approach in goal["approaches"]
        for activity in approach["activities"]
    }
    assert counts["EAC0005"] == 1


def test_engage_coverage_counts_across_different_operations():
    op1 = _make_operation(name="Op1")
    op1.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(engage_activity_ids=["EAC0005"])))
    op2 = _make_operation(name="Op2")
    op2.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(engage_activity_ids=["EAC0005"])))

    coverage = _portfolio_engage_coverage([op1, op2])

    counts = {
        activity["activity"].id: activity["operation_count"]
        for goal in coverage
        for approach in goal["approaches"]
        for activity in approach["activities"]
    }
    assert counts["EAC0005"] == 2


def test_engage_coverage_only_includes_engagement_goals_not_strategic():
    coverage = _portfolio_engage_coverage([])

    goal_kinds = {goal["goal"].kind for goal in coverage}
    assert goal_kinds == {"engagement"}


def test_engage_coverage_zero_count_for_unplanned_activity():
    coverage = _portfolio_engage_coverage([])

    counts = {
        activity["activity"].id: activity["operation_count"]
        for goal in coverage
        for approach in goal["approaches"]
        for activity in approach["activities"]
    }
    assert counts["EAC0005"] == 0


# -- measured_count / _portfolio_measured_effect_notes() (tercer item del ---
# -- backlog de Engage post-M12: efectividad medida en el Portafolio) -------


def _counts_by_activity(coverage):
    return {
        activity["activity"].id: (activity["operation_count"], activity["measured_count"])
        for goal in coverage
        for approach in goal["approaches"]
        for activity in approach["activities"]
    }


def test_measured_count_zero_when_no_binding_is_measured():
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(engage_activity_ids=["EAC0005"])))

    counts = _counts_by_activity(_portfolio_engage_coverage([op]))

    assert counts["EAC0005"] == (1, 0)


def test_measured_count_counts_the_operation_when_at_least_one_binding_is_measured():
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="funciono como esperado"),
        )
    )

    counts = _counts_by_activity(_portfolio_engage_coverage([op]))

    assert counts["EAC0005"] == (1, 1)


def test_measured_count_does_not_double_count_two_measured_bindings_same_operation():
    # Mismo denominador que operation_count (M13g): cuenta OPERACIONES,
    # no bindings sueltos -- dos bindings medidos en la MISMA operacion
    # siguen contando 1, no 2.
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="nota 1"),
        )
    )
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-2",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="nota 2"),
        )
    )

    counts = _counts_by_activity(_portfolio_engage_coverage([op]))

    assert counts["EAC0005"] == (1, 1)


def test_measured_count_across_operations_only_counts_measured_ones():
    op1 = _make_operation(name="Op1")
    op1.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="funciono"),
        )
    )
    op2 = _make_operation(name="Op2")
    op2.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(engage_activity_ids=["EAC0005"])))

    counts = _counts_by_activity(_portfolio_engage_coverage([op1, op2]))

    assert counts["EAC0005"] == (2, 1)


def test_measured_effect_notes_empty_when_nothing_measured():
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(engage_activity_ids=["EAC0005"])))

    assert _portfolio_measured_effect_notes([op]) == []


def test_measured_effect_notes_excludes_measured_bindings_without_engage_activities():
    # Fase 2 (measured_outcome) no exige tener actividades de Engage
    # cargadas -- esta seccion es especificamente sobre actividades de
    # Engage, asi que un binding medido sin ninguna actividad no
    # deberia aparecer en esta lista.
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(measured_outcome="medido pero sin actividad"))
    )

    assert _portfolio_measured_effect_notes([op]) == []


def test_measured_effect_notes_includes_real_text_and_operation_link():
    op = _make_operation(name="Operacion con nota real")
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="el atacante piso el senuelo", measured_by="fede"),
        )
    )

    notes = _portfolio_measured_effect_notes([op])

    assert len(notes) == 1
    assert notes[0]["operation_id"] == op.id
    assert notes[0]["operation_name"] == "Operacion con nota real"
    assert notes[0]["measured_outcome"] == "el atacante piso el senuelo"
    assert notes[0]["measured_by"] == "fede"
    assert notes[0]["activities"] == [get_activity("EAC0005")]


def test_measured_effect_notes_two_measured_bindings_same_operation_produce_two_rows():
    # A diferencia de measured_count (agregado por operacion), esta
    # lista es por binding -- dos bindings medidos en la MISMA
    # operacion producen dos notas distintas, cada una con su propio
    # texto real.
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="nota 1"),
        )
    )
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-2",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="nota 2"),
        )
    )

    notes = _portfolio_measured_effect_notes([op])

    assert {n["measured_outcome"] for n in notes} == {"nota 1", "nota 2"}


def test_measured_effect_notes_one_row_per_binding_not_per_activity():
    # Un binding con dos actividades no debe repetir el mismo texto
    # dos veces -- una fila con las dos actividades juntas.
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005", "EAC0004"], measured_outcome="una sola nota"),
        )
    )

    notes = _portfolio_measured_effect_notes([op])

    assert len(notes) == 1
    assert {a.id for a in notes[0]["activities"]} == {"EAC0005", "EAC0004"}


def test_measured_effect_notes_sorted_most_recent_first():
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-old",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="vieja", measured_at=now - timedelta(days=5)),
        )
    )
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-new",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="nueva", measured_at=now),
        )
    )

    notes = _portfolio_measured_effect_notes([op])

    assert [n["measured_outcome"] for n in notes] == ["nueva", "vieja"]


def test_measured_effect_notes_without_measured_at_sorts_last():
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-no-date",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="sin fecha"),
        )
    )
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-with-date",
            surface="data",
            effect=DeceptionEffect(
                engage_activity_ids=["EAC0005"], measured_outcome="con fecha", measured_at=datetime.now(timezone.utc)
            ),
        )
    )

    notes = _portfolio_measured_effect_notes([op])

    assert [n["measured_outcome"] for n in notes] == ["con fecha", "sin fecha"]


def test_build_portfolio_includes_measured_effect_notes(tmp_path):
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="real"),
        )
    )
    telemetry = TelemetryCollector(repository=SQLiteTelemetryRepository(tmp_path / "t.db"))

    portfolio = build_portfolio([op], telemetry)

    assert len(portfolio["measured_effect_notes"]) == 1
    assert portfolio["measured_effect_notes"][0]["measured_outcome"] == "real"


# -- _portfolio_plugin_kind_counts() / _resolve_portfolio_plugin_kind() -----


def test_resolve_portfolio_plugin_kind_prefers_explicit_kind_over_prefix():
    binding = PluginBinding(plugin_id="mi-decoy-custom", surface="network", plugin_kind="dolost")
    assert _resolve_portfolio_plugin_kind(binding) == "dolost"


def test_resolve_portfolio_plugin_kind_accepts_mock_and_honeytoken_explicit():
    # A diferencia de operations.py::_plugin_kind() (M12h, acotada a
    # dolost/buda), esta SI reconoce mock/honeytoken explicitos.
    assert _resolve_portfolio_plugin_kind(PluginBinding(plugin_id="x", surface="n", plugin_kind="mock")) == "mock"
    assert (
        _resolve_portfolio_plugin_kind(PluginBinding(plugin_id="x", surface="n", plugin_kind="honeytoken"))
        == "honeytoken"
    )


def test_resolve_portfolio_plugin_kind_falls_back_to_legacy_prefix():
    binding = PluginBinding(plugin_id="dolost-1", surface="network")
    assert _resolve_portfolio_plugin_kind(binding) == "dolost"


def test_resolve_portfolio_plugin_kind_unclassified_without_kind_or_prefix():
    binding = PluginBinding(plugin_id="custom-thing", surface="network")
    assert _resolve_portfolio_plugin_kind(binding) is None


def test_plugin_kind_counts_shows_all_registered_kinds_even_at_zero():
    counts = _portfolio_plugin_kind_counts([])

    kinds = {item["kind"] for item in counts["kinds"]}
    assert kinds == {"mock", "honeytoken", "dolost", "buda", "canarytoken", "opencanary", "playground"}
    assert all(item["count"] == 0 for item in counts["kinds"])
    assert counts["unclassified_count"] == 0


def test_plugin_kind_counts_aggregates_across_operations_with_readable_display_name():
    op1 = _make_operation(name="Op1")
    op1.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", plugin_kind="honeytoken"))
    op2 = _make_operation(name="Op2")
    op2.bind_plugin(PluginBinding(plugin_id="honeytoken-2", surface="data", plugin_kind="honeytoken"))
    op2.bind_plugin(PluginBinding(plugin_id="custom-unclassified", surface="data"))

    counts = _portfolio_plugin_kind_counts([op1, op2])

    by_kind = {item["kind"]: item for item in counts["kinds"]}
    assert by_kind["honeytoken"]["count"] == 2
    assert by_kind["honeytoken"]["display_name"] == "Honeytokens de archivo"
    assert counts["unclassified_count"] == 1


# -- Integracion: GET /operations/portfolio ----------------------------------


def _save(app, operation: Operation) -> Operation:
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


def test_portfolio_route_returns_200(client):
    response = client.get("/operations/portfolio")
    assert response.status_code == 200


def test_portfolio_empty_repository_says_so_explicitly(client):
    response = client.get("/operations/portfolio")
    text = response.data.decode()

    assert response.status_code == 200
    assert "Todav&iacute;a no hay operaciones creadas" in text
    assert "No hay fichas en el inventario" in text


def test_portfolio_operations_without_expected_ttps_says_so_explicitly(client, app):
    _save(app, _make_operation())

    response = client.get("/operations/portfolio")
    text = response.data.decode()

    assert response.status_code == 200
    assert "Ninguna operaci&oacute;n tiene TTPs esperadas cargadas todav&iacute;a" in text


def test_portfolio_shows_excluded_count_when_some_operations_lack_expected_ttps(client, app):
    _save(app, _make_operation(name="Con TTPs", adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1078"])))
    _save(app, _make_operation(name="Sin TTPs"))

    response = client.get("/operations/portfolio")
    text = response.data.decode()

    assert response.status_code == 200
    assert "2 operaci" in text
    assert "1 sin TTPs esperadas cargadas" in text


def test_portfolio_nav_link_present(client):
    response = client.get("/operations/")
    assert response.status_code == 200
    assert b'href="/operations/portfolio"' in response.data


def test_portfolio_has_executive_section_navigation_and_bulk_controls(client, app):
    op = _make_operation(
        adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1078"])
    )
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(
                engage_activity_ids=["EAC0005"], measured_outcome="resultado real"
            ),
        )
    )
    _save(app, op)
    text = client.get("/operations/portfolio").get_data(as_text=True)

    assert 'class="portfolio-section-nav" aria-label="Secciones del portafolio"' in text
    for section in ("operational-metrics", "heatmap", "engage", "effects", "plugins", "assets"):
        assert f'id="portfolio-{section}"' in text
    assert "data-portfolio-expand" in text and "data-portfolio-collapse" in text
    assert "setAllPortfolioSections" in text
    assert "Alcance y forma de c" in text


def test_portfolio_renders_asset_categories_and_deep_links(client, app):
    covered = Asset(identifier="ASSET-CRIT", name="ERP crítico", asset_type="service", criticality="critical")
    uncovered = Asset(identifier="ASSET-HIGH", name="Correo", asset_type="service", criticality="high")
    unplanned = Asset(identifier="ASSET-LOW", name="Impresora", asset_type="device", criticality="low")
    for asset in (covered, uncovered, unplanned):
        app.config["ASSET_REPOSITORY"].save(asset)

    op_with_capacity = _make_operation(
        name="Operación que cubre ERP",
        adversary_profile=AdversaryProfile(name="Actor", target_assets=[covered.identifier]),
    )
    op_with_capacity.plugins.extend(
        [
            PluginBinding(plugin_id="decoy-erp-1", surface="network", protected_asset_ids=[covered.identifier]),
            PluginBinding(plugin_id="decoy-erp-2", surface="network", protected_asset_ids=[covered.identifier]),
        ]
    )
    op_without_capacity = _make_operation(
        name="Operación que planifica correo",
        adversary_profile=AdversaryProfile(name="Actor", target_assets=[uncovered.identifier]),
    )
    _save(app, op_with_capacity)
    _save(app, op_without_capacity)

    text = client.get("/operations/portfolio").get_data(as_text=True)

    assert "Activos cubiertos por alguna operaci&oacute;n" in text
    assert "Objetivos sin cobertura" in text
    assert "Activos que no son objetivo de ninguna operaci&oacute;n" in text
    assert "ERP crítico" in text and "Correo" in text and "Impresora" in text
    assert f'href="/operations/{op_with_capacity.id}#tab-plugins"' in text
    assert f'href="/operations/{op_without_capacity.id}#tab-profile"' in text
    assert "(1)" in text


def test_portfolio_renders_unresolved_asset_references_separately(client, app):
    operation = _make_operation(
        adversary_profile=AdversaryProfile(name="Actor", target_assets=["Segmento manual"])
    )
    operation.plugins.append(
        PluginBinding(plugin_id="decoy-manual", surface="network", protected_asset_ids=["Servicio manual"])
    )
    _save(app, operation)

    text = client.get("/operations/portfolio").get_data(as_text=True)

    assert "Referencias sin ficha de inventario" in text
    assert "Segmento manual" in text and "Servicio manual" in text


def test_portfolio_shows_transverse_metrics_with_source_period_and_scope(client, app):
    operation = _save(
        app,
        _make_operation(
            name="Operacion medible",
            adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1078"]),
        ),
    )
    app.config["TELEMETRY_COLLECTOR"].repository.append(
        _make_ttp_record(operation.id, "T1078")
    )

    text = client.get("/operations/portfolio").get_data(as_text=True)

    assert 'id="portfolio-operational-metrics"' in text
    assert "Operacion medible" in text
    # La atribucion de fuente sigue estando; dentro de la propia app decir
    # "Telemetria <producto>" era redundante (fase 4 del renombre).
    assert "Fuente: Telemetr&iacute;a" in text
    assert "Alcance: las 1 operaciones actuales" in text
    assert "historial persistido" in text
    assert "estad&iacute;sticas internas de los motores" in text


# -- Integracion: efectividad medida (tercer item del backlog de Engage) ----


def test_portfolio_shows_empty_state_when_nothing_measured(client, app):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(engage_activity_ids=["EAC0005"])))
    _save(app, op)

    response = client.get("/operations/portfolio")
    text = response.data.decode()

    assert response.status_code == 200
    assert "Todav&iacute;a ning&uacute;n plugin vinculado a una actividad de Engage tiene un" in text


def test_portfolio_shows_real_measured_outcome_text_with_operation_link(client, app):
    op = _make_operation(name="Operacion con medicion real")
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(
                engage_activity_ids=["EAC0005"], measured_outcome="el atacante piso el senuelo dos veces", measured_by="fede"
            ),
        )
    )
    _save(app, op)

    response = client.get("/operations/portfolio")
    text = response.data.decode()

    assert "el atacante piso el senuelo dos veces" in text
    assert "fede" in text
    assert f'href="/operations/{op.id}#tab-plugins"' in text


def test_portfolio_measured_count_badge_appears_next_to_planned_count(client, app):
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="funciono"),
        )
    )
    _save(app, op)

    response = client.get("/operations/portfolio")
    text = response.data.decode()

    assert "medida: 1" in text


def test_portfolio_no_measured_badge_when_activity_planned_but_not_measured(client, app):
    # "medida:" en si aparece siempre en la leyenda explicativa
    # (estatica) -- lo que no deberia aparecer es el badge puntual por
    # actividad, que lleva este title especifico.
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(engage_activity_ids=["EAC0005"])))
    _save(app, op)

    response = client.get("/operations/portfolio")
    text = response.data.decode()

    assert 'title="Con resultado medido' not in text


def test_portfolio_does_not_show_synthetic_effectiveness_percentage(client, app):
    # Restriccion explicita del pedido: measured_outcome es texto
    # libre, no hay ningun "% de efectividad" honesto que calcular por
    # actividad -- confirma que build_portfolio() no fabrica ese
    # numero (busca un patron tipo "73%" que no deberia existir en
    # ningun lado de la pagina).
    import re

    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(engage_activity_ids=["EAC0005"], measured_outcome="funciono"),
        )
    )
    _save(app, op)

    response = client.get("/operations/portfolio")
    text = response.data.decode()

    assert re.search(r"\d+\s*%", text) is None
    assert "no una puntuaci" in text and "xito" in text

"""Sección "Coherencia de la ficción" dentro del tab "Ensayo en seco"
(referencia declarada: CounterCraft). Ver docstring de
`apate.web._narrative_coherence` para el diseño completo."""

from __future__ import annotations

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación de coherencia"),
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=kwargs.pop("narrative", Narrative(name="Narrativa")),
        **kwargs,
    )


def test_section_present_within_dryrun_tab(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    dryrun_start = text.index('id="tab-dryrun"')
    coherence_start = text.index("Coherencia de la ficci&oacute;n")
    # "operation-context-upload-form" aparece dos veces (el <form> real de
    # Preparación, más temprano en el documento, y un getElementById() de
    # ese mismo id en el JS al final) -- se usa la referencia del script,
    # inequívocamente posterior a las dos secciones del tab de ensayo.
    dryrun_end = text.index("getElementById('operation-context-upload-form')")
    assert dryrun_start < coherence_start < dryrun_end


def test_empty_operation_shows_empty_state(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "coherencia de la ficci&oacute;n" in text.lower() or "coherencia de la ficción" in text.lower()
    assert "Completar narrativa" in text


def test_rich_operation_shows_all_pieces_side_by_side(client, app):
    operation = _operation(
        narrative=Narrative(name="N", description="Cierre de trimestre", psychological_impact="Urgencia"),
        adversary_profile=AdversaryProfile(name="Actor", target_assets=["Backups financieros"]),
    )
    operation.scenarios.append(Scenario(description="Detectar exfiltración de backups financieros"))
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            config={"decoys": [{"Hostname": "FileServerBackup", "Description": "Servidor de backups financieros"}]},
        )
    )
    operation.plugins.append(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "Cierre de trimestre" in text
    assert "Backups financieros" in text
    assert "FileServerBackup" in text
    assert "Servidor de backups financieros" in text
    assert "Detectar exfiltraci" in text


def test_narrative_without_employees_check_rendered(client, app):
    operation = _operation(narrative=Narrative(name="N", description="Historia real con contenido"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "ning&uacute;n protagonista humano" in text or "ningún protagonista humano" in text
    assert "Informativo" in text


def test_no_checks_shows_clear_state(client, app):
    # Solo un escenario, sin narrativa/activos/empleados/infraestructura/
    # documentos -- alcanza para `has_content=True` (hay algo que
    # mostrar) sin que dispare ninguno de los chequeos heurísticos (todos
    # exigen la presencia de al menos dos piezas para comparar).
    operation = _operation()
    operation.scenarios.append(Scenario(description="Escenario sin nada más cargado"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "Sin observaciones" in text


def test_tab_badge_counts_both_dry_run_findings_and_coherence_checks(client, app):
    operation = _operation(narrative=Narrative(name="N", description="Historia real con contenido"))
    # Capacidad totalmente desconectada -> 1 finding de ensayo en seco (isolated_capability).
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    # 1 hallazgo estructural (isolated_capability) + 1 chequeo de coherencia
    # (narrative_without_employees), visibles en el tab consolidado.
    assert 'data-tab="tab-review" aria-controls="tab-review">Preparaci&oacute;n y revisi&oacute;n <span class="tab-count">0/8 prep. &middot; 2 rev.</span>' in text


def test_explicitly_disclaims_scoring_and_llm_judgment(client, app):
    operation = _operation(narrative=Narrative(name="N", description="x"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()
    coherence_section = text[text.index("narrative-coherence-title") : text.index("</section>", text.index("narrative-coherence-title"))]

    assert "no hay ning" in coherence_section.lower()
    assert "score" in coherence_section.lower()
    assert "llm" in coherence_section.lower()

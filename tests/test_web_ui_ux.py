"""Regresiones estructurales de la mejora transversal de UI/UX."""

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario


def _operation(app, *, status: str = "planning") -> Operation:
    operation = Operation(
        name=f"Operacion {status}",
        adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa", description="Historia"),
    )
    if status == "active":
        operation.mark_active()
    elif status == "compromised":
        operation.mark_active()
        operation.mark_compromised()
    elif status == "closed":
        operation.close()
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


def test_base_has_collapsible_navigation_and_shared_ui_script(client):
    html = client.get("/operations/").get_data(as_text=True)
    assert 'data-nav-toggle' in html
    assert 'aria-controls="sidebar-navigation"' in html
    assert '/static/ui.js' in html
    assert html.index('/static/ui.js') < html.index('/static/loading.js')


def test_flash_is_accessible_and_dismissible(client):
    response = client.post("/operations/no-existe/transition", data={"to": "active"})
    assert response.status_code == 404
    with client.session_transaction() as session:
        session["_flashes"] = [("error", "Mensaje de prueba")]
    html = client.get("/operations/").get_data(as_text=True)
    assert 'role="alert"' in html
    assert 'data-flash-dismiss' in html


def test_404_uses_apate_shell_and_spanish_recovery_actions(client):
    response = client.get("/ruta-inexistente")
    html = response.get_data(as_text=True)

    assert response.status_code == 404
    assert 'lang="es"' in html
    assert "No encontramos esta página" in html
    assert "Ir a Operaciones" in html
    assert 'id="sidebar-navigation"' in html


def test_operation_state_actions_only_show_valid_transitions(client, app):
    expected = {
        "planning": ('value="active"', 'value="closed"'),
        "active": ('value="compromised"', 'value="closed"'),
        "compromised": ('value="closed"',),
        "closed": (),
    }
    forbidden = {
        "planning": ('value="compromised"',),
        "active": ('value="active"',),
        "compromised": ('value="active"', 'value="compromised"'),
        "closed": ('value="active"', 'value="compromised"', 'value="closed"'),
    }
    for status in expected:
        operation = _operation(app, status=status)
        html = client.get(f"/operations/{operation.id}").get_data(as_text=True)
        header = html.split('<header class="operation-context">', 1)[1].split("</header>", 1)[0]
        assert all(value in header for value in expected[status])
        assert all(value not in header for value in forbidden[status])


def test_close_is_confirmed_as_irreversible(client, app):
    operation = _operation(app)
    html = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    assert 'data-confirm="Cerrar es irreversible:' in html
    assert "Reoperar" in html


def test_tabs_have_accessible_relationships_and_progress_indicators(client, app):
    operation = _operation(app)
    html = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    assert 'id="tab-control-design"' in html
    assert 'aria-controls="tab-design"' in html
    assert 'aria-labelledby="tab-control-design"' in html
    assert 'class="tab-count">0 esc. / 0 cap.' in html
    assert 'class="design-step-nav"' in html
    assert '1 TTP</span>' in html
    assert '✓</span>' in html
    assert "aria-selected" in html  # gestionado dinamicamente por el script
    assert "ArrowRight" in html and "ArrowLeft" in html


def test_long_editorial_forms_guard_unsaved_changes(client, app):
    operation = _operation(app)
    detail = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    assert 'action="/operations/' in detail and 'data-guard-unsaved' in detail
    assert 'id="operation-form" novalidate data-guard-unsaved' in client.get("/operations/new").get_data(as_text=True)
    assert 'id="rules-form" data-guard-unsaved' in client.get("/rules/").get_data(as_text=True)


def test_shared_ui_script_contains_dirty_guard_and_uniform_confirm(client):
    script = client.get("/static/ui.js").get_data(as_text=True)
    assert "beforeunload" in script
    assert "data-confirm" in script
    assert "window.confirm" in script
    assert "event.defaultPrevented" in script


def test_base_has_preferences_palette_skip_link_and_dialogs(client):
    html = client.get("/operations/").get_data(as_text=True)
    assert 'class="skip-link"' in html
    assert "data-theme-toggle" in html and "data-density-toggle" in html
    assert 'data-label-comfortable="Vista cómoda"' in html
    assert "data-command-dialog" in html and "data-confirm-dialog" in html
    assert 'class="ui-preferences-more"' in html
    assert "Vista y ayuda" in html


def test_visible_operation_language_hides_internal_milestones_and_class_names(client, app):
    operation = _operation(app, status="active")
    list_html = client.get("/operations/").get_data(as_text=True)
    detail_html = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    portfolio_html = client.get("/operations/portfolio").get_data(as_text=True)

    assert "RuleEngine.history" not in list_html
    assert "SQLiteTelemetryRepository" not in portfolio_html
    assert "PluginBinding" not in portfolio_html
    assert "M13a" not in detail_html and "M12f" not in detail_html
    assert "Capacidades vinculadas" in detail_html


def test_command_palette_uses_the_new_information_architecture(client):
    html = client.get("/operations/").get_data(as_text=True)
    palette = html.split('class="command-results"', 1)[1].split("</div>", 1)[0]

    assert "Cat&aacute;logo de capacidades" in palette
    assert "Salud y configuraci&oacute;n" in palette
    assert 'data-command-keywords=' in palette
    assert "Herramientas" not in palette


def test_ui_script_persists_preferences_and_uses_chord_shortcuts(client):
    script = client.get("/static/ui.js").get_data(as_text=True)
    assert "apate-theme" in script and "apate-density" in script
    assert "commandPrefix" in script
    assert "pendingSubmitter" in script


def test_base_has_presentation_mode_and_contextual_glossary(client):
    html = client.get("/operations/").get_data(as_text=True)

    assert html.count("data-presentation-toggle") == 2
    assert "data-help-open" in html and "data-help-dialog" in html
    assert "Rules of Engagement" in html
    assert "no las acciones manuales" in html
    assert "<dt>Capacidad</dt>" in html
    assert "<dt>Despliegue</dt>" in html


def test_shared_ui_persists_presentation_and_localizes_semantic_times(client, app):
    operation = _operation(app)
    html = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    script = client.get("/static/ui.js").get_data(as_text=True)

    assert 'time data-local-time datetime="' in html
    assert "apate-presentation" in script
    assert "Intl.DateTimeFormat" in script
    assert "Intl.RelativeTimeFormat" in script
    assert "date.toISOString" in script


def test_guarded_forms_get_explicit_local_undo_without_server_rollback(client):
    script = client.get("/static/ui.js").get_data(as_text=True)
    form = client.get("/rules/").get_data(as_text=True)

    assert "editor-undo-toolbar" in script
    assert "dataset.undoLabel" in script and "dataset.undoStatus" in script
    assert all(
        text not in script
        for text in (
            "Vista cómoda",
            "Vista compacta",
            "Tema oscuro",
            "Tema claro",
            "Deshacer última edición",
            "Solo revierte campos locales",
            "Última edición local revertida",
        )
    )
    assert 'data-undo-label="Deshacer última edición"' in form
    assert "nunca acciones ya ejecutadas" in form
    assert "undoStack" in script and "restoreField" in script


def test_preference_and_undo_labels_follow_the_active_locale(client, app):
    app.config["APATE_LOCALE"] = "en"

    base = client.get("/operations/").get_data(as_text=True)
    form = client.get("/rules/").get_data(as_text=True)

    assert 'data-label-comfortable="Comfortable view"' in base
    assert 'data-label-compact="Compact view"' in base
    assert 'data-undo-label="Undo last edit"' in form
    assert "Last local edit reverted. Saving remains an explicit decision." in form


def test_operation_form_has_ttp_search_and_final_review(client):
    html = client.get("/operations/new").get_data(as_text=True)
    assert 'id="ttp-picker-search"' in html
    assert 'id="ttp-picker-selected"' in html
    assert 'id="ttp-picker-count"' in html
    assert 'id="wizard-review-summary"' in html
    steps = html.split('<div class="wizard-step')
    assert "wizard-review-summary" not in steps[2]
    assert "wizard-review-summary" in steps[3]


def test_operation_detail_has_source_labelled_timeline_and_typed_close_confirmation(client, app):
    operation = _operation(app)
    html = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    assert 'id="operation-timeline"' in html
    assert 'data-timeline-filter="telemetry"' in html
    assert 'data-timeline-source="operation"' in html
    assert f'data-confirm-name="{operation.name}"' in html


def test_portfolio_heatmap_uses_buttons_and_accessible_dialog(client, app):
    _operation(app)
    html = client.get("/operations/portfolio").get_data(as_text=True)
    assert '<button type="button" class="ttp-cell' in html
    assert 'id="heatmap-dialog"' in html
    assert 'aria-label="Resumen ejecutivo"' in html
    assert "se interpreta?" in html


def test_responsive_css_hides_collapsed_preferences_and_heatmap_details(client):
    css = client.get("/static/theme.css").get_data(as_text=True)
    assert ".sidebar nav.mobile-open + .ui-preferences" in css
    assert ".heatmap-detail[hidden]" in css


def test_operation_detail_uses_valid_consistent_action_links(client, app):
    operation = _operation(app, status="closed")
    html = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert 'class="button operation-secondary-action"' in html
    assert 'class="button small detail-action-link"' in html
    assert '<a class="button" href="' in html and 'Reoperar</a>' in html
    resources = html.split('<section class="operation-resources', 1)[1].split("</section>", 1)[0]
    assert "<button" not in resources  # los links de descarga ya no anidan botones invalidos
    assert "operation-tabs" in html and 'aria-label="Secciones de la operaci&oacute;n"' in html


def test_operation_center_precedes_secondary_metrics_and_exposes_operational_cycle(client, app):
    operation = _operation(app)
    html = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert html.index('id="operation-center"') < html.index('id="operation-metrics"')
    center = html.split('id="operation-center"', 1)[1].split("</section>", 1)[0]
    assert "Siguiente acci&oacute;n permitida" in center
    assert "Requiere atenci&oacute;n" in center
    assert "Actividad reciente" in center
    assert center.count('class="operation-cycle-step ') == 1
    assert "Diseño" in center
    assert "Estados derivados de evidencia, no un score" in center
    assert "Estado inicial: planning" not in center
    assert "Estado inicial: En preparación" in center


def test_operation_center_derives_permitted_action_from_state_and_evidence(client, app):
    planning = _operation(app)
    planning_html = client.get(f"/operations/{planning.id}").get_data(as_text=True)
    planning_center = planning_html.split('id="operation-center"', 1)[1].split("</section>", 1)[0]
    assert "Completar diseño" in planning_center
    assert "El diseño reúne perfil" in planning_center

    active = _operation(app, status="active")
    active.bind_plugin(PluginBinding(plugin_id="mock-demo", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(active)
    active_html = client.get(f"/operations/{active.id}").get_data(as_text=True)
    active_center = active_html.split('id="operation-center"', 1)[1].split("</section>", 1)[0]
    assert "Abrir telemetría" in active_center
    assert "No hay eventos persistidos todavía" in active_center

    closed = _operation(app, status="closed")
    closed_html = client.get(f"/operations/{closed.id}").get_data(as_text=True)
    closed_center = closed_html.split('id="operation-center"', 1)[1].split("</section>", 1)[0]
    assert "Reoperar" in closed_center
    assert "su estado es irreversible" in closed_center


def test_operation_center_adds_validation_and_rules_stops_when_design_is_linked(client, app):
    operation = _operation(app)
    operation.add_scenario(Scenario(description="Escenario", related_ttps=["T1046"]))
    operation.bind_plugin(PluginBinding(plugin_id="mock-demo", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    html = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    center = html.split('id="operation-center"', 1)[1].split("</section>", 1)[0]
    assert "Validar el diseño" in center
    assert "No hay reglas globales que apliquen a esta operación" in center
    assert 'href="#tab-review"' in center
    assert '<li><a href="/rules/"><strong>Reglas</strong>' in center
    assert 'href="/rules/"' in center


def test_operation_center_cycle_is_horizontally_contained_on_small_screens(client):
    css = client.get("/static/theme.css").get_data(as_text=True)

    assert ".operation-cycle-scroll" in css and "overflow-x: auto" in css
    assert ".operation-center-grid { grid-template-columns: minmax(0, 1fr); }" in css
    assert "grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));" in css

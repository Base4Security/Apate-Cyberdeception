"""Alcance de las reglas globales dentro del detalle de una operación."""

import json
import sqlite3
from datetime import datetime, timezone

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.rules import Action, ActionKind, RejectedAction, RejectionKind


def _operation(*, plugin_ids=()):
    operation = Operation(
        name="Operación para reglas",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    for plugin_id in plugin_ids:
        operation.plugins.append(PluginBinding(plugin_id=plugin_id, surface="network"))
    return operation


def _write_rules(app):
    app.config["APATE_RULES_PATH"].write_text(
        """rules:
  - name: Señuelo financiero observado
    when:
      event_type: interaction
      plugin_id: honey-finanzas
    then:
      - action: rotate
        plugin_id: honey-finanzas
  - name: Capacidad ajena observada
    when:
      event_type: interaction
      plugin_id: honey-ajeno
    then:
      - action: retire
        plugin_id: honey-ajeno
  - name: Cerrar al vencimiento
    when:
      closure_due: true
    then:
      - action: transition
        to: closed
""",
        encoding="utf-8",
    )


def test_operation_shows_rules_that_apply_and_do_not_apply_by_plugin_id(client, app):
    _write_rules(app)
    operation = _operation(plugin_ids=("honey-finanzas",))
    app.config["OPERATION_REPOSITORY"].save(operation)

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert "Reglas del motor de decisión" in body
    assert "Señuelo financiero observado" in body
    assert "Capacidad ajena observada" in body
    assert "Cerrar al vencimiento" in body
    assert body.count("Aplicaría en esta operación") == 2
    assert body.count("No aplica a esta operación") == 1
    assert "honey-ajeno" in body
    assert "no está vinculada a esta operación" in body
    assert "telemetría recibida por la ingesta periódica o los puentes externos" in body


def test_operation_without_capabilities_renders_global_rules_without_breaking(client, app):
    _write_rules(app)
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert "Capacidad ajena observada" in body
    assert body.count("No aplica a esta operación") == 2
    assert body.count("Aplicaría en esta operación") == 1


def test_invalid_global_rules_are_reported_without_breaking_operation_detail(client, app):
    app.config["APATE_RULES_PATH"].write_text("rules: [", encoding="utf-8")
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")

    assert response.status_code == 200
    assert "No se pudo cargar el documento global de reglas" in response.get_data(as_text=True)


def test_the_rules_section_links_to_the_editor(client, app):
    """Mostrar las reglas sin dejar llegar al editor deja al operador
    enterado de que existen y todavía teniendo que ir a buscarlas: es
    justamente lo que este hito venía a evitar. El texto del enlace cambia
    según haya reglas o no, porque "editar" no aplica a un documento vacío.
    """

    from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement

    operation = Operation(
        name="Enlace al editor",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="N"),
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    seccion = body[body.index("operation-rules-title") : body.index("Editar reglas de interacci")]

    assert 'href="/rules/"' in seccion
    assert "Escribir la primera regla" in seccion


def test_operation_detail_labels_all_rejection_kinds_and_keeps_legacy_rows_visible(client, app):
    operation = _operation(plugin_ids=("capacidad-roe", "capacidad-tope", "capacidad-error"))
    app.config["OPERATION_REPOSITORY"].save(operation)
    repository = app.config["RULE_DECISION_REPOSITORY"]
    timestamp = datetime.now(timezone.utc)
    for kind, plugin_id in (
        (RejectionKind.ROE, "capacidad-roe"),
        (RejectionKind.CASCADE_LIMIT, "capacidad-tope"),
        (RejectionKind.EXECUTION_ERROR, "capacidad-error"),
    ):
        repository.append_rejection(
            operation.id,
            RejectedAction(
                rule_name=f"Regla {kind.value}",
                action=Action(kind=ActionKind.ROTATE, plugin_id=plugin_id),
                reason=f"Motivo de {kind.value}",
                kind=kind,
                timestamp=timestamp,
                triggering_event_id=f"evento-{kind.value}",
            ),
        )

    connection = sqlite3.connect(repository._path)
    try:
        connection.execute(
            """INSERT INTO rejected_rule_actions
            (id, operation_id, rule_name, action_json, reason, timestamp, rejection_kind, triggering_event_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "rechazo-anterior",
                operation.id,
                "Regla anterior",
                json.dumps({"action": "retire", "plugin_id": "capacidad-roe"}),
                "Prohibida por Rules of Engagement: ['retire']",
                timestamp.isoformat(),
                None,
                None,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert "Acciones rechazadas" in body
    assert "capacidad-error" in body
    assert "evento-execution_error" in body
    assert '<span class="tag" data-rejection-kind="roe"><code>roe</code> · Reglas de interacción</span>' in body
    assert '<span class="tag" data-rejection-kind="cascade_limit"><code>cascade_limit</code> · Tope de cascada</span>' in body
    assert '<span class="tag" data-rejection-kind="execution_error"><code>execution_error</code> · Error de ejecución</span>' in body
    assert "Regla anterior" in body

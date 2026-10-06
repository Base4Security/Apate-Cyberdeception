"""Integración web de la Fase 5: contexto explícito por operación."""

import io

from apate.core import (
    AdversaryProfile,
    BehaviorContextSource,
    BehaviorContextStatus,
    Narrative,
    Operation,
    RulesOfEngagement,
)
from apate.web import _behavior_context as context_service
from apate.web.blueprints import plugins as plugins_module


def _operation() -> Operation:
    return Operation(
        name="Operación UEBA",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )


def _save_operation(app) -> Operation:
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


def _source(app, *, status=BehaviorContextStatus.PENDING, operation_id=None):
    source = BehaviorContextSource(
        name="Contexto Finanzas",
        data={"usernames": ["alice"], "work_hours": {"alice": [8, 17]}},
        provenance="EVTX:security.evtx",
        pending_operation_id=operation_id,
    )
    if status == BehaviorContextStatus.ACTIVE:
        source.confirm()
    app.config["BEHAVIOR_CONTEXT_REPOSITORY"].save(source)
    return source


def test_library_shows_sources_provenance_status_and_integrity(app, client):
    source = _source(app, status=BehaviorContextStatus.ACTIVE)

    text = client.get("/capabilities/behavior-context").get_data(as_text=True)

    assert source.name in text
    assert source.provenance in text
    assert source.integrity_sha256 in text
    assert "verificada" in text
    assert "Extraer no es utilizar" in text


def test_upload_creates_pending_candidate_without_selecting_operation(app, client, monkeypatch):
    operation = _save_operation(app)
    monkeypatch.setattr(plugins_module, "count_evtx_records", lambda _path: 2)
    monkeypatch.setattr(
        context_service,
        "_extract_ueba_from_evtx",
        lambda _path: {"usernames": ["alice"], "source_ips": ["10.0.0.5"]},
    )

    response = client.post(
        "/capabilities/behavior-context/upload",
        data={"name": "Candidato global", "file": (io.BytesIO(b"evtx"), "audit.evtx")},
        content_type="multipart/form-data",
    )
    body = response.get_data(as_text=True)
    sources = list(app.config["BEHAVIOR_CONTEXT_REPOSITORY"].list())

    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    assert "records:2" in body and "candidate:" in body
    assert len(sources) == 1
    assert sources[0].status == BehaviorContextStatus.PENDING
    assert sources[0].pending_operation_id is None
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).behavior_context_source_ids == []
    assert not list(app.config["BEHAVIOR_CONTEXT_UPLOAD_DIR"].glob("*"))


def test_upload_rejects_non_evtx_before_extraction(app, client):
    operation = _save_operation(app)
    response = client.post(
        "/capabilities/behavior-context/upload",
        data={"file": (io.BytesIO(b"text"), "audit.txt")},
        content_type="multipart/form-data",
    )
    operation_response = client.post(
        f"/operations/{operation.id}/preparation/behavior-context/upload",
        data={"file": (io.BytesIO(b"text"), "audit.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 302
    assert operation_response.status_code == 302
    assert operation_response.location.endswith("#tab-preparation")
    assert list(app.config["BEHAVIOR_CONTEXT_REPOSITORY"].list()) == []


def test_upload_rejects_evtx_over_configured_limit_and_removes_temporary_file(app, client, monkeypatch):
    monkeypatch.setattr(context_service, "MAX_EVTX_BYTES", 3)

    response = client.post(
        "/capabilities/behavior-context/upload",
        data={"file": (io.BytesIO(b"four"), "audit.evtx")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 302
    assert not list(app.config["BEHAVIOR_CONTEXT_UPLOAD_DIR"].glob("*"))
    assert list(app.config["BEHAVIOR_CONTEXT_REPOSITORY"].list()) == []


def test_library_confirmation_requires_second_explicit_action(app, client):
    source = _source(app)

    client.post(f"/capabilities/behavior-context/{source.id}/confirm")
    assert app.config["BEHAVIOR_CONTEXT_REPOSITORY"].get(source.id).status == BehaviorContextStatus.PENDING

    client.post(
        f"/capabilities/behavior-context/{source.id}/confirm",
        data={"confirm": "CONFIRMAR"},
    )
    assert app.config["BEHAVIOR_CONTEXT_REPOSITORY"].get(source.id).status == BehaviorContextStatus.ACTIVE


def test_catalog_use_opens_preparation_without_mutating_operation(app, client):
    operation = _save_operation(app)
    source = _source(app, status=BehaviorContextStatus.ACTIVE)

    response = client.get(
        f"/capabilities/use?operation_id={operation.id}&resource_type=contexto&resource_id={source.id}"
    )

    assert response.status_code == 302
    assert f"catalog_context_id={source.id}" in response.location
    assert response.location.endswith("#tab-preparation")
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).behavior_context_source_ids == []


def test_operation_selection_accepts_only_active_integral_sources_and_audits(app, client):
    operation = _save_operation(app)
    source = _source(app, status=BehaviorContextStatus.ACTIVE)

    response = client.post(
        f"/operations/{operation.id}/preparation/behavior-context/select",
        data={"source_ids": source.id},
    )

    assert response.status_code == 302
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).behavior_context_source_ids == [source.id]
    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert actions[-1].action == "behavior_context_select"
    assert actions[-1].target == source.id

    source.data["usernames"].append("alterado")
    app.config["BEHAVIOR_CONTEXT_REPOSITORY"].save(source)
    client.post(
        f"/operations/{operation.id}/preparation/behavior-context/select",
        data={"source_ids": source.id},
    )
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).behavior_context_source_ids == [source.id]
    assert len(app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)) == 1


def test_operation_candidate_confirmation_links_only_after_review(app, client):
    operation = _save_operation(app)
    source = _source(app, operation_id=operation.id)
    route = f"/operations/{operation.id}/preparation/behavior-context/{source.id}/confirm"

    client.post(route)
    assert app.config["BEHAVIOR_CONTEXT_REPOSITORY"].get(source.id).status == BehaviorContextStatus.PENDING
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).behavior_context_source_ids == []

    client.post(route, data={"confirm": "CONFIRMAR"})
    assert app.config["BEHAVIOR_CONTEXT_REPOSITORY"].get(source.id).status == BehaviorContextStatus.ACTIVE
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).behavior_context_source_ids == [source.id]
    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert actions[-1].action == "behavior_context_confirm"


def test_operation_cannot_confirm_candidate_owned_by_another_operation(app, client):
    operation = _save_operation(app)
    other = _save_operation(app)
    source = _source(app, operation_id=other.id)

    response = client.post(
        f"/operations/{operation.id}/preparation/behavior-context/{source.id}/confirm",
        data={"confirm": "CONFIRMAR"},
    )

    assert response.status_code == 404
    assert app.config["BEHAVIOR_CONTEXT_REPOSITORY"].get(source.id).status == BehaviorContextStatus.PENDING


def test_archiving_shared_source_preserves_operation_reference(app, client):
    operation = _save_operation(app)
    source = _source(app, status=BehaviorContextStatus.ACTIVE)
    operation.select_behavior_context([source.id])
    app.config["OPERATION_REPOSITORY"].save(operation)

    client.post(f"/capabilities/behavior-context/{source.id}/archive")

    assert app.config["BEHAVIOR_CONTEXT_REPOSITORY"].get(source.id).status == BehaviorContextStatus.ARCHIVED
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).behavior_context_source_ids == [source.id]
    text = client.get(f"/operations/{operation.id}#tab-preparation").get_data(as_text=True)
    assert "Referencias preservadas" in text
    assert source.name in text


def test_pending_candidate_can_be_discarded_but_active_source_cannot(app, client):
    operation = _save_operation(app)
    pending = _source(app, operation_id=operation.id)
    active = _source(app, status=BehaviorContextStatus.ACTIVE)

    client.post(f"/operations/{operation.id}/preparation/behavior-context/{pending.id}/discard")
    response = client.post(f"/capabilities/behavior-context/{active.id}/discard")

    try:
        app.config["BEHAVIOR_CONTEXT_REPOSITORY"].get(pending.id)
        pending_exists = True
    except KeyError:
        pending_exists = False
    assert not pending_exists
    assert response.status_code == 302
    assert app.config["BEHAVIOR_CONTEXT_REPOSITORY"].get(active.id).status == BehaviorContextStatus.ACTIVE


def test_operation_preparation_renders_available_selected_and_pending_sources(app, client):
    operation = _save_operation(app)
    selected = _source(app, status=BehaviorContextStatus.ACTIVE)
    selected.name = "Fuente seleccionada"
    app.config["BEHAVIOR_CONTEXT_REPOSITORY"].save(selected)
    available = _source(app, status=BehaviorContextStatus.ACTIVE)
    available.name = "Fuente disponible"
    app.config["BEHAVIOR_CONTEXT_REPOSITORY"].save(available)
    pending = _source(app, operation_id=operation.id)
    pending.name = "Candidato pendiente"
    app.config["BEHAVIOR_CONTEXT_REPOSITORY"].save(pending)
    operation.select_behavior_context([selected.id])
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}?catalog_context_id={available.id}").get_data(as_text=True)

    assert "Fuente seleccionada" in text and 'checked' in text
    assert "Fuente disponible" in text
    assert "Candidato pendiente" in text
    assert "Confirmar y seleccionar" in text
    assert "Recurso sugerido desde el Cat" in text

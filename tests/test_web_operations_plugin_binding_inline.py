"""Tests para la configuracion inline de decoy/narrativa al vincular un
plugin (correccion de flujo posterior a M14, ver docs/roadmap.md) --
"Vincular plugin" (paso 4) deja de ser un paso desconectado de
"Mecanica especifica": si `plugin_kind == "dolost"` y llega un
`Hostname`, el decoy se agrega en la misma request; si
`plugin_kind == "buda"` y el checkbox `create_buda_narrative` viene
marcado, la narrativa se crea en la misma request.

Mismo patron de fixtures que test_web_operations_panels.py
(`mounted_app`/`mounted_client`, con `SQLALCHEMY_DATABASE_URI` real --
`_create_buda_narrative_from_operation()` toca `BUDA.app.db`, que solo
se inicializa cuando `mount_buda()` corre, es decir con
`APATE_MOUNT_EXTERNAL_TOOLS=True`, el default de `create_app()`).

No duplica las aserciones de placeholders de
`test_buda_create_narrative_uses_operation_as_placeholder_source`
(`test_web_operations_panels.py`) -- eso ya prueba
`_create_buda_narrative_from_operation()` en detalle; aca solo se
confirma que este flujo nuevo tambien la dispara. Tampoco duplica
`test_dolost_add_decoy_persists_into_config` -- aca solo se confirma
que el decoy queda en `binding.config["decoys"]` via este flujo nuevo.
Las rutas dedicadas (`dolost_add_decoy()`/`buda_create_narrative()`)
siguen sin tocarse, cubiertas aparte por su propia suite."""

import pytest

from BUDA.app import db as buda_db
from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.web import create_app


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-inline-binding-test.db'}",
        }
    )


@pytest.fixture
def mounted_client(mounted_app):
    return mounted_app.test_client()


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba",
        adversary_profile=AdversaryProfile(name="APT ficticio", motivation="espionaje", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _save(app, operation: Operation) -> Operation:
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


# -- dolost: decoy inline al vincular -----------------------------------


def test_binding_dolost_with_hostname_creates_binding_and_decoy_in_one_request(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins",
        data={
            "plugin_id": "dolost-1",
            "surface": "network",
            "plugin_kind": "dolost",
            "Hostname": "ssh1",
            "Service": "ssh",
            "IP": "172.16.127.150",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-success" in response.data

    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert len(reloaded.plugins) == 1
    binding = reloaded.plugins[0]
    assert binding.plugin_id == "dolost-1"
    assert binding.config["decoys"] == [
        {
            "Hostname": "ssh1",
            "Description": "",
            "IP": "172.16.127.150",
            "Subnet": "",
            "Gateway": "",
            "DeceptionNetwork": "",
            "ServicePorts": "",
            "Service": "ssh",
            "DecoyFiles": "",
        }
    ]


def test_binding_dolost_without_hostname_creates_only_binding_no_error(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins",
        data={"plugin_id": "dolost-1", "surface": "network", "plugin_kind": "dolost"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-success" in response.data
    assert b"flash-error" not in response.data

    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert len(reloaded.plugins) == 1
    assert "decoys" not in reloaded.plugins[0].config


def test_binding_dolost_hostname_ignored_when_plugin_kind_is_not_dolost(mounted_app, mounted_client):
    # Un Hostname en el form sin plugin_kind="dolost" no crea ningun
    # decoy -- el campo solo se interpreta bajo ese kind especifico.
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins",
        data={"plugin_id": "mock-1", "surface": "network", "Hostname": "ssh1"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert "decoys" not in reloaded.plugins[0].config


# -- buda: narrativa inline al vincular ----------------------------------


def test_binding_buda_with_checkbox_creates_binding_and_narrative(mounted_app, mounted_client):
    op = _make_operation(
        name="Operacion placeholder",
        adversary_profile=AdversaryProfile(name="APT-9", motivation="sabotaje", skill_level="advanced"),
    )
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins",
        data={
            "plugin_id": "buda-1",
            "surface": "identity",
            "plugin_kind": "buda",
            "create_buda_narrative": "on",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-success" in response.data

    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert len(reloaded.plugins) == 1
    binding = reloaded.plugins[0]
    narrative_id = binding.config.get("narrative_id")
    assert narrative_id is not None

    with mounted_app.app_context():
        from BUDA.models import Narrative as BudaNarrative

        narrative = buda_db.session.get(BudaNarrative, narrative_id)
        assert narrative.title == "Operacion placeholder"
        assert "APT-9" in narrative.attacker_profile
        assert "sabotaje" in narrative.attacker_profile
        assert narrative.is_running is False


def test_binding_buda_without_checkbox_creates_only_binding_no_narrative(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins",
        data={"plugin_id": "buda-1", "surface": "identity", "plugin_kind": "buda"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-success" in response.data

    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert len(reloaded.plugins) == 1
    assert "narrative_id" not in reloaded.plugins[0].config


# -- "Mecanica especifica" sigue funcionando igual para configurar despues --


def test_dolost_add_decoy_route_still_works_after_binding_without_decoy(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)
    mounted_client.post(
        f"/operations/{op.id}/plugins",
        data={"plugin_id": "dolost-1", "surface": "network", "plugin_kind": "dolost"},
    )

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys",
        data={"Hostname": "ftp1", "Service": "ftp"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    hostnames = [d["Hostname"] for d in reloaded.plugins[0].config["decoys"]]
    assert hostnames == ["ftp1"]


def test_buda_create_narrative_route_still_works_after_binding_without_narrative(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)
    mounted_client.post(
        f"/operations/{op.id}/plugins",
        data={"plugin_id": "buda-1", "surface": "identity", "plugin_kind": "buda"},
    )

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/create", follow_redirects=True
    )

    assert response.status_code == 200
    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert reloaded.plugins[0].config.get("narrative_id") is not None


# -- Vincular plugin (template): fieldset condicional --------------------


def test_bind_plugin_form_includes_dolost_and_buda_inline_fieldsets(mounted_client, mounted_app):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    text = response.data.decode()
    assert 'id="bind-dolost-fields"' in text
    assert 'id="bind-buda-fields"' in text
    assert 'name="create_buda_narrative"' in text
    # El Hostname de este fieldset no es obligatorio en este paso.
    idx = text.index('id="bind-Hostname"')
    tag_end = text.index(">", idx)
    assert "required" not in text[idx:tag_end]

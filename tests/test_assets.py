"""Inventario global de activos y su vínculo textual con operaciones."""

import io

import pytest

from apate.web._sessions import marcar_inicio

from apate.assets import Asset, AssetNotFoundError, JSONFileAssetRepository
from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.identity import IdentityRole


def _asset(identifier: str = "ASSET-ERP-01") -> Asset:
    return Asset(
        identifier=identifier,
        name="ERP de producción",
        asset_type="service",
        criticality="critical",
        technical_identifier="erp.example.internal",
    )


def _operation_form(**overrides):
    form = {
        "name": "Operación con inventario",
        "adversary_name": "APT de prueba",
        "environment": "isolated",
        "narrative_name": "Narrativa",
    }
    form.update(overrides)
    return form


def test_asset_repository_crud(tmp_path):
    repository = JSONFileAssetRepository(tmp_path)
    asset = _asset()

    repository.save(asset)
    assert repository.get(asset.identifier).to_dict() == asset.to_dict()
    assert [item.identifier for item in repository.list()] == [asset.identifier]

    repository.delete(asset.identifier)
    with pytest.raises(AssetNotFoundError):
        repository.get(asset.identifier)


def test_asset_web_crud(client):
    response = client.post(
        "/assets/",
        data={
            "identifier": "ASSET-AD-01",
            "name": "Active Directory",
            "asset_type": "server",
            "criticality": "high",
            "technical_identifier": "ad01.example.internal",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Active Directory" in response.data

    response = client.post(
        "/assets/ASSET-AD-01/edit",
        data={
            "name": "Active Directory principal",
            "asset_type": "server",
            "criticality": "critical",
            "technical_identifier": "ad01.example.internal",
        },
        follow_redirects=True,
    )
    assert b"Active Directory principal" in response.data

    response = client.post("/assets/ASSET-AD-01/delete", follow_redirects=True)
    assert b"Todav" in response.data


def test_operation_selector_saves_inventory_reference_and_keeps_manual_asset(client, app):
    app.config["ASSET_REPOSITORY"].save(_asset())

    response = client.post(
        "/operations/new",
        data=_operation_form(
            inventory_target_assets=["ASSET-ERP-01"], target_assets="Activo aún no inventariado"
        ),
        follow_redirects=False,
    )
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)

    assert operation.adversary_profile.target_assets == ["ASSET-ERP-01", "Activo aún no inventariado"]
    detail = client.get(f"/operations/{operation_id}").get_data(as_text=True)
    assert "ERP de producción" in detail
    # La criticidad se muestra como en el resto de la interfaz; el valor
    # interno sigue siendo el que se persiste y viaja en el CSV.
    assert "service · Crítica" in detail
    assert operation.adversary_profile.target_assets[0] == "ASSET-ERP-01"
    assert "Activo aún no inventariado" in detail
    assert "manual; no está en inventario" in detail


def test_legacy_text_target_asset_loads_and_displays_without_inventory(client, app):
    operation = Operation(
        name="Operación heredada",
        adversary_profile=AdversaryProfile(name="APT", target_assets=["Servidor legado libre"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="N"),
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    detail = client.get(f"/operations/{operation.id}").get_data(as_text=True)
    assert "Servidor legado libre" in detail
    assert "manual; no está en inventario" in detail


def test_inventory_is_shared_between_teams_but_only_administration_can_change_it(client, app):
    provider = app.config["IDENTITY_PROVIDER"]
    administrator = provider.create("Administradora", "Clave-de-prueba")
    blue = provider.create("Azul", "Clave-de-prueba", role=IdentityRole.OPERATION, team_id="azul")
    red = provider.create("Rojo", "Clave-de-prueba", role=IdentityRole.OPERATION, team_id="rojo")
    app.config["ASSET_REPOSITORY"].save(_asset())

    for identity in (blue, red):
        with client.session_transaction() as saved:
            saved["identity_id"] = identity.id
            marcar_inicio(saved)
        response = client.get("/assets/")
        assert response.status_code == 200
        assert b"ERP de producci" in response.data

    with client.session_transaction() as saved:
        saved["identity_id"] = blue.id
        marcar_inicio(saved)
    assert client.post("/assets/", data=_asset("ASSET-NEW").to_dict()).status_code == 403

    with client.session_transaction() as saved:
        saved["identity_id"] = administrator.id
        marcar_inicio(saved)
    assert client.post("/assets/", data=_asset("ASSET-NEW").to_dict()).status_code == 302


def test_csv_preview_reports_invalid_rows_before_writing_and_confirm_imports_valid_rows(client, app):
    csv_data = (
        "identifier,name,asset_type,criticality,technical_identifier\n"
        "ASSET-01,Correo,service,high,mail.example.internal\n"
        "ASSET-02,,server,critical,10.0.0.2\n"
        "ASSET-03,Repositorio,data,medium,\n"
    ).encode()

    preview = client.post(
        "/assets/import/preview",
        data={"inventory_csv": (io.BytesIO(csv_data), "inventario.csv")},
        content_type="multipart/form-data",
    )
    text = preview.get_data(as_text=True)
    assert preview.status_code == 200
    assert "Se importarán 2 activo(s) del inventario" in text
    assert "Se omitirán 1 fila(s) del inventario" in text
    assert "Fila 3" in text
    assert list(app.config["ASSET_REPOSITORY"].list()) == []

    import re

    token = re.search(r"/assets/import/([a-f0-9]+)/confirm", text).group(1)
    confirmed = client.post(f"/assets/import/{token}/confirm", follow_redirects=True)
    assert b"2 activo(s) guardado(s); 1 fila(s) omitida(s)" in confirmed.data
    assert [asset.identifier for asset in app.config["ASSET_REPOSITORY"].list()] == ["ASSET-01", "ASSET-03"]


def test_csv_malformed_row_does_not_abort_valid_rows(client, app):
    csv_data = (
        "identifier,name,asset_type,criticality\n"
        "ASSET-01,Correo,service,high\n"
        "ASSET-02,Demasiadas,columnas,critical,extra\n"
        "ASSET-03,Datos,data,medium\n"
    ).encode()
    preview = client.post(
        "/assets/import/preview",
        data={"inventory_csv": (io.BytesIO(csv_data), "inventario.csv")},
        content_type="multipart/form-data",
    )
    text = preview.get_data(as_text=True)
    assert "Fila 3: tiene más columnas que el encabezado." in text
    assert "ASSET-01" in text and "ASSET-03" in text
    assert list(app.config["ASSET_REPOSITORY"].list()) == []


# -- El CSV acepta el vocabulario que la interfaz muestra -------------------


def test_csv_accepts_the_criticality_labels_the_interface_shows():
    """El valor persistido es `high`, pero la interfaz muestra "Alta", así que
    quien arma un CSV escribe lo que ve en pantalla.

    Encontrado importando un CSV con las criticidades tal como aparecen en la
    UI: **10 filas de 10 rechazadas**. Es el mismo problema que el proyecto ya
    corrigió dos veces mostrando valores crudos (enums, tácticas de ATT&CK),
    acá del lado de la entrada en vez del de la salida.
    """

    from apate.assets import Asset

    for escrito, esperado in (
        ("Crítica", "critical"),
        ("critica", "critical"),
        ("Alta", "high"),
        ("media", "medium"),
        ("BAJA", "low"),
        ("high", "high"),  # el valor interno sigue funcionando
    ):
        activo = Asset(
            identifier="srv-1", name="Servidor", asset_type="servidor", criticality=escrito
        )
        assert activo.criticality == esperado, escrito


def test_unknown_criticality_error_names_what_the_operator_sees():
    """Un mensaje que solo dice "low, medium, high, critical" obliga a adivinar
    la relación con las etiquetas de la pantalla."""

    import pytest

    from apate.assets import Asset, AssetValidationError

    with pytest.raises(AssetValidationError) as error:
        Asset(
            identifier="srv-1",
            name="Servidor",
            asset_type="servidor",
            criticality="importantisimo",
        )

    mensaje = str(error.value)
    assert "Crítica" in mensaje and "critical" in mensaje


def test_interface_labels_and_importer_share_one_source():
    """Tener las etiquetas duplicadas en la capa web fue lo que dejó que la
    interfaz y la importación hablaran vocabularios distintos."""

    from apate.assets import CRITICALITY_LABELS
    from apate.web.blueprints.assets import _CRITICALITY_LABELS

    assert _CRITICALITY_LABELS is CRITICALITY_LABELS

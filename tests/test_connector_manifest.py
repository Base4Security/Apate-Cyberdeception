"""El contrato declarativo distingue capacidades de validación física."""

import pytest

from apate.deployment import (
    ActiveDirectoryHoneyuserConnector,
    ConnectorManifest,
    DeploymentService,
    FilesystemHoneyfileConnector,
)


def test_conectores_incluidos_exponen_un_contrato_versionado(tmp_path):
    service = DeploymentService(repository=object(), connectors={
        "filesystem-honeyfile": FilesystemHoneyfileConnector(tmp_path / "receipts")})
    filesystem = service.connector_manifest("filesystem-honeyfile")
    ad = ActiveDirectoryHoneyuserConnector.contract().to_dict()

    assert filesystem == {
        "kind": "filesystem-honeyfile", "contract_version": 2,
        "actions": ["deploy", "retire", "rotate"], "observations": ["status"],
        "external_validation": "not_asserted"}
    assert ad["observations"] == ["events", "status"]
    assert ad["external_validation"] == "not_asserted"


def test_conector_heredado_sigue_si_dar_manifest(tmp_path):
    class Legacy(FilesystemHoneyfileConnector):
        kind = "legacy"
        manifest = None

    legacy = Legacy(tmp_path / "receipts")
    assert legacy.contract().contract_version == 1
    assert legacy.contract().kind == "legacy"


def test_manifest_invalido_o_de_otro_kind_se_rechaza():
    with pytest.raises(ValueError, match="invalid_connector_manifest"):
        ConnectorManifest("x", 2, frozenset({"execute-anything"}), frozenset({"status"}))

    class Wrong(FilesystemHoneyfileConnector):
        kind = "other"

    with pytest.raises(ValueError, match="connector_manifest_kind_mismatch"):
        Wrong.contract()

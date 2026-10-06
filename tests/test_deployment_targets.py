import json

import pytest

from apate.deployment import (
    DeploymentNotFoundError,
    DeploymentTarget,
    DeploymentValidationError,
    JSONFileDeploymentTargetRepository,
)


def test_target_round_trip_and_list(tmp_path):
    repository = JSONFileDeploymentTargetRepository(tmp_path)
    target = DeploymentTarget(
        name="DC principal",
        connector_kind="active-directory-honeyuser",
        address="dc01.example.test",
        credential_ref="secret://target/one",
        config={"ou_allowlist": ["OU=Deception,DC=example,DC=test"]},
    )

    repository.save(target)

    assert repository.get(target.id) == target
    assert repository.list() == [target]
    assert "secret://target/one" in json.loads((tmp_path / f"{target.id}.json").read_text())["credential_ref"]


def test_target_config_rejects_embedded_secrets(tmp_path):
    repository = JSONFileDeploymentTargetRepository(tmp_path)
    target = DeploymentTarget(
        name="DC",
        connector_kind="active-directory-honeyuser",
        address="dc.example.test",
        config={"password": "no debe quedar acá"},
    )

    with pytest.raises(DeploymentValidationError, match="credential_ref"):
        repository.save(target)


def test_missing_target_is_typed(tmp_path):
    with pytest.raises(DeploymentNotFoundError):
        JSONFileDeploymentTargetRepository(tmp_path).get("missing")


def test_scope_revision_preserves_previous_snapshot_and_rejects_stale_write(tmp_path):
    repository = JSONFileDeploymentTargetRepository(tmp_path)
    original = DeploymentTarget(name="DC", connector_kind="active-directory-honeyuser",
                                address="dc01.example.test", config={"ou_allowlist": ["OU=Old,DC=example,DC=test"]})
    repository.save(original)
    updated = DeploymentTarget(id=original.id, revision=2, name=original.name,
                               connector_kind=original.connector_kind, address="dc02.example.test",
                               config={"ou_allowlist": ["OU=New,DC=example,DC=test"]})
    repository.save(updated)
    assert repository.get(original.id).address == "dc02.example.test"
    assert repository.history(original.id) == [original]
    with pytest.raises(DeploymentValidationError, match="revisión"):
        repository.save(updated)

import pytest

from apate.deployment import DeploymentValidationError, JSONFileHoneyuserCheckpointRepository


def test_checkpoint_defaults_to_zero_and_persists_atomically(tmp_path):
    repository = JSONFileHoneyuserCheckpointRepository(tmp_path)
    assert repository.get("record-1") == 0
    repository.save("record-1", 42)
    assert repository.get("record-1") == 42
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("record_id", ["../escape", "a/b", "", "x" * 129])
def test_checkpoint_rejects_unsafe_record_ids(tmp_path, record_id):
    repository = JSONFileHoneyuserCheckpointRepository(tmp_path)
    with pytest.raises(DeploymentValidationError):
        repository.get(record_id)


def test_checkpoint_rejects_negative_event_id(tmp_path):
    with pytest.raises(DeploymentValidationError):
        JSONFileHoneyuserCheckpointRepository(tmp_path).save("record-1", -1)

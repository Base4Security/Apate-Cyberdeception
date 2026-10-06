"""Regresiones de credenciales WinRM de BUDA no recuperables."""

from __future__ import annotations

import sqlite3
from datetime import date

from cryptography.fernet import Fernet

from BUDA.app import db as buda_db
from BUDA.models import Narrative as BudaNarrative
from BUDA.models import UserProfile as BudaUserProfile
from BUDA.utils import orchestrator
from BUDA.utils.crypto_utils import reset_fernet_cache
from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.web import create_app


def _app(tmp_path, *, data_name: str = "data", database_name: str = "buda.db"):
    data_dir = tmp_path / data_name
    database_path = tmp_path / database_name
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": data_dir,
            "APATE_RULES_PATH": data_dir / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
        }
    )


def _profile_with_narrative(app) -> tuple[int, int]:
    with app.app_context():
        narrative = BudaNarrative(
            title="Narrativa de recuperación",
            objective="Comprobar una credencial cifrada",
            end_date=date(2030, 1, 1),
            is_running=False,
        )
        profile = BudaUserProfile(
            name="Perfil recuperable",
            role="Analista",
            behavior_pattern="Trabaja en una estación simulada.",
            winrm_server="winrm.demo.example.invalid",
            winrm_username="DEMO\\recovery",
            winrm_password="DEMO_ONLY_NOT_A_REAL_SECRET",
        )
        narrative.user_profiles.append(profile)
        buda_db.session.add(narrative)
        buda_db.session.commit()
        return narrative.id, profile.id


def test_local_key_is_created_once_and_reused_without_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("BUDA_CREDENTIAL_ENCRYPTION_KEY", raising=False)
    reset_fernet_cache()

    first_app = _app(tmp_path)
    narrative_id, _ = _profile_with_narrative(first_app)
    key_path = tmp_path / "data" / "buda_credential_encryption.key"
    first_key = key_path.read_bytes()

    second_app = _app(tmp_path)
    with second_app.app_context():
        profile = buda_db.session.get(BudaNarrative, narrative_id).user_profiles[0]
        assert profile.credentials_recoverable is True
        assert profile.winrm_username == "DEMO\\recovery"
        assert profile.winrm_password == "DEMO_ONLY_NOT_A_REAL_SECRET"

    assert key_path.read_bytes() == first_key


def test_environment_key_wins_over_local_key(tmp_path, monkeypatch):
    monkeypatch.delenv("BUDA_CREDENTIAL_ENCRYPTION_KEY", raising=False)
    reset_fernet_cache()
    _app(tmp_path)
    local_key = (tmp_path / "data" / "buda_credential_encryption.key").read_bytes()
    environment_key = Fernet.generate_key()
    monkeypatch.setenv("BUDA_CREDENTIAL_ENCRYPTION_KEY", environment_key.decode())
    reset_fernet_cache()

    app = _app(tmp_path)
    _profile_with_narrative(app)
    database_path = tmp_path / "buda.db"
    raw_username = sqlite3.connect(database_path).execute(
        "SELECT winrm_username FROM user_profiles"
    ).fetchone()[0]

    assert Fernet(environment_key).decrypt(raw_username.encode()).decode() == "DEMO\\recovery"
    assert (tmp_path / "data" / "buda_credential_encryption.key").read_bytes() == local_key


def test_unreadable_profile_is_visible_but_blocks_winrm(tmp_path, monkeypatch, caplog):
    original_key = Fernet.generate_key()
    monkeypatch.setenv("BUDA_CREDENTIAL_ENCRYPTION_KEY", original_key.decode())
    reset_fernet_cache()
    first_app = _app(tmp_path)
    narrative_id, profile_id = _profile_with_narrative(first_app)

    operation = Operation(
        name="Operación con credencial no recuperable",
        adversary_profile=AdversaryProfile(name="Adversario de prueba"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa APATE"),
    )
    operation.bind_plugin(PluginBinding(plugin_id="buda-recovery", surface="identity", config={"narrative_id": narrative_id}))
    first_app.config["OPERATION_REPOSITORY"].save(operation)

    monkeypatch.setenv("BUDA_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    reset_fernet_cache()
    second_app = _app(tmp_path)
    caplog.set_level("WARNING", logger="BUDA.utils.crypto_utils")
    with second_app.app_context():
        profile = buda_db.session.get(BudaUserProfile, profile_id)
        narrative = buda_db.session.get(BudaNarrative, narrative_id)
        assert profile.credentials_recoverable is False

        calls = []
        monkeypatch.setattr(orchestrator.winrm, "Session", lambda *args, **kwargs: calls.append((args, kwargs)))
        monkeypatch.setattr(orchestrator, "log_command", lambda *args: None)
        monkeypatch.setattr(orchestrator, "record_event", lambda **kwargs: kwargs)
        result = orchestrator.execute_command(narrative, profile.name, "hostname")

    client = second_app.test_client()
    assert client.get("/capabilities/").status_code == 200
    profiles_response = client.get("/capabilities/identity-profiles")
    detail_response = client.get(f"/operations/{operation.id}")
    assert profiles_response.status_code == detail_response.status_code == 200
    assert b"No recuperables" in profiles_response.data
    assert b"No recuperables" in detail_response.data
    assert "no se pueden descifrar" in result
    assert calls == []
    assert "modo no recuperable" in caplog.text

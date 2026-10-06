"""Regresiones del cifrado local de secretos recuperables."""

from __future__ import annotations

import json

from cryptography.fernet import Fernet

from BUDA.utils import config_utils
from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.secrets import (
    EncryptedSiemSoarConfigRepository,
    EncryptedJSONFileOperationRepository,
    EncryptedVirusTotalConfigRepository,
    SecretCipher,
    configure_default_secret_cipher,
)
from apate.web import create_app


def test_app_arranca_sin_clave_de_entorno_y_crea_clave_local(tmp_path, monkeypatch):
    monkeypatch.delenv("APATE_SECRET_ENCRYPTION_KEY", raising=False)

    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
        }
    )

    assert app.config["SECRET_CIPHER"]
    assert (tmp_path / "data" / "secret_encryption.key").is_file()


def test_repositorios_cifran_en_disco_y_descifran_para_su_uso(tmp_path):
    cipher = SecretCipher(Fernet.generate_key())
    virustotal = EncryptedVirusTotalConfigRepository(tmp_path / "virustotal.json", cipher)
    siem_soar = EncryptedSiemSoarConfigRepository(tmp_path / "siem-soar.json", cipher)

    virustotal.save_api_key("vt-secret")
    siem_soar.save("https://siem.example/secret", "siem-secret")

    assert "vt-secret" not in (tmp_path / "virustotal.json").read_text(encoding="utf-8")
    raw_siem_soar = (tmp_path / "siem-soar.json").read_text(encoding="utf-8")
    assert "https://siem.example/secret" not in raw_siem_soar
    assert "siem-secret" not in raw_siem_soar
    assert virustotal.load() == {"api_key": "vt-secret"}
    assert siem_soar.load() == {
        "webhook_url": "https://siem.example/secret",
        "auth_token": "siem-secret",
    }


def test_valores_heredados_se_leen_y_se_cifran_en_el_siguiente_guardado(tmp_path):
    cipher = SecretCipher(Fernet.generate_key())
    path = tmp_path / "virustotal.json"
    path.write_text(json.dumps({"api_key": "vt-heredada"}), encoding="utf-8")
    repository = EncryptedVirusTotalConfigRepository(path, cipher)

    assert repository.load() == {"api_key": "vt-heredada"}
    repository.save_api_key(repository.load()["api_key"])

    raw = path.read_text(encoding="utf-8")
    assert "vt-heredada" not in raw
    assert cipher.decrypt(json.loads(raw)["api_key"]) == "vt-heredada"


def test_configuracion_llm_heredada_se_migra_al_guardarla(tmp_path, monkeypatch):
    config_path = tmp_path / "config_llm.json"
    config_path.write_text(json.dumps({"provider": "openai", "api_key": "llm-heredada"}), encoding="utf-8")
    configure_default_secret_cipher(SecretCipher(Fernet.generate_key()))
    # `CONFIG_FILE` dejo de ser una constante relativa al directorio de
    # trabajo: ahora la ruta se resuelve al usarse, bajo APATE_DATA_DIR
    # (ver apate.runtime_paths). Se apunta la variable al tmp_path.
    monkeypatch.setenv("APATE_DATA_DIR", str(tmp_path))

    loaded = config_utils.load_llm_config()
    assert loaded["api_key"] == "llm-heredada"
    assert config_utils.save_llm_config(loaded) == {"message": "Settings updated successfully"}

    assert "llm-heredada" not in config_path.read_text(encoding="utf-8")


# -- Limite conocido: donde vive la frontera de cifrado --------------------


def test_operation_repository_encrypts_canarytoken_auth_token_and_decrypts_for_domain(tmp_path):

    secreto = "TOKEN-DE-ADMINISTRACION-EN-CLARO"
    operation = Operation(
        name="Frontera de cifrado",
        adversary_profile=AdversaryProfile(name="APT"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="N"),
    )
    operation.bind_plugin(
        PluginBinding(
            plugin_id="canarytoken-1",
            plugin_kind="canarytoken",
            surface="data",
            config={"auth_token": secreto},
        )
    )
    repository = EncryptedJSONFileOperationRepository(tmp_path, SecretCipher(Fernet.generate_key()))
    repository.save(operation)

    en_disco = "".join(f.read_text(encoding="utf-8") for f in tmp_path.rglob("*.json"))
    assert secreto not in en_disco
    assert repository.get(operation.id).plugins[0].config["auth_token"] == secreto


def test_operation_repository_migrates_legacy_plaintext_token_when_rewritten(tmp_path):
    cipher = SecretCipher(Fernet.generate_key())
    repository = EncryptedJSONFileOperationRepository(tmp_path, cipher)
    operation = Operation(
        name="Token heredado",
        adversary_profile=AdversaryProfile(name="APT"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="N"),
    )
    operation.bind_plugin(
        PluginBinding(
            plugin_id="canarytoken-1",
            plugin_kind="canarytoken",
            surface="data",
            config={"auth_token": "legado-en-claro"},
        )
    )
    path = tmp_path / f"{operation.id}.json"
    path.write_text(json.dumps(operation.to_dict()), encoding="utf-8")

    loaded = repository.get(operation.id)
    assert loaded.plugins[0].config["auth_token"] == "legado-en-claro"
    repository.save(loaded)

    assert "legado-en-claro" not in path.read_text(encoding="utf-8")

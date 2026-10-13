"""La candidata instalada conserva operación, telemetría y auditoría al restaurar."""

import hashlib
import json
import zipfile

import pytest

from apate.release import release_evidence, smoke_distribution
from apate.sbom import build_document


def test_smoke_instalacion_y_restauracion_real(tmp_path):
    notice = tmp_path / "NOTICE"
    notice.write_text("APATE - material sintético de prueba", encoding="utf-8")
    sbom = tmp_path / "apate.cdx.json"
    sbom.write_text(json.dumps(build_document()), encoding="utf-8")

    result = smoke_distribution(scratch=tmp_path, notice=notice, sbom=sbom)

    assert result["web"] == result["machine_api"] == result["backup_restore"] == "ok"
    assert result["backup_files"] >= 3
    assert result["external_services"] == "not_used"
    assert not list(tmp_path.glob("apate-release-*"))


def test_smoke_rechaza_procedencia_incorrecta_antes_de_crear_datos(tmp_path):
    with pytest.raises(ValueError, match="release_commit_mismatch"):
        smoke_distribution(scratch=tmp_path, expected_commit="commit-inventado")
    assert not list(tmp_path.glob("apate-release-*"))


def test_evidencia_vincula_wheel_sbom_locks_e_imagen_sin_firmar(tmp_path):
    commit = "a" * 40
    source = f"https://example.org/apate/tree/{commit}"
    wheel = tmp_path / "apate-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name in ("apate/ledger/repository.py", "apate/plugins/playground_plugin.py",
                     "apate/release.py", "apate/ops.py", "apate/doctor.py", "apate/sbom.py",
                     "apate/schema_version.py", "apate/deployment/connector.py",
                     "apate/web/_readiness.py", "apate/web/_request_observability.py",
                     "apate/playground/_stack/docker-compose.yml", "apate/playground/_stack/LICENSE",
                     "apate/web/templates/base.html", "apate/web/static/theme.css",
                     "apate/web/translations/en/LC_MESSAGES/messages.mo"):
            archive.writestr(name, "")
        archive.writestr("apate-0.1.0.dist-info/entry_points.txt",
                         '[apate.plugins]\nplayground = apate.plugins.playground_plugin:PlaygroundPlugin\n'
                         '[apate.identity_providers]\nlocal = apate.identity.providers:LocalIdentityProvider\n')
        archive.writestr("apate-0.1.0.dist-info/METADATA", "Name: apate\nVersion: 0.1.0\n")
        archive.writestr("apate-0.1.0.dist-info/licenses/LICENSE", "AGPL")
        archive.writestr("apate-0.1.0.dist-info/licenses/NOTICE", "APATE")
    sbom = tmp_path / "image.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {
        "name": "apate", "version": "0.1.0",
        "properties": [{"name": "apate:build:commit", "value": commit}],
        "externalReferences": [{"type": "distribution-source", "url": source}]}}}), encoding="utf-8")
    notice = tmp_path / "NOTICE"
    notice.write_text("APATE", encoding="utf-8")
    lock = tmp_path / "release.txt"
    lock.write_text("flask==3.1.3 \\\n    --hash=sha256:" + "b" * 64 + "\n", encoding="utf-8")
    build_lock = tmp_path / "build.txt"
    build_lock.write_text("wheel==0.48.0 --hash=sha256:" + "c" * 64, encoding="utf-8")
    image_id = tmp_path / "image-id.txt"
    image_id.write_text("sha256:" + "d" * 64, encoding="utf-8")
    arguments = dict(wheel=wheel, sbom=sbom, notice=notice, lock=lock, build_lock=build_lock,
                     base_image="python:3.11-slim-bookworm@sha256:" + "e" * 64,
                     image_id=image_id, expected_commit=commit, source_url=source)
    evidence = release_evidence(**arguments)
    assert evidence["version"] == "0.1.0" and evidence["runtime_packages_locked"] == 1
    assert evidence["artifacts"]["wheel"]["sha256"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert evidence["signed_attestation"] is False
    upgrade = tmp_path / "upgrade.json"
    upgrade.write_text(json.dumps({"format": 1, "baseline_wheel_sha256": "a" * 64,
        "candidate_wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "upgrade": "ok", "candidate_restore": "ok", "rollback": "ok",
        "original_unchanged": True, "external_services": "not_used"}), encoding="utf-8")
    linked = release_evidence(**arguments, upgrade_smoke=upgrade)
    assert linked["artifacts"]["upgrade_smoke"]["sha256"] == hashlib.sha256(upgrade.read_bytes()).hexdigest()
    upgrade.write_text(upgrade.read_text(encoding="utf-8").replace('"rollback": "ok"', '"rollback": "failed"'), encoding="utf-8")
    with pytest.raises(ValueError, match="release_upgrade_smoke_mismatch"):
        release_evidence(**arguments, upgrade_smoke=upgrade)
    wrong_wheel = json.loads(upgrade.read_text(encoding="utf-8"))
    wrong_wheel["rollback"] = "ok"
    wrong_wheel["candidate_wheel_sha256"] = "f" * 64
    upgrade.write_text(json.dumps(wrong_wheel), encoding="utf-8")
    with pytest.raises(ValueError, match="release_upgrade_smoke_mismatch"):
        release_evidence(**arguments, upgrade_smoke=upgrade)
    with pytest.raises(ValueError, match="release_sbom_commit_mismatch"):
        release_evidence(**{**arguments, "expected_commit": "f" * 40,
                            "source_url": "https://example.org/apate/tree/" + "f" * 40})

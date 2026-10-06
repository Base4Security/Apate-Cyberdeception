"""La GUI en inglés se puede recorrer y reproduce datos demo en inglés."""

import json
import os
import subprocess
import sys
from pathlib import Path

from apate.web import create_app


def test_language_switch_persists_through_navigation(client):
    response = client.get("/operations/?lang=en")
    assert b'<html lang="en">' in response.data
    assert b"Operation control" in response.data
    assert b"+ New operation" in response.data
    assert b"Todav" not in response.data

    response = client.get("/rules/")
    assert b"Decision engine rules" in response.data
    assert b"Loaded rules (0)" in response.data
    response = client.get("/operations/new")
    assert b"Create operation" in response.data
    response = client.get("/telemetry/")
    assert b"Select an operation" in response.data

    response = client.get("/operations/?lang=es")
    assert b'<html lang="es">' in response.data
    assert b"Control de operaciones" in response.data


def test_english_seed_produces_english_rules_events_and_detail(tmp_path):
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join((str(root / "src"), env.get("PYTHONPATH", "")))
    subprocess.run(
        [sys.executable, str(root / "examples" / "seed_gui.py"), "--lang", "en"],
        cwd=tmp_path, env=env, check=True, capture_output=True, text=True,
    )

    data = tmp_path / ".apate_data"
    assert "Scan on honeypot-mock-1" in (data / "rules.yaml").read_text(encoding="utf-8")
    operations = [json.loads(path.read_text(encoding="utf-8")) for path in (data / "operations").glob("*.json")]
    assert len(operations) == 3
    demonstration = next(item for item in operations if item["name"] == "Local demonstration")

    app = create_app({"TESTING": True, "APATE_DATA_DIR": data, "APATE_RULES_PATH": data / "rules.yaml"})
    client = app.test_client()
    assert b"Local demonstration" in client.get("/operations/?lang=en").data
    assert b"Adversary profile" in client.get(f"/operations/{demonstration['id']}").data
    assert b"Scan on honeypot-mock-1" in client.get("/rules/").data
    telemetry = client.get(f"/telemetry/{demonstration['id']}").data
    assert b"Observed TTPs" in telemetry
    assert b"Simulated port scan against the mock honeypot." in telemetry

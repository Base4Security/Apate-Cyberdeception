from unittest.mock import Mock, patch
from threading import Thread

import requests
from flask import Flask, jsonify, request as flask_request
from werkzeug.serving import make_server

from apate.plugins import EventType, PluginEvent
from apate.telemetry import virustotal as virustotal_module


def _seed_iocs(app):
    app.config["TELEMETRY_COLLECTOR"].handle_event(
        PluginEvent(
            event_type=EventType.INTERACTION,
            plugin_id="honeypot-mock-1",
            surface="network",
            operation_id="op-1",
            payload={
                "kind": "scan",
                "source_ip": "8.8.8.8",
                "domain": "example.com",
            },
        )
    )


def _response():
    response = Mock()
    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 4,
                    "suspicious": 1,
                    "harmless": 65,
                    "undetected": 20,
                }
            }
        }
    }
    return response


def test_button_is_visible_but_disabled_without_api_key(client, app):
    _seed_iocs(app)

    text = client.get("/telemetry/op-1?view=iocs").get_data(as_text=True)

    assert "Consultar en VirusTotal" in text
    assert "Configurar API key" in text
    assert "disabled" in text


def test_button_is_enabled_when_api_key_is_configured(client, app):
    _seed_iocs(app)
    app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].save_api_key("vt-secret")

    text = client.get("/telemetry/op-1?view=iocs").get_data(as_text=True)

    button_fragment = text.split("Consultar en VirusTotal")[0][-250:]
    assert "disabled" not in button_fragment
    assert "vt-secret" not in text


def test_mocked_query_saves_and_displays_result(client, app):
    _seed_iocs(app)
    app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].save_api_key("vt-secret")

    with patch("apate.telemetry.virustotal.requests.get", return_value=_response()) as get:
        response = client.post(
            "/telemetry/op-1/iocs/virustotal",
            data={"ioc_type": "ip", "ioc_value": "8.8.8.8"},
            follow_redirects=True,
        )

    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "4 maliciosas · 1 sospechosas / 90 motores" in text
    assert "Ver resultado en VirusTotal" in text
    assert get.call_args.kwargs == {"headers": {"x-apikey": "vt-secret"}, "timeout": 8.0}
    saved = app.config["VIRUSTOTAL_ENRICHMENT_REPOSITORY"].list_for_operation("op-1")
    assert len(saved) == 1 and saved[0].subject_key == "ip:8.8.8.8"


def test_query_without_key_does_not_call_virustotal(client, app):
    _seed_iocs(app)

    with patch("apate.telemetry.virustotal.requests.get") as get:
        response = client.post(
            "/telemetry/op-1/iocs/virustotal",
            data={"ioc_type": "ip", "ioc_value": "8.8.8.8"},
            follow_redirects=True,
        )

    get.assert_not_called()
    assert "Configur" in response.get_data(as_text=True)


def test_tampered_ioc_is_rejected_without_http_call(client, app):
    _seed_iocs(app)
    app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].save_api_key("vt-secret")

    with patch("apate.telemetry.virustotal.requests.get") as get:
        response = client.post(
            "/telemetry/op-1/iocs/virustotal",
            data={"ioc_type": "ip", "ioc_value": "198.51.100.99"},
            follow_redirects=True,
        )

    get.assert_not_called()
    assert "no existe" in response.get_data(as_text=True)


def test_remote_failure_is_visible_and_not_persisted(client, app):
    _seed_iocs(app)
    app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].save_api_key("vt-secret")

    with patch("apate.telemetry.virustotal.requests.get", side_effect=TimeoutError):
        response = client.post(
            "/telemetry/op-1/iocs/virustotal",
            data={"ioc_type": "domain", "ioc_value": "example.com"},
            follow_redirects=True,
        )

    assert "no pudo devolver" in response.get_data(as_text=True)
    assert app.config["VIRUSTOTAL_ENRICHMENT_REPOSITORY"].list_for_operation("op-1") == []


def test_live_http_flow_against_simulated_virustotal_server(app, monkeypatch):
    """Verifica el flujo por sockets HTTP reales, no solo FlaskClient."""

    _seed_iocs(app)
    app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].save_api_key("vt-live-test")
    fake_vt = Flask("fake-virustotal")

    @fake_vt.get("/api/v3/ip_addresses/<ip>")
    def ip_report(ip):
        assert ip == "8.8.8.8"
        assert flask_request.headers["x-apikey"] == "vt-live-test"
        return jsonify(
            data={
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 3,
                        "harmless": 75,
                        "undetected": 10,
                    }
                }
            }
        )

    vt_server = make_server("127.0.0.1", 0, fake_vt, threaded=True)
    apate_server = make_server("127.0.0.1", 0, app, threaded=True)
    vt_thread = Thread(target=vt_server.serve_forever, daemon=True)
    apate_thread = Thread(target=apate_server.serve_forever, daemon=True)
    vt_thread.start()
    apate_thread.start()
    monkeypatch.setattr(
        virustotal_module,
        "VIRUSTOTAL_API_BASE",
        f"http://127.0.0.1:{vt_server.server_port}/api/v3",
    )
    try:
        response = requests.post(
            f"http://127.0.0.1:{apate_server.server_port}/telemetry/op-1/iocs/virustotal",
            data={"ioc_type": "ip", "ioc_value": "8.8.8.8"},
            timeout=8.0,
            allow_redirects=False,
        )
        page = requests.get(
            f"http://127.0.0.1:{apate_server.server_port}/telemetry/op-1?view=iocs",
            timeout=8.0,
        )
    finally:
        apate_server.shutdown()
        vt_server.shutdown()
        apate_thread.join(timeout=2)
        vt_thread.join(timeout=2)

    assert response.status_code == 302
    assert page.status_code == 200
    assert "2 maliciosas · 3 sospechosas / 90 motores" in page.text

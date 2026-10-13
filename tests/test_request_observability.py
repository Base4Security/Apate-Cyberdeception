"""Los IDs HTTP permiten correlación sin registrar rutas ni secretos."""

import json
import logging
import re


def test_identificador_y_log_sanitizado_en_rechazo_api(app, client, caplog):
    app.config["APATE_STRUCTURED_ACCESS_LOG"] = True
    with caplog.at_level(logging.INFO, logger=app.logger.name):
        response = client.get("/api/v1/operations?secret=NO_REGISTRAR",
                              headers={"Authorization": "Bearer SECRETO"})

    assert response.status_code == 401
    identifier = response.headers["X-Request-ID"]
    assert re.fullmatch(r"[0-9a-f]{32}", identifier)
    events = [json.loads(record.message) for record in caplog.records
              if record.message.startswith('{"duration_ms"')]
    assert len(events) == 1
    assert events[0]["request_id"] == identifier
    assert events[0]["endpoint"] == "api.operations"
    assert events[0]["status"] == 401
    assert "NO_REGISTRAR" not in caplog.text
    assert "SECRETO" not in caplog.text


def test_identificadores_distintos_aun_sin_log(client):
    first = client.get("/about")
    second = client.get("/about")
    assert first.status_code == second.status_code == 200
    assert first.headers["X-Request-ID"] != second.headers["X-Request-ID"]

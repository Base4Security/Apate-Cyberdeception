"""La GUI local rechaza escrituras ajenas sin token de formulario."""

import re

from apate.web import create_app


def test_post_requires_csrf_outside_testing(tmp_path):
    app = create_app({"APATE_DATA_DIR": tmp_path, "APATE_RULES_PATH": tmp_path / "rules.yaml"})
    client = app.test_client()
    assert client.post("/rules/", data={"rules_text": "rules: []"}).status_code == 400
    response = client.get("/rules/")
    token = re.search(rb'name="_csrf_token" value="([^"]+)"', response.data).group(1).decode()
    assert client.post("/rules/", data={"rules_text": "rules: []", "_csrf_token": token}).status_code == 302


def test_nonlocal_host_is_rejected(tmp_path):
    app = create_app({"APATE_DATA_DIR": tmp_path, "APATE_RULES_PATH": tmp_path / "rules.yaml"})
    response = app.test_client().get("/operations/", headers={"Host": "external.example"})
    assert response.status_code == 403

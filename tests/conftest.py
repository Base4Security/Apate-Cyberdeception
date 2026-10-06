import pytest

from apate.web import create_app


@pytest.fixture
def app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
        }
    )


@pytest.fixture
def client(app):
    return app.test_client()

"""`python -m apate.web` -- revision de seguridad post-vendorizado
(ver docs/roadmap.md): `debug` estaba hardcodeado en `True` en el
comando real que arranca la demo sin autenticacion (M13j), habilitando
el debugger interactivo de Werkzeug (RCE potencial) para cualquiera
que llegue a la app. Ahora depende de `APATE_DEBUG`, default `False`."""

from apate.web.__main__ import _debug_enabled


def test_debug_defaults_to_false_without_env_var(monkeypatch):
    monkeypatch.delenv("APATE_DEBUG", raising=False)
    assert _debug_enabled() is False


def test_debug_disabled_for_falsy_values(monkeypatch):
    for value in ("0", "false", "no", "", "anything-else"):
        monkeypatch.setenv("APATE_DEBUG", value)
        assert _debug_enabled() is False


def test_debug_enabled_for_truthy_values(monkeypatch):
    for value in ("1", "true", "True", "TRUE", "yes", "Yes"):
        monkeypatch.setenv("APATE_DEBUG", value)
        assert _debug_enabled() is True

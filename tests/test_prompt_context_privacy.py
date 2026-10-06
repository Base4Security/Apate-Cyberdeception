"""Lo que sale hacia el modelo externo: contexto curado, sin identificadores.

`generate_activity()` leía `context.json` del directorio de trabajo y lo pegaba
entero al prompt. Ese archivo es el extracto UEBA de los `.evtx` del cliente:
**nombres de usuario, IPs internas, nombres de equipos, horarios**. Y salteaba
el repositorio curado de APATE, así que una fuente que el operador había
descartado en la interfaz seguía viajando igual —`import_legacy()` copia el
archivo "sin eliminarlo"—.

Dos garantías, y las dos tienen que valer a la vez: que solo viaje lo
**aprobado**, y que de eso viaje solo la **forma**, no las identidades.
"""

from __future__ import annotations

import json

import pytest

from apate.core import BehaviorContextSource, BehaviorContextStatus
from apate.web import create_app

EXTRACTO_CRUDO = {
    "usernames": ["jdoe", "mrodriguez", "admin_svc"],
    "work_hours": {"9": 120, "10": 340, "18": 45},
    "ip_addresses": ["10.4.1.22", "10.4.1.87"],
    "devices": ["WKS-FINANCE-04", "DC01"],
    "login_frequencies": {"jdoe": 210, "mrodriguez": 88, "admin_svc": 4},
}

IDENTIFICADORES = (
    "jdoe", "mrodriguez", "admin_svc", "10.4.1.22", "10.4.1.87", "WKS-FINANCE-04", "DC01",
)


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-test.db'}",
        }
    )


# -- La proyección -----------------------------------------------------


def test_ningun_identificador_sobrevive_a_la_proyeccion():
    fuente = BehaviorContextSource(name="x", data=EXTRACTO_CRUDO, provenance="test")

    serializado = json.dumps(fuente.prompt_summary(), ensure_ascii=False)

    for identificador in IDENTIFICADORES:
        assert identificador not in serializado, identificador


def test_la_forma_del_comportamiento_si_sobrevive():
    """Si no sobreviviera, el modelo no tendría con qué generar algo plausible
    y el arreglo sería un apagón disfrazado de control de privacidad."""

    resumen = BehaviorContextSource(name="x", data=EXTRACTO_CRUDO, provenance="test").prompt_summary()

    assert resumen["work_hours"] == {"9": 120, "10": 340, "18": 45}
    assert resumen["usernames"] == {"distintos": 3}
    assert resumen["login_frequencies"]["entradas"] == 3
    assert resumen["login_frequencies"]["total"] == 302
    assert resumen["login_frequencies"]["maximo"] == 210


def test_un_campo_nuevo_con_texto_libre_no_filtra_su_contenido():
    """Permite por construcción: un campo que el extractor agregue mañana cae
    en el caso general y no viaja."""

    fuente = BehaviorContextSource(
        name="x",
        data={"nota": "exportado del DC de la sede de Madrid, contacto jdoe@cliente.com"},
        provenance="test",
    )

    resumen = fuente.prompt_summary()

    assert resumen["nota"] == {"presente": True}
    assert "Madrid" not in json.dumps(resumen)
    assert "jdoe" not in json.dumps(resumen)


def test_un_diccionario_con_claves_no_horarias_pierde_las_claves():
    fuente = BehaviorContextSource(
        name="x", data={"por_equipo": {"WKS-01": 5, "WKS-02": 9}}, provenance="test"
    )

    resumen = fuente.prompt_summary()

    assert "WKS-01" not in json.dumps(resumen)
    assert resumen["por_equipo"]["entradas"] == 2
    assert resumen["por_equipo"]["total"] == 14


def test_una_clave_horaria_fuera_de_rango_no_cuenta_como_hora():
    fuente = BehaviorContextSource(name="x", data={"raro": {"99": 1}}, provenance="test")

    assert "99" not in json.dumps(fuente.prompt_summary()["raro"])


# -- Solo lo aprobado --------------------------------------------------


def test_una_fuente_pendiente_no_llega_al_prompt(mounted_app):
    """Es la mitad de gobierno del arreglo: el candidato que el operador
    todavía no confirmó no sale de la red del cliente."""

    from apate.web.blueprints.plugins import _prompt_context

    repositorio = mounted_app.config["BEHAVIOR_CONTEXT_REPOSITORY"]
    repositorio.save(
        BehaviorContextSource(
            name="Pendiente", data=EXTRACTO_CRUDO, provenance="test",
            status=BehaviorContextStatus.PENDING,
        )
    )

    with mounted_app.test_request_context("/"):
        assert _prompt_context() == ""


def test_una_fuente_archivada_tampoco(mounted_app):
    from apate.web.blueprints.plugins import _prompt_context

    fuente = BehaviorContextSource(name="Vieja", data=EXTRACTO_CRUDO, provenance="test")
    fuente.confirm()
    fuente.archive()
    mounted_app.config["BEHAVIOR_CONTEXT_REPOSITORY"].save(fuente)

    with mounted_app.test_request_context("/"):
        assert _prompt_context() == ""


def test_una_fuente_activa_llega_proyectada(mounted_app):
    from apate.web.blueprints.plugins import _prompt_context

    fuente = BehaviorContextSource(name="Activa", data=EXTRACTO_CRUDO, provenance="test")
    fuente.confirm()
    mounted_app.config["BEHAVIOR_CONTEXT_REPOSITORY"].save(fuente)

    with mounted_app.test_request_context("/"):
        contexto = _prompt_context()

    assert contexto
    for identificador in IDENTIFICADORES:
        assert identificador not in contexto, identificador
    assert "work_hours" in contexto


# -- Que no vuelva a leer el archivo crudo -----------------------------


def test_generate_activity_no_lee_context_json_del_directorio_de_trabajo(tmp_path, monkeypatch):
    """La regresión del hallazgo.

    Se deja un `context.json` con identificadores donde estaba, se llama sin
    pasar contexto, y se verifica que nada de ese archivo aparezca en lo que
    se le manda al modelo.
    """

    from BUDA.routes import ai_integration

    monkeypatch.chdir(tmp_path)
    (tmp_path / "context.json").write_text(json.dumps(EXTRACTO_CRUDO), encoding="utf-8")

    enviado = {}

    def _capturar(messages, *args, **kwargs):
        enviado["messages"] = messages
        return json.dumps({"activity_type": "x", "details": "y"})

    monkeypatch.setattr(ai_integration, "get_llm_response", _capturar)

    class _PerfilFalso:
        name = "Ana"
        role = "analyst"

    monkeypatch.setattr(
        ai_integration.db, "session", type("S", (), {"get": staticmethod(lambda *a: _PerfilFalso())})()
    )

    ai_integration.generate_activity(1, activity_type="Recon", details=None)

    texto = json.dumps(enviado["messages"], ensure_ascii=False)
    for identificador in IDENTIFICADORES:
        assert identificador not in texto, identificador
    assert "No context available." in texto

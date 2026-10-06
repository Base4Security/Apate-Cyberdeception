"""El worker de narrativas ejecuta un repertorio aprobado, no lo que diga un LLM.

**Qué fija este archivo, y por qué existe.** El worker le pedía comandos a un
modelo externo en cada paso —una llamada saliente cada 30 a 600 segundos— y
ejecutaba la respuesta por WinRM sobre los servidores reales del binding, sin
que nadie la mirara. Dos problemas serios a la vez para una herramienta que
corre adentro de la red que protege: egreso periódico no auditable, y ejecución
remota de contenido devuelto por un tercero. Y contradecía lo que la propia
interfaz promete: *"Generación, no decisión — ninguna sugerencia se aplica
sola"*.

Los tests están escritos para fallar si alguien vuelve a meter una llamada al
modelo en el bucle: el más importante no verifica qué se ejecuta sino **que no
se llame a nada externo**.
"""

from __future__ import annotations

import json

import pytest

from apate.web import create_app


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


def _crear_narrativa(mounted_app, *, comandos, dias=30):
    """Narrativa mínima con un perfil y una actividad, en la base de BUDA."""

    from datetime import date, timedelta

    from BUDA.app import db
    from BUDA.models import Activity, Narrative, UserProfile

    with mounted_app.app_context():
        actividad = Activity(activity_type="Recon", details="Revisión de carpetas")
        actividad.set_approved_commands(comandos)
        perfil = UserProfile(
            name="Ana",
            role="analyst",
            behavior_pattern="oficina",
            winrm_server="10.0.0.5",
            winrm_username="ana",
            winrm_password="secreta",
        )
        perfil.activities = [actividad]
        narrativa = Narrative(
            title="Narrativa de prueba",
            objective="probar",
            attacker_profile="ninguno",
            end_date=date.today() + timedelta(days=dias),
            percentage_of_similarity=50.0,
            is_running=False,
        )
        narrativa.user_profiles = [perfil]
        db.session.add_all([actividad, perfil, narrativa])
        db.session.commit()
        return narrativa.id


# -- El repertorio aprobado --------------------------------------------


def test_una_actividad_sin_comandos_no_aporta_nada_al_lote(mounted_app):
    from BUDA.app import db
    from BUDA.models import Narrative
    from BUDA.utils.narrative_worker import approved_batch

    narrativa_id = _crear_narrativa(mounted_app, comandos=[])

    with mounted_app.app_context():
        narrativa = db.session.get(Narrative, narrativa_id)
        assert approved_batch(narrativa) == []


def test_el_lote_lleva_los_comandos_guardados_por_el_operador(mounted_app):
    from BUDA.app import db
    from BUDA.models import Narrative
    from BUDA.utils.narrative_worker import approved_batch

    narrativa_id = _crear_narrativa(mounted_app, comandos=["Get-ChildItem", "Get-Process"])

    with mounted_app.app_context():
        narrativa = db.session.get(Narrative, narrativa_id)
        lote = approved_batch(narrativa)

        assert len(lote) == 1
        assert lote[0]["commands"] == ["Get-ChildItem", "Get-Process"]
        assert lote[0]["activity_type"] == "Recon"


def test_el_repertorio_descarta_vacios_y_normaliza(mounted_app):
    from BUDA.models import Activity

    actividad = Activity(activity_type="x")
    actividad.set_approved_commands(["  Get-Date  ", "", "   ", "Get-Host"])

    assert actividad.approved_commands() == ["Get-Date", "Get-Host"]


def test_un_json_invalido_en_el_campo_no_rompe_la_lectura(mounted_app):
    # Preferible a propagar: quien decide qué hacer sin repertorio es el
    # arranque de la narrativa, que se niega y lo dice.
    from BUDA.models import Activity

    actividad = Activity(activity_type="x")
    actividad.commands = "{no es json"

    assert actividad.approved_commands() == []


def test_un_json_que_no_es_lista_tampoco(mounted_app):
    from BUDA.models import Activity

    actividad = Activity(activity_type="x")
    actividad.commands = json.dumps({"commands": ["Get-Date"]})

    assert actividad.approved_commands() == []


# -- Falla cerrado -----------------------------------------------------


def test_la_narrativa_no_arranca_sin_repertorio_y_dice_cual_falta(mounted_app):
    """Arrancar y no ejecutar nada sería peor: la interfaz mostraría una
    narrativa "corriendo" que no hace nada."""

    from BUDA.app import db
    from BUDA.models import Narrative
    from BUDA.utils.narrative_worker import start_narrative

    narrativa_id = _crear_narrativa(mounted_app, comandos=[])

    with mounted_app.app_context():
        resultado = start_narrative(narrativa_id)

        assert "no tienen comandos aprobados" in resultado["message"]
        assert "Ana / Recon" in resultado["message"]
        assert db.session.get(Narrative, narrativa_id).is_running is False


def test_con_repertorio_la_narrativa_arranca(mounted_app, monkeypatch):
    from BUDA.app import db
    from BUDA.models import Narrative
    from BUDA.utils import narrative_worker

    # El hilo real dormiría entre 30 y 600 segundos; lo que se prueba acá es
    # que el arranque no se niega, no lo que hace el hilo.
    monkeypatch.setattr(narrative_worker.threading, "Thread", lambda *a, **k: type(
        "HiloFalso", (), {"daemon": True, "start": lambda self: None}
    )())

    narrativa_id = _crear_narrativa(mounted_app, comandos=["Get-Date"])

    with mounted_app.app_context():
        resultado = narrative_worker.start_narrative(narrativa_id)

        assert resultado["message"] == "Narrative started"
        assert db.session.get(Narrative, narrativa_id).is_running is True


# -- La regresión que importa -----------------------------------------


def test_el_bucle_no_llama_a_ningun_modelo_externo():
    """**Este es el test del hallazgo.**

    No verifica qué ejecuta el worker sino qué *no* consulta: si alguien
    vuelve a meter una llamada al modelo en el bucle, el nombre reaparece en
    el módulo y esto falla. Es una verificación de texto a propósito — un
    mock no sirve, porque lo que hay que impedir es que la llamada exista.
    """

    from pathlib import Path

    fuente = Path(narrative_worker_path()).read_text(encoding="utf-8")

    assert "generate_commands" not in fuente, (
        "El worker de narrativas volvió a llamar al generador asistido por LLM. "
        "Lo que se ejecuta sobre hosts reales tiene que salir de "
        "Activity.approved_commands(), aprobado por un operador."
    )
    assert "behavior_engine" not in fuente
    assert "get_llm_response" not in fuente


def narrative_worker_path() -> str:
    import BUDA.utils.narrative_worker as modulo

    return modulo.__file__


def test_el_generador_de_borrador_no_persiste_ni_ejecuta(mounted_app, monkeypatch):
    """La otra mitad del principio: el modelo propone, no aplica.

    La ruta devuelve comandos y **no** los guarda en la actividad; recién el
    POST del formulario, con el operador de por medio, los aprueba.
    """

    from BUDA.app import db
    from BUDA.models import Activity
    from BUDA.routes import ai_integration

    monkeypatch.setattr(
        ai_integration, "get_llm_response", lambda messages: json.dumps({"commands": ["Get-Date"]})
    )

    _crear_narrativa(mounted_app, comandos=[])
    cliente = mounted_app.test_client()

    with mounted_app.app_context():
        actividad_id = db.session.query(Activity).first().id

    respuesta = cliente.post(f"/capabilities/behavior-activities/{actividad_id}/generate-commands")

    assert respuesta.status_code == 200
    assert respuesta.get_json()["commands"] == ["Get-Date"]
    with mounted_app.app_context():
        assert db.session.get(Activity, actividad_id).approved_commands() == []

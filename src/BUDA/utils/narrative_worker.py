"""Ejecucion programada de una narrativa, desde el repertorio aprobado.

**Que cambio y por que.** Este worker le pedia comandos nuevos a un LLM en
cada paso -- una llamada saliente cada 30 a 600 segundos, durante toda la
vida de la narrativa -- y ejecutaba la respuesta como PowerShell por WinRM
sobre los servidores reales del binding, sin que nadie la mirara. Eran dos
problemas a la vez, y los dos serios para una herramienta que corre adentro
de la red que protege: **egreso periodico no auditable hacia un tercero**, y
**ejecucion remota de contenido devuelto por ese tercero**. Ademas
contradecia lo que la propia interfaz de APATE le promete al operador en la
pantalla de generacion asistida: *"Generacion, no decision -- el LLM produce
borradores... ninguna sugerencia se aplica sola"*.

Ahora el bucle **no tiene ninguna salida de red fuera del WinRM del propio
binding**. Ejecuta el repertorio que un operador reviso y guardo en cada
`Activity` (`Activity.approved_commands()`). El modelo sigue estando
disponible para *proponer* ese repertorio, pero la propuesta pasa por la
pantalla, no por el worker.
"""

import json
import threading
import time
from datetime import datetime
from flask import current_app
from ..app import db
from ..models import Narrative
from ..utils.orchestrator import execute_command
from ..utils.events import record_event
import random


narratives_to_stop = {}


def approved_batch(narrative):
    """El repertorio aprobado de la narrativa, en el formato que ejecuta el bucle.

    Devuelve una lista de `{"user_profile": <UserProfile>, "activity_type": str,
    "commands": [str, ...]}`, una entrada por actividad con comandos aprobados.
    Es una lectura de la base: no llama a nada externo y no puede fallar por
    red.
    """

    lote = []
    for perfil in narrative.user_profiles:
        for actividad in perfil.activities:
            comandos = actividad.approved_commands()
            if comandos:
                lote.append(
                    {
                        "user_profile": perfil,
                        "activity_type": actividad.activity_type,
                        "commands": comandos,
                    }
                )
    return lote


def missing_approved_commands(narrative):
    """Actividades sin repertorio, como `[(perfil, tipo_de_actividad), ...]`.

    Lo usa `start_narrative()` para negarse a arrancar **nombrando** lo que
    falta. Arrancar igual y no hacer nada seria peor que no arrancar: la
    interfaz mostraria una narrativa corriendo que no ejecuta nada.
    """

    faltantes = []
    for perfil in narrative.user_profiles:
        for actividad in perfil.activities:
            if not actividad.approved_commands():
                faltantes.append((perfil.name, actividad.activity_type))
    return faltantes


def narrative_engine(narrative_id, app):
    """
    Simulates a background process for the narrative.
    Stops when the end date is reached or the user manually stops it.
    """
    with app.app_context():
        narrative = db.session.get(Narrative, narrative_id)
        if not narrative:
            return
        
        while narrative.is_running:
            # Refresh the narrative object from the database
            if narrative.id in narratives_to_stop:
                narrative.is_running = False
                db.session.commit()
                del narratives_to_stop[narrative.id]
                return
            
            # Check if the narrative has reached its end date
            if datetime.now().date() >= narrative.end_date:
                narrative.is_running = False
                db.session.commit()
                return
            
            # Code execution for the narrative
            # Add current execution date to log

            print(f"{datetime.now().date()} - Running Narrative {narrative.id} - {narrative.title} - End Date: {narrative.end_date}")
            record_event(
                kind="narrative_step",
                detail=f"Running narrative '{narrative.title}' (id={narrative.id}), end date {narrative.end_date}",
                narrative_id=narrative.id,
            )

            # El repertorio se relee en cada paso a proposito: si el operador
            # corrige o retira comandos mientras la narrativa corre, el cambio
            # tiene efecto en el paso siguiente sin reiniciar nada. Es una
            # lectura de la base, no una llamada de red.
            commands = approved_batch(narrative)

            if not commands:
                # Quedarse sin repertorio a mitad de la narrativa solo puede
                # pasar si el operador lo vacio. Detener y decirlo es la unica
                # respuesta honesta: seguir girando mostraria en la interfaz
                # una narrativa "corriendo" que no ejecuta nada.
                detail = (
                    f"Narrativa '{narrative.title}' (id={narrative.id}) detenida: "
                    f"ninguna actividad de sus perfiles tiene comandos aprobados."
                )
                print(f"{datetime.now().date()} - [NW] {detail}")
                record_event(kind="narrative_error", detail=detail, narrative_id=narrative.id)
                narrative.is_running = False
                db.session.commit()
                return

            # Ejecuta el repertorio aprobado. Ninguna llamada saliente fuera
            # del WinRM del propio binding.
            for command_set in commands:
                user_profile = command_set["user_profile"]
                record_event(
                    kind="narrative_activity",
                    detail=(
                        f"Ejecutando actividad '{command_set['activity_type']}' "
                        f"del perfil '{user_profile.name}' "
                        f"({len(command_set['commands'])} comandos aprobados)"
                    ),
                    narrative_id=narrative.id,
                )
                for cmd in command_set["commands"]:
                    print(f"{datetime.now().date()} - [NW]Executing command: {cmd}")
                    output = execute_command(narrative,  user_profile, cmd)
    
            # Sleep random time between 30 and 600 seconds
            sleep_time = random.randint(30, 600)
            print(f"{datetime.now().date()} - [NW]Sleeping for {sleep_time} seconds")
            record_event(
                kind="narrative_step",
                detail=f"Sleeping for {sleep_time} seconds before the next step of narrative {narrative.id}",
                narrative_id=narrative.id,
            )
            time.sleep(sleep_time)

def start_narrative(narrative_id):
    """
    Starts a narrative process in a background thread.
    """
    app = current_app._get_current_object()

    with app.app_context():
        narrative = db.session.get(Narrative, narrative_id)
        if not narrative:
            return {"message": f"Narrative not found"}
        
        if datetime.now().date() >= narrative.end_date:
            return {"message": f"Narrative has already reached its end date"}
        
        if not narrative.user_profiles:
            return {"message": f"Narrative has no user profiles"}
        
        for narrative_user_profile in narrative.user_profiles:
            if not narrative_user_profile.activities:
                return {"message": f"User profile '{narrative_user_profile.name}' has no activity types"}

        # Falla cerrado: sin repertorio aprobado no se arranca, y se dice cual
        # falta. La alternativa -- arrancar y no ejecutar nada -- deja al
        # operador mirando una narrativa "corriendo" que no hace nada, que es
        # la peor de las dos.
        faltantes = missing_approved_commands(narrative)
        if faltantes:
            detalle = ", ".join(f"{perfil} / {actividad}" for perfil, actividad in faltantes)
            return {
                "message": (
                    "No se puede iniciar: estas actividades no tienen comandos aprobados "
                    f"({detalle}). Cargalos en el Catalogo de capacidades antes de desplegar."
                )
            }

        narrative.is_running = True
        db.session.commit()

    thread = threading.Thread(target=narrative_engine, args=(narrative_id, app))
    thread.daemon = True
    thread.start()
    
    return {"message": f"Narrative started"}

def stop_narrative(narrative_id):
    """
    Stops a running narrative process.
    """

    app = current_app._get_current_object()

    with app.app_context():
        narrative = db.session.get(Narrative, narrative_id)
        if not narrative:
            return {"error": f"Narrative not found"}

        narrative.is_running = False
        db.session.commit()
        narratives_to_stop[narrative_id] = True
        return {"message": f"Narrative '{narrative.title}' queued for stopping."}

    return

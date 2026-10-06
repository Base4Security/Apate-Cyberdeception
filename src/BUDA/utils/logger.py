"""Registro de comandos ejecutados por narrativa.

**Dos correcciones respecto de la version original, y las dos importan.**

1. **El import ya no escribe en el disco.** Antes este modulo hacia
   `os.makedirs("logs", exist_ok=True)` a nivel de modulo, con ruta relativa
   al directorio de trabajo. Como `apate.web` lo importa en cadena
   (`_activity_ingestion` -> `buda_plugin` -> `narrative_worker` ->
   `orchestrator` -> aca), un proceso arrancado desde un directorio no
   escribible -- un `gunicorn` bajo systemd sin `WorkingDirectory`, por
   ejemplo -- moria en el import con un `PermissionError` que ni siquiera
   nombraba a APATE. Un import no debe tocar el sistema de archivos.

2. **Los logs viven bajo `APATE_DATA_DIR`**, no en el directorio de trabajo.
   Sin esa variable -- BUDA corriendo solo -- se conserva `logs/` relativo,
   igual que antes.

Y una decision de fondo: **el registro no puede romper la ejecucion**. Si no
se puede escribir, se degrada a un logger sin destino y la narrativa sigue.
Perder una linea de log es malo; que un log caido detenga una operacion de
engano es peor.
"""

import logging
import os
from datetime import datetime

LOG_DIR_NAME = "logs"


def _log_dir():
    """El directorio de logs, resuelto en cada llamada y no al importar."""

    try:
        from apate.runtime_paths import runtime_path

        return runtime_path(LOG_DIR_NAME)
    except Exception:
        # BUDA corriendo fuera de APATE: comportamiento historico.
        from pathlib import Path

        return Path(LOG_DIR_NAME)


def get_log_filename():
    """
    Generates a log filename based on the current date and hour.
    Format: <APATE_DATA_DIR>/logs/YYYY-MM-DD_HH.log
    """
    current_time = datetime.now()
    return os.path.join(str(_log_dir()), f"{current_time.strftime('%Y-%m-%d_%H')}.log")


def setup_logger():
    """
    Configures the logger to write logs into a separate file based on time.

    Devuelve un logger sin destino si el archivo no se puede abrir, en vez de
    propagar: ver el docstring del modulo.
    """

    logger = logging.getLogger("command_execution")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    try:
        os.makedirs(str(_log_dir()), exist_ok=True)
        file_handler = logging.FileHandler(get_log_filename())
    except OSError:
        logger.addHandler(logging.NullHandler())
        logger.warning("No se pudo abrir el archivo de log de comandos; se continua sin registrarlo.")
        return logger

    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - [Narrative ID: %(message)s]", "%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def log_command(narrative_id, user_profile, command, output):
    """
    Logs executed commands per narrative and user profile into a time-based log file.
    """
    logger = setup_logger()
    log_entry = f"{narrative_id}] [User: {user_profile}] Command: {command} | Output: {output}"
    logger.info(log_entry)

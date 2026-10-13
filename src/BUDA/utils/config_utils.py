import os
import json
from flask import jsonify

from apate.secrets import get_default_secret_cipher

CONFIG_FILE_NAME = "config_llm.json"


def _config_file():
    """La ruta del JSON, resuelta al usarse y bajo `APATE_DATA_DIR`.

    Antes era una constante relativa al directorio de trabajo, asi que la
    configuracion del modelo se guardaba en un lugar distinto segun desde
    donde se hubiera arrancado el proceso.
    """

    try:
        from apate.runtime_paths import runtime_path

        return str(runtime_path(CONFIG_FILE_NAME))
    except Exception:
        return CONFIG_FILE_NAME

def load_llm_config():
    """Carga la configuración LLM y descifra su clave para uso en memoria."""
    if os.path.exists(_config_file()):
        with open(_config_file(), "r", encoding="utf-8") as file:
            config = json.load(file)
        api_key = config.get("api_key")
        if isinstance(api_key, str):
            config["api_key"] = get_default_secret_cipher().decrypt(api_key)
        return config
    else:
        return jsonify({"error": "No LLM settings found"}), 404
    
def save_llm_config(new_config):
    """Guarda la configuración LLM con la clave de API cifrada."""
    try:
        stored_config = dict(new_config)
        api_key = stored_config.get("api_key")
        if isinstance(api_key, str):
            stored_config["api_key"] = get_default_secret_cipher().encrypt(api_key)
        with open(_config_file(), "w", encoding="utf-8") as file:
            json.dump(stored_config, file, indent=4)
        return {"message": "Settings updated successfully"}
    except Exception as e:
        return {"error": str(e)}

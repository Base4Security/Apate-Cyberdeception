import os


def _runtime_dir():
    """El directorio de estado de APATE, o el de trabajo si corre solo."""

    try:
        from apate.runtime_paths import runtime_dir

        return str(runtime_dir())
    except Exception:
        # DOLOS-T fuera de APATE: comportamiento historico.
        return os.getcwd()


class Context:
    """
    A class defining the context for the DOLOST application.

    `CONFIG_PATH` dejo de ser un atributo de clase calculado al importar.
    **Ese era el problema**: se resolvia contra el directorio de trabajo del
    proceso y en el momento del import, o sea antes de que APATE pudiera
    declarar donde vive su estado. El resultado era que la configuracion del
    cliente Docker se guardaba en un lugar distinto segun desde donde se
    hubiera arrancado, y se perdia en cualquier reinstalacion. Ahora es un
    metodo que resuelve en cada uso, bajo `APATE_DATA_DIR`.

    Attributes:
        base_dir (str): The absolute path of the base directory.
        CONFIG_FOLDER (str): The folder name for Docker client configuration.
        CONFIG_FILE (str): The configuration file name.
    """

    base_dir = os.path.abspath(os.path.dirname(__file__))
    CONFIG_FOLDER = 'docker_client_config'
    CONFIG_FILE = 'config.json'

    @classmethod
    def config_folder(cls):
        """El directorio de configuracion, bajo el estado declarado."""

        return os.path.join(_runtime_dir(), cls.CONFIG_FOLDER)

    @classmethod
    def config_path(cls):
        """El archivo de configuracion del cliente Docker."""

        return os.path.join(cls.config_folder(), cls.CONFIG_FILE)

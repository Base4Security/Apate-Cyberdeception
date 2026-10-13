"""Excepciones de la capa de integracion por plugins (M2)."""

from __future__ import annotations

from apate.core.exceptions import ApateError


class PluginStateError(ApateError):
    """Se invoco deploy()/rotate()/retire() en un estado del ciclo de
    vida del plugin que no lo permite (por ejemplo, desplegar dos
    veces, o retirar sin haber desplegado antes)."""


class HoneytokenFileError(ApateError):
    """Fallo real de E/S en HoneytokenPlugin (M7): falta 'directory' en
    la configuracion, no se pudo escribir/eliminar un senuelo, o no se
    pudo confirmar que un borrado se concreto. No hereda de
    PluginStateError porque no es un problema de ciclo de vida sino de
    filesystem."""


class PluginConfigError(ApateError):
    """Falta configuracion requerida en `config` (PluginBinding.config)
    para que el plugin pueda operar -- por ejemplo, BudaPlugin (M8c)
    necesita 'narrative_id' para saber que narrativa de BUDA
    desplegar/rotar/retirar."""


class CanarytokenAPIError(ApateError):
    """Fallo real al hablar con el servidor de Canarytokens self-hosted
    (CanarytokenPlugin): conexion rechazada/timeout, respuesta HTTP no
    exitosa, o una respuesta bien formada pero con `error` seteado (el
    formato de error real de `POST {base_url}/generate`, verificado
    contra una instancia real -- ver apate.plugins.canarytoken_client).
    No hereda de PluginStateError: no es un problema de ciclo de vida
    sino de la API externa."""


class OpenCanaryError(ApateError):
    """Fallo real al hablar con Docker para desplegar/reiniciar/retirar
    un contenedor OpenCanary, o al leer sus logs (OpenCanaryPlugin,
    apate.plugins.opencanary_client) -- conexion con el daemon
    rechazada, puerto ya ocupado (docker-py devuelve un APIError claro
    al crear el contenedor, ver docstring de opencanary_client sobre
    por que esto es preferible a network_mode=host), o el contenedor no
    responde. No hereda de PluginStateError: no es un problema de ciclo
    de vida sino de la infraestructura Docker externa."""

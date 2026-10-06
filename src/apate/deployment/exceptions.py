"""Excepciones de la capa de despliegue empresarial."""

from __future__ import annotations

from ..core.exceptions import ApateError


class DeploymentError(ApateError):
    """Base para errores de planificación y ejecución de despliegues."""


class DeploymentNotFoundError(DeploymentError):
    """El plan o registro solicitado no existe."""


class DeploymentValidationError(DeploymentError):
    """El destino o la configuración no satisfacen al conector."""


class DeploymentExecutionError(DeploymentError):
    """El conector falló después de comenzar una acción real."""


class InvalidDeploymentTransitionError(DeploymentError):
    """El registro intentó una transición de estado inválida."""

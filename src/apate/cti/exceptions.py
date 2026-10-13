"""Excepciones de apate.cti -- Fase 6 post-BlackHat (ver docs/roadmap.md)."""

from __future__ import annotations


class CTIExtractionError(Exception):
    """Error al extraer texto de un informe de CTI cargado -- formato
    no soportado, archivo vacio/demasiado grande, o PDF ilegible. El
    mensaje esta pensado para mostrarse tal cual en un flash()/JSON de
    error, no solo para debugging."""

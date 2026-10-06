"""Datos de ejemplo del dashboard de impacto para presentaciones.

La vista ``/impact/`` es deliberadamente un prototipo: este módulo es su
única fuente de datos y no consulta repositorios de operaciones, telemetría
ni reglas. Las claves imitan las piezas que un adaptador real aportaría
después (cobertura ATT&CK, métricas, actividad e infraestructura), para que
el cambio futuro sea sustituir esta función, no rediseñar la pantalla.
"""

from __future__ import annotations

from ..attack import list_techniques
from ..i18n import gettext as _


_COVERAGE_BY_TTP = {
    "T1046": "matched",
    "T1110": "matched",
    "T1190": "matched",
    "T1041": "matched",
    "T1021": "not-observed",
    "T1078": "not-observed",
    "T1059": "not-observed",
    "T1105": "not-observed",
    "T1552": "unexpected",
}


def impact_dashboard_mock() -> dict:
    """Devuelve la fotografía coherente, aislada y mutable del prototipo.

    Los identificadores y proveedores evocan las operaciones APT28, FIN7 y
    Lazarus del seed de demo, pero sus conteos y eventos son ficticios. El
    catálogo ATT&CK es estático y local; se usa solo para conservar las trece
    tácticas y los nombres de técnica que ya conoce la interfaz.
    """

    techniques_by_tactic: dict[str, list] = {}
    for technique in list_techniques():
        techniques_by_tactic.setdefault(technique.tactic, []).append(technique)

    return {
        "is_mock": True,
        "generated_at": _("Actualizado hace 12 s"),
        "heatmap": [
            {
                "tactic": tactic,
                "cells": [
                    {
                        "id": technique.id,
                        "name": technique.name,
                        "status": _COVERAGE_BY_TTP.get(technique.id),
                    }
                    for technique in techniques
                ],
            }
            for tactic, techniques in sorted(techniques_by_tactic.items())
        ],
        "metrics": [
            {"label": _("Eventos"), "value": "2.847", "detail": _("%(change)s más en la última hora", change="+18 %")},
            {"label": _("TTPs observadas"), "value": "18", "detail": _("9 coincidentes")},
            {"label": "IoCs", "value": "63", "detail": _("7 priorizados")},
            {"label": _("Reglas disparadas"), "value": "42", "detail": _("0 rechazadas")},
            {"label": _("Capacidades"), "value": "12", "detail": _("10 desplegadas")},
        ],
        "activity": [
            {
                "time": "14:32:08",
                "severity": "critical",
                "source": "dolost-lazarus-exfil",
                "message": _("Transferencia saliente hacia infraestructura no autorizada"),
            },
            {
                "time": "14:31:41",
                "severity": "high",
                "source": "buda-fin7-hr",
                "message": _("Acceso fuera del patrón de soporte remoto"),
            },
            {
                "time": "14:31:09",
                "severity": "medium",
                "source": "dolost-apt28-finance",
                "message": _("Fuerza bruta SSH detectada en gateway señuelo"),
            },
            {
                "time": "14:30:26",
                "severity": "medium",
                "source": "honeytoken-finanzas",
                "message": _("TTP T1552.001 observada al acceder a credenciales"),
            },
        ],
        "infrastructure": [
            {
                "label": _("Decoys de red"),
                "value": "4 / 5",
                "status": "up",
                "detail": _("SshFinanceGateway, FileServerBackup y 2 más en línea"),
            },
            {
                "label": _("Narrativas activas"),
                "value": "2",
                "status": "up",
                "detail": _("Soporte RRHH y cierre contable simulados"),
            },
            {
                "label": _("Honeytokens desplegados"),
                "value": "6",
                "status": "up",
                "detail": _("1 acceso pendiente de triage"),
            },
            {
                "label": _("Dependencias externas"),
                "value": _("1 atención"),
                "status": "unknown",
                "detail": _("Canarytoken: último sondeo hace 4 min"),
            },
        ],
    }

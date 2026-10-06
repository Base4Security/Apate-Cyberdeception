"""Retroalimentacion CTI (M6) y kit de taller colaborativo (M12i) - ver
documento de diseno, seccion 4.3."""

from .dry_run import DryRunChain, DryRunFinding, DryRunStep, OperationDryRun, simulate_dry_run
from .generator import TTPComparison, compare_ttps, generate_report, plugin_effect_summaries
from .models import OperationReport, PluginEffectSummary, WorkshopKit
from .workshop import generate_workshop_kit

__all__ = [
    "DryRunChain",
    "DryRunFinding",
    "DryRunStep",
    "OperationDryRun",
    "OperationReport",
    "PluginEffectSummary",
    "TTPComparison",
    "WorkshopKit",
    "compare_ttps",
    "generate_report",
    "generate_workshop_kit",
    "plugin_effect_summaries",
    "simulate_dry_run",
]

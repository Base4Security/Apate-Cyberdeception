"""Catalogo de MITRE Engage (M12a) - ver apate.engage.catalog. Motor
de sugerencia TTP -> actividades (M12d) y objetivo estrategico ->
actividades - ver apate.engage.suggestions."""

from .catalog import (
    Activity,
    Approach,
    Goal,
    get_activity,
    list_activities,
    list_approaches,
    list_goals,
)
from .suggestions import suggest_activities, suggest_activities_for_objectives

__all__ = [
    "Activity",
    "Approach",
    "Goal",
    "get_activity",
    "list_activities",
    "list_approaches",
    "list_goals",
    "suggest_activities",
    "suggest_activities_for_objectives",
]

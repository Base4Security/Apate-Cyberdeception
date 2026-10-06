"""Traducciones pequeñas de la GUI local; el texto fuente está en español."""

from __future__ import annotations

from flask import request, session


ENGLISH = {
    "Navegación principal": "Main navigation",
    "Idioma": "Language",
    "inicio": "home",
    "Operaciones de ciberengaño": "Cyberdeception operations",
    "en un flujo local y trazable.": "in a local, traceable workflow.",
    "Operaciones": "Operations",
    "OPERACIONES": "OPERATIONS",
    "Reglas": "Rules",
    "Telemetría": "Telemetry",
    "Entorno local · simulación": "Local environment · simulation",
    "ALFA": "ALPHA",
    "Ejecución local": "Local run",
    "Control de operaciones": "Operation control",
    "Perfil, reglas de interacción y observaciones alrededor de una misma operación.": "Adversary profile, rules of engagement, and observations in one operation.",
    "+ Nueva operación": "+ New operation",
    "Resumen de operaciones": "Operation summary",
    "ACTIVAS": "ACTIVE",
    "CERRADAS": "CLOSED",
    "Operación": "Operation",
    "Estado": "Status",
    "Perfil de adversario": "Adversary profile",
    "Creada": "Created",
    "Abrir →": "Open →",
    "Planificada": "Planning",
    "Activa": "Active",
    "Comprometida": "Compromised",
    "Cerrada": "Closed",
    "Todavía no hay operaciones creadas. Empezá con una operación local o ejecutá el ejemplo de demostración.": "No operations yet. Create a local operation or run the demo example.",
    "Nueva operación": "New operation",
    "Marcar activa": "Mark active",
    "Marcar comprometida": "Mark compromised",
    "Cerrar": "Close",
    "Ver telemetría de esta operación →": "View telemetry for this operation →",
    "Nombre": "Name",
    "Motivación": "Motivation",
    "Nivel de habilidad": "Skill level",
    "TTPs esperadas": "Expected TTPs",
    "Reglas de interacción": "Rules of engagement",
    "Entorno": "Environment",
    "Acciones permitidas": "Allowed actions",
    "Acciones prohibidas": "Forbidden actions",
    "Contacto de escalamiento": "Escalation contact",
    "Narrativa": "Narrative",
    "Descripción": "Description",
    "% de similitud": "Similarity %",
    "Escenarios": "Scenarios",
    "TTPs relacionadas": "Related TTPs",
    "Nivel de engaño": "Deception level",
    "Sin escenarios asociados.": "No scenarios linked.",
    "Plugins asociados": "Linked plugins",
    "Superficie": "Surface",
    "Sin plugins asociados.": "No plugins linked.",
    "Perfil de adversario (paso 1)": "Adversary profile (step 1)",
    "Nombre / actor": "Name / actor",
    "TTPs esperadas (separadas por coma, ej. T1046, T1078)": "Expected TTPs (comma-separated, e.g. T1046, T1078)",
    "Rules of Engagement (paso 2)": "Rules of engagement (step 2)",
    "Entorno de despliegue": "Deployment environment",
    "Narrativa (paso 5)": "Narrative (step 5)",
    "Crear operación": "Create operation",
    "Cancelar": "Cancel",
    "Reglas del motor de decisión": "Decision engine rules",
    "Formato condición-acción en YAML. Guardar valida el documento antes de sobreescribir el archivo; cualquier motor que lea ese mismo archivo ve las reglas nuevas en su próxima carga.": "Condition/action rules in YAML. Saving validates the document before replacing the file; any engine reading it sees the new rules on its next load.",
    "Documento YAML inválido": "Invalid YAML document",
    "Reglas cargadas": "Loaded rules",
    "Condición": "Condition",
    "Acciones": "Actions",
    "todos": "all",
    "No hay reglas cargadas todavía.": "No rules loaded yet.",
    "Editar": "Edit",
    "Guardar y recargar": "Save and reload",
    "Elegí una operación para ver sus eventos, IoCs y TTPs observadas.": "Select an operation to see its events, IoCs, and observed TTPs.",
    "Ver telemetría": "View telemetry",
    "Todavía no hay operaciones creadas.": "No operations yet.",
    "Telemetría de la operación": "Operation telemetry",
    "ver operación": "view operation",
    "Filtrar por plugin": "Filter by plugin",
    "Filtrar por superficie": "Filter by surface",
    "(todos)": "(all)",
    "(todas)": "(all)",
    "Filtrar": "Filter",
    "TTPs observadas": "Observed TTPs",
    "Sin TTPs observadas todavía.": "No TTPs observed yet.",
    "Tipo": "Type",
    "Valor": "Value",
    "Sin IoCs observados todavía.": "No IoCs observed yet.",
    "Eventos": "Events",
    "Sin eventos registrados todavía para esta operación": "No events recorded for this operation yet",
    "con este filtro": "with this filter",
    "Operación '{}' creada.": "Operation '{}' created.",
    "Transición desconocida: '{}'.": "Unknown transition: '{}'.",
    "Operación transicionada a '{}'.": "Operation transitioned to '{}'.",
    "No se guardó: {}": "Not saved: {}",
    "Reglas guardadas y recargadas: {} regla(s).": "Rules saved and reloaded: {} rule(s).",
}


def current_language() -> str:
    """Consulta el idioma de la sesión sin alterar el contenido persistido."""

    return session.get("ui_language", "es")


def select_language() -> None:
    """Acepta sólo los idiomas de la interfaz; ignora otros valores."""

    selected = request.args.get("lang")
    if selected in {"es", "en"}:
        session["ui_language"] = selected


def translate(message: str, language: str | None = None) -> str:
    """Traduce una etiqueta visible y conserva el texto fuente como respaldo."""

    if (language or current_language()) == "en":
        return ENGLISH.get(message, message)
    return message

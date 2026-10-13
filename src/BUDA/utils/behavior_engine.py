def generate_commands(narrative_id):
    """
    Calls the AI integration function directly to generate PowerShell commands.

    Refactored during APATE roadmap milestone M14e: this used to make an
    HTTP self-call to http://127.0.0.1:5000/buda/ai/generate_commands/{id}
    (fixed to include the missing '/buda' prefix in the M14c follow-up --
    see git log for that fix). That URL stopped resolving to anything once
    ai_bp is no longer registered as a Flask blueprint when BUDA runs
    inside APATE (M14e retires mount_buda()'s blueprint registration
    entirely -- BUDA becomes a pure library there, same as DOLOS-T since
    M14b). Calls routes.ai_integration.generate_ai_commands() directly
    instead -- that function already only needed an active Flask
    application context (never read request.json), which the only real
    caller, utils/narrative_worker.py::narrative_engine(), already
    guarantees (`with app.app_context():`).

    Return shape is unchanged on purpose (a list: either the AI's
    {"commands": [...]} on success, or ["Error: ..."] on failure) --
    narrative_worker.py::_is_valid_command_batch() already depends on
    telling those two shapes apart.
    """
    from ..routes.ai_integration import generate_ai_commands

    try:
        result = generate_ai_commands(narrative_id)
    except Exception as e:
        return [f"Error: {str(e)}"]

    if "error" in result:
        return [f"Error: {result['error']}"]

    return result.get("commands", ["Error: AI did not return commands"])

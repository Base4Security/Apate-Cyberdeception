from flask import Blueprint, request, jsonify, current_app
import os
from ..app import db
from ..models.user import UserProfile
from ..models.narrative import Narrative
from ..models.activity import Activity
import json

from ..utils.llm_utils import get_llm_response


ai_bp = Blueprint('ai', __name__)

CONTEXT_FILE = 'context.json'

def load_context():
    if not os.path.exists(CONTEXT_FILE):
        return "No context available."
    with open(CONTEXT_FILE, 'r') as f:
        return f.read()

@ai_bp.route('/upload_context', methods=['POST'])
def upload_context():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    # Save the uploaded file as context.txt
    file.save(CONTEXT_FILE)
    return jsonify({"message": f"Context saved successfully in {CONTEXT_FILE}"}), 200

@ai_bp.route('/generate/narrative', methods=['POST'])
def generate_narrative():
    data = request.json
    title = data.get('title')
    objective = data.get('objective')
    attacker_profile = data.get('attacker_profile')
    deception_activities = data.get('deception_activities')

    context = load_context()

    percentage_of_similarity = "100"

    # Generate the prompt
    narrative_prompt = """
                        Generate a new honey narrative
                        narrative_context { title: """ + f" {title}" + """, objective: """ + f" {objective}" + """, attacker_profile: """ + f" {attacker_profile}" + """, deception_activities: """ + f" {deception_activities}" + """ }
                        The narrative its a honey narrative that is a fake narrative that is used to attract attackers.
                        Use the context and thee narrative_context as a reference not to be copied. Do not use the context data.
                        The narrative is""" + f" {percentage_of_similarity}" + """% similar to the context.

                        The narrative must use the next base:
                        { title: "title", objective: "objective", attacker_profile: "attacker profile", deception_activities: "deception activities" }
                        - Title is the title of the narrative. Its a brief description of the narrative. Use the context as a reference for choosing a title.
                        - Objective is the objective of the narrative. Its a brief description of the narrative objective. Use the context as a reference for choosing an objective.
                        - Attacker Profile is a brief description of the attacker characteristics. Its a brief description of the attacker. Use the context as a reference for choosing an attacker profile.
                        - Deception Activities is a brief description of the activities in the narrative. Its a brief description of the activities in the narrative. Use the context as a reference for choosing deception activities.
                        
                        Return the narrative in JSON object in plain text.
                    """
    
    messages = [
        {"role": "system", "content": "You are a helpful cybersecurity proffesional that generates structured data"},
        {"role": "user", "content": f" Context:\n {context} \n\n {narrative_prompt}\n"}
    ]

    result = get_llm_response(messages)

    return jsonify({"message": result}), 200

@ai_bp.route('/generate/user_profile', methods=['POST'])
def generate_user_profile():
    data = request.json
    narrative_id = data.get('narrative_id')
    if not narrative_id:
        return jsonify({"error": "Missing narrative_id in request"}), 400
    narrative = db.get_or_404(Narrative, narrative_id)

    name = data.get('name')
    role = data.get('role')
    behavior_pattern = data.get('behavior_pattern')

    context = load_context()

    percentage_of_similarity = "100"

    # Generate the prompt
    user_profile_prompt = """
                            Generate a new honey user profile 
                            user_profile_context { complete_name: """ + f" {name}" + """, role: """ + f" {role}" + """, behavior_pattern: """ + f" {behavior_pattern}" + """ }
                            The user its a honey user that is a fake user that is used to attract attackers.
                            Use the context and thee user_profile_context as a reference not to be copied. Do not use the context data.
                            The user profile is""" + f" {percentage_of_similarity}" + """% similar to the context.
                            
                            The user profile must use the next base:
                            { complete_name: "name lastname", role: "organization role", behavior_pattern: "some pattern" }
                            - Name is the name and lastname of a user. Its a human name. Use the context as a reference for choosing a name.
                            - Role is the role of the user. Its a typical organization role. Use the context as a reference for choosing a role.
                            - The Behavior Pattern is a brief description of typical activities in the envinronment. It describe the user behavior in the system. Use the context as a reference for choosing a behavior pattern.

                            Return the profile in JSON object in plain text.
                        """

    messages = [
        {"role": "system", "content": "You are a helpful cybersecurity proffesional that generates structured data"},
        {"role": "user", "content": f" Context:\n {context} \n\n {user_profile_prompt}\n"}
    ]    

    result = get_llm_response(messages)

    return jsonify({"message": result}), 200

def generate_activity(user_profile_id, activity_type=None, details=None, context=None):
    """
    Genera con asistencia LLM un tipo de actividad para un perfil de usuario.

    Desde M14e recibe sus argumentos de forma explícita, en lugar de leerlos
    de ``request.json``. La integración histórica llamaba por HTTP al
    blueprint ``/buda/ai``; el Catálogo de capacidades actual consume esta
    función Python directamente. Solo requiere un contexto de aplicación
    Flask activo para consultar ``UserProfile``, igual que
    ``BudaPlugin.deploy()`` y ``BudaPlugin.retire()``.

    Lanza ``ValueError`` cuando falta ``user_profile_id`` y ``LookupError``
    cuando el perfil no existe. Así conserva los antiguos estados 400/404
    sin acoplar la función reutilizable a ``abort()`` o ``get_or_404()``.

    **``context`` se recibe; ya no se lee de ``context.json``.** Antes esta
    función hacía ``load_context()``, que es un ``read()`` plano del archivo
    del directorio de trabajo, y lo pegaba entero al prompt: nombres de
    usuario, IPs internas y nombres de equipos del cliente salían hacia el
    modelo externo en cada generación. Peor, salteaba el repositorio curado
    de APATE (``apate.core.behavior_context``), así que una fuente que el
    operador había descartado en la interfaz seguía viajando igual, porque
    ``import_legacy()`` copia el archivo "sin eliminarlo".

    Quien llama decide qué contexto mandar y se hace responsable de él.
    APATE pasa la proyección sin identificadores de sus fuentes **activas**
    (``BehaviorContextSource.prompt_summary()``); BUDA autónomo conserva su
    comportamiento histórico pasando ``load_context()`` explícitamente desde
    su propia ruta HTTP. Sin ``context`` no se busca ninguno: se genera sin
    contexto y se dice, que es la respuesta correcta a "no me dieron uno".
    """
    if not user_profile_id:
        raise ValueError("Missing user_profile_id in request")
    user_profile = db.session.get(UserProfile, user_profile_id)
    if user_profile is None:
        raise LookupError(f"UserProfile {user_profile_id} not found")

    context = context or "No context available."

    percentage_of_similarity = "100"

    # Generate the prompt
    activitytype_prompt = """
                        Generate a new honey activity type
                        activity_context { activity_type: """ + f" {activity_type}" + """, details: """ + f" {details}" + """ }
                        The activity type its a honey activity type that is a fake activity that is used to attract attackers.
                        Use the context and thee activity_context as a reference not to be copied. Do not use the context data.
                        The activity type is""" + f" {percentage_of_similarity}" + """% similar to the context.

                        The activity type must use the next base:
                        { activity_type: "activity_type", details: "details" }
                        - activity_type is the title of the type of a normal user activity based on the context elements. Its a brief description of the activity. Use the context as a reference for choosing a description.
                        - Details is a string describing the activity. Its a brief description of the activity. Use the context as a reference for choosing details.

                        Return the activity in JSON object in plain text.
                    """

    messages = [
        {"role": "system", "content": "You are a helpful cybersecurity proffesional that generates structured data"},
        {"role": "user", "content": f" Context:\n {context} \n\n {activitytype_prompt}\n"}
    ]

    return get_llm_response(messages)


def generate_activity_commands(activity_type, details=None, profile_role=None, context=None):
    """Propone comandos de PowerShell para un tipo de actividad. **Borrador.**

    Lo que devuelve **no se ejecuta**: va a la pantalla, el operador lo lee,
    lo corrige y decide si lo guarda como repertorio aprobado de la actividad
    (`Activity.set_approved_commands()`). Recien entonces el worker de
    narrativas lo ejecuta. Esa separacion es el punto: antes el worker le
    pedia comandos al modelo y los corria directo por WinRM cada 30-600
    segundos, sin que nadie los viera.

    `context` se recibe, igual que en `generate_activity()`: quien llama
    decide que mandar. APATE manda la proyeccion sin identificadores de sus
    fuentes activas, nunca el volcado crudo.

    Devuelve una lista de cadenas. Lanza `ValueError` si falta el tipo de
    actividad, y devuelve lista vacia si el modelo no produjo nada usable --
    el operador ve "no se pudo generar", no un comando inventado.
    """

    if not activity_type or not str(activity_type).strip():
        raise ValueError("Missing activity_type")

    prompt = f"""
        You are a cybersecurity expert defining what NORMAL day-to-day activity
        looks like for a simulated user on a Windows workstation.

        - **Activity type:** {activity_type}
        - **Details:** {details or "(none given)"}
        - **User role:** {profile_role or "(unspecified)"}

        Suggest up to 5 PowerShell commands that a real user in that role would
        plausibly run as part of that activity. They must be read-only or
        otherwise harmless: no destructive operations, no credential access, no
        changes to system configuration. A human operator will review every
        command before any of them runs.

        Return ONLY a JSON object, in plain text, shaped like:
        {{ "commands": ["cmd1", "cmd2"] }}
    """

    messages = [
        {"role": "system", "content": "You are a cybersecurity professional that generates structured JSON data."},
        {"role": "user", "content": f" Context:\n {context or 'No context available.'} \n\n {prompt}\n"},
    ]

    try:
        resultado = json.loads(get_llm_response(messages))
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    comandos = resultado.get("commands", []) if isinstance(resultado, dict) else []
    if not isinstance(comandos, list):
        return []
    return [str(item).strip() for item in comandos if str(item).strip()]


@ai_bp.route('/generate/activitytype', methods=['POST'])
def generate_activity_view():
    """Thin HTTP wrapper over generate_activity() -- kept so any
    external caller of BUDA running standalone (outside APATE) that
    still depends on this exact route keeps working; APATE itself
    stopped using it (calls generate_activity() directly, see M14e)."""

    data = request.json or {}
    try:
        result = generate_activity(
            data.get('user_profile_id'),
            activity_type=data.get('activity_type'),
            details=data.get('details'),
            # BUDA autonomo conserva su comportamiento historico. Esta ruta no
            # esta registrada cuando BUDA corre dentro de APATE (mount_buda()
            # no registra ai_bp desde M14e), asi que este load_context() no
            # alcanza a ninguna instalacion de APATE.
            context=load_context(),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except LookupError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"message": result}), 200


def generate_ai_commands(narrative_id):
    """Generates PowerShell commands dynamically using AI based on a narrative.

    Refactored during APATE roadmap milestone M14e: already took
    narrative_id as a plain argument (never read request.json), but
    used to return a Flask Response (jsonify(...)) directly, which only
    makes sense for an HTTP caller. Now returns a plain dict --
    {"commands": [...]} on success, {"error": "..."} on failure --
    invocable directly from Python with just an app context (for the
    Narrative query), same criterion as BudaPlugin.deploy()/retire().
    Used directly by utils/behavior_engine.py::generate_commands()
    since M14e -- that used to make an HTTP self-call to this exact
    route (fixed to include the missing '/buda' prefix in the M14c
    follow-up, see git log), which stopped being viable once ai_bp is
    no longer registered as a blueprint when BUDA runs inside APATE
    (M14e retires mount_buda()'s blueprint registration entirely)."""

    narrative = db.session.get(Narrative, narrative_id)
    if not narrative:
        return {"error": "Narrative not found"}

    # Organize User Profiles and Activity Types
    user_profiles_data = {}
    for profile in narrative.user_profiles:
        activity_types = [activity.activity_type for activity in profile.activities]
        user_profiles_data[profile.name] = activity_types

    percentage_of_similarity = narrative.percentage_of_similarity

    # Construct AI Prompt
    commands_prompt = f"""
        You are a cybersecurity expert generating PowerShell commands for a simulated cyber attack scenario.
        Based on the following details, suggest 3 relevant PowerShell commands for each user profile.

        - **Narrative Title:** {narrative.title}
        - **Objective:** {narrative.objective}
        - **Attacker Profile:** {narrative.attacker_profile}
        - **Percentage of Similarity:** {narrative.percentage_of_similarity}%

        The **percentage of similarity** defines how closely the commands should match the context:
        - **100% similarity** means commands must be highly aligned to the scenario, matching the exact attack techniques described.
        - **1% similarity** means commands should be loosely related, potentially exploratory or unexpected in this context.

        Provide structured output in the format:
        ```
        {{ "commands": [ {{ "user_profile": "User1", "activity_type": "Recon", "commands": ["cmd1", "cmd2", "cmd3"] }}, ... ] }}
        ```
    """

    # Add detailed breakdown per user profile
    for user, activities in user_profiles_data.items():
        commands_prompt += f"\n- **User Profile:** {user} \n  - Activity Types: {', '.join(activities)}\n"

    messages = [
        {"role": "system", "content": "You are a cybersecurity professional that generates structured JSON data."},
        {"role": "user", "content": f"{commands_prompt}\n"}
    ]

    result = get_llm_response(messages)

    # Extract and return structured JSON response
    try:
        return json.loads(result)
    except (json.JSONDecodeError, KeyError):
        return {"error": "AI Response Failed or returned unstructured data"}


@ai_bp.route('/generate_commands/<int:narrative_id>', methods=['POST'])
def generate_ai_commands_view(narrative_id):
    """Thin HTTP wrapper over generate_ai_commands() -- same rationale
    as generate_activity_view() above."""

    result = generate_ai_commands(narrative_id)
    if result.get("error") == "Narrative not found":
        return jsonify(result), 404
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result), 200

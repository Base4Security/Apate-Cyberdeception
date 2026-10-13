import winrm
from datetime import datetime
from ..utils.logger import log_command
from ..utils.events import record_event
from ..utils.crypto_utils import is_unrecoverable_credential

# MITRE ATT&CK T1021.006 (Remote Services: Windows Remote Management) is a
# structural fact about *how* this function reaches the target host, not an
# inference from command content -- every command executed through this
# function is, by definition, an instance of that technique, so it's safe
# to use as a fixed default instead of trying to infer a TTP from
# arbitrary PowerShell text (which we don't attempt -- see events.py).
_WINRM_TTP_ID = "T1021.006"


def execute_command(narrative, user_name, command):
    """
    Executes a PowerShell command remotely via WinRM.

    WinRM credentials/target (winrm_server/winrm_username/winrm_password)
    live on UserProfile, not on Narrative (see models/narrative.py vs.
    models/user.py) -- `narrative` only tells us *which* user profiles are
    valid for this narrative, via the existing many-to-many
    Narrative.user_profiles relationship (models/narratives_user_profiles.py).
    `user_profile` is resolved by name *within that relationship*, not via
    a global UserProfile query: a name that exists somewhere in the table
    but isn't actually bound to this narrative must not resolve to a
    profile (and its credentials/target host) that has nothing to do with
    the narrative being run.

    Fixes a bug found during APATE roadmap milestone M8b (documented then,
    fixed now on M8b's follow-up): this function used to read
    narrative.winrm_server/winrm_username/winrm_password directly, which
    don't exist on Narrative and raised AttributeError before ever
    attempting a WinRM connection.
    """
    narrative_id = narrative.id

    user_profile = next((profile for profile in narrative.user_profiles if profile.name == user_name), None)
    if not user_profile:
        return f"User profile '{user_name}' not found in narrative '{narrative.title}'"

    winrm_server = user_profile.winrm_server
    winrm_username = user_profile.winrm_username
    winrm_password = user_profile.winrm_password

    if is_unrecoverable_credential(winrm_username) or is_unrecoverable_credential(winrm_password):
        error = "Las credenciales WinRM del perfil no se pueden descifrar; reemplazalas antes de conectar."
        print(f"{datetime.now().date()} - [Or]WinRM Error: {error}")
        log_command(narrative_id, user_profile, command, error)
        record_event(
            kind="winrm_command_executed",
            detail=f"WinRM bloqueado para '{user_profile.name}': credenciales no recuperables.",
            ttp_id=_WINRM_TTP_ID,
            narrative_id=narrative_id,
            winrm_server=winrm_server,
            user_profile=user_profile.name,
            command=command,
            status="error",
        )
        return f"WinRM Error: {error}"

    print(f"{datetime.now().date()} - [Or]User Profile: {user_profile.name}")

    try:
        print(f"{datetime.now().date()} - [Or]Executing command: {command}")
        session = winrm.Session(winrm_server, auth=(winrm_username, winrm_password))
        response = session.run_ps(command)
        print(f"{datetime.now().date()} - [Or]Response: {response.status_code}")
        log_command(narrative_id, user_profile, command, response.status_code)
        if response.status_code == 0:
            print(response.std_out.decode('utf-8').strip())
            record_event(
                kind="winrm_command_executed",
                detail=f"Command executed successfully on '{winrm_server}' for user profile '{user_profile.name}'",
                ttp_id=_WINRM_TTP_ID,
                narrative_id=narrative_id,
                winrm_server=winrm_server,
                user_profile=user_profile.name,
                command=command,
                status="success",
            )
            return response.std_out.decode('utf-8').strip()
        else:
            print(f"{datetime.now().date()} - [Or]Response error: {response.status_code}")
            record_event(
                kind="winrm_command_executed",
                detail=(
                    f"Command failed on '{winrm_server}' for user profile '{user_profile.name}' "
                    f"(exit code {response.status_code})"
                ),
                ttp_id=_WINRM_TTP_ID,
                narrative_id=narrative_id,
                winrm_server=winrm_server,
                user_profile=user_profile.name,
                command=command,
                status="error",
            )
            return f"Error: {response.std_err.decode('utf-8').strip()}"
    except Exception as e:
        print(f"{datetime.now().date()} - [Or]WinRM Error: {str(e)}")
        log_command(narrative_id, user_profile, command, str(e))
        record_event(
            kind="winrm_command_executed",
            detail=f"WinRM error on '{winrm_server}' for user profile '{user_profile.name}': {str(e)}",
            ttp_id=_WINRM_TTP_ID,
            narrative_id=narrative_id,
            winrm_server=winrm_server,
            user_profile=user_profile.name,
            command=command,
            status="error",
        )
        return f"WinRM Error: {str(e)}"

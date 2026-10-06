from ..app import db
from ..utils.crypto_utils import EncryptedString, is_unrecoverable_credential
from .narratives_user_profiles import narratives_user_profiles
from .user_profiles_activity_types import user_profiles_activity_types

class UserProfile(db.Model):
    __tablename__ = 'user_profiles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    behavior_pattern = db.Column(db.Text, nullable=False)
    winrm_server = db.Column(db.String(100), nullable=False)
    # Encrypted at rest (APATE roadmap M8b) -- see utils/crypto_utils.py.
    # Existing plaintext data in a pre-M8b database needs
    # scripts/migrate_encrypt_credentials.py run once before this column
    # type change is deployed; see that script's docstring.
    winrm_username = db.Column(EncryptedString, nullable=False)
    winrm_password = db.Column(EncryptedString, nullable=False)

    narrative = db.relationship('Narrative', secondary=narratives_user_profiles, back_populates='user_profiles')
    activities = db.relationship('Activity', secondary=user_profiles_activity_types, back_populates='user_profiles')

    @property
    def credentials_recoverable(self):
        """Si las credenciales siguen siendo aptas para una conexión WinRM."""

        return not (
            is_unrecoverable_credential(self.winrm_username)
            or is_unrecoverable_credential(self.winrm_password)
        )

    def to_dict(self):
        # Fixes a bug found during APATE roadmap milestone M14c: 'username'
        # and 'password' used to be included here in plain text -- as
        # documented in utils/crypto_utils.py::EncryptedString, reading
        # winrm_username/winrm_password as Python attributes transparently
        # decrypts them, so this JSON shape leaked real WinRM credentials
        # through every consumer of to_dict() (GET /user_profiles/list,
        # and indirectly Activity.to_dict()/Narrative.to_dict(), which
        # both nest a UserProfile.to_dict() per profile). 'server' alone
        # is not sensitive (just a hostname/IP, not encrypted at rest
        # either) and stays, matching what APATE's own native panel
        # already shows (never username/password together, see
        # docs/roadmap.md M9/M11 in the APATE repo). The real credential
        # values are still readable via the model attributes directly
        # (utils/orchestrator.py's WinRM session reads those, not
        # to_dict()) -- only this serialized-for-API/UI shape changes.
        return {
            'id': self.id,
            'name': self.name,
            'role': self.role,
            'behavior_pattern': self.behavior_pattern,
            'narrative': [narrative.to_dict() for narrative in self.narrative],
            'activities': [activity.to_dict() for activity in self.activities],
            'winrm': {
                'server': self.winrm_server,
            }
        }

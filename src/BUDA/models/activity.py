import json

from ..app import db
from .user_profiles_activity_types import user_profiles_activity_types

class Activity(db.Model):
    __tablename__ = 'activities'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    activity_type = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text, nullable=True)

    # Repertorio de comandos aprobado por el operador, como lista JSON.
    #
    # **Es lo unico que el worker de narrativas ejecuta.** Antes el worker le
    # pedia comandos nuevos a un LLM en cada paso (cada 30-600 segundos) y los
    # ejecutaba por WinRM sobre servidores reales sin que nadie los mirara, lo
    # que contradecia el principio que la propia interfaz declara ("Generacion,
    # no decision -- ninguna sugerencia se aplica sola"). Ahora el modelo puede
    # proponer un borrador, pero lo que corre en la red del cliente es lo que
    # un operador leyo y guardo aca.
    #
    # Nullable a proposito: una actividad creada antes de esta columna no tiene
    # repertorio, y la narrativa se niega a arrancar diciendo cual falta -- en
    # vez de arrancar y quedarse muda.
    commands = db.Column(db.Text, nullable=True)

    # Relation with UserProfile
    user_profiles = db.relationship('UserProfile', secondary=user_profiles_activity_types, back_populates='activities')

    def approved_commands(self):
        """La lista de comandos aprobados, o `[]` si no hay ninguno.

        Tolera el campo vacio y el JSON invalido devolviendo la lista vacia:
        quien decide que hacer sin repertorio es el arranque de la narrativa,
        que se niega y lo dice, no este getter.
        """

        if not self.commands:
            return []
        try:
            cargado = json.loads(self.commands)
        except (TypeError, ValueError):
            return []
        if not isinstance(cargado, list):
            return []
        return [str(item).strip() for item in cargado if str(item).strip()]

    def set_approved_commands(self, commands):
        """Guarda el repertorio, descartando vacios y normalizando a texto."""

        limpios = [str(item).strip() for item in (commands or []) if str(item).strip()]
        self.commands = json.dumps(limpios, ensure_ascii=False) if limpios else None

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'activity_type': self.activity_type,
            'details': self.details,
            'commands': self.approved_commands(),
            'user_profiles': [profile.to_dict() for profile in self.user_profiles],
        }

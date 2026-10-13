"""Modelo mínimo de un activo inventariado."""

from __future__ import annotations

from dataclasses import dataclass

from apate.i18n import gettext
from apate.i18n import lazy_gettext as _


class AssetValidationError(ValueError):
    """Un activo no tiene los datos mínimos para poder inventariarse."""


_CRITICALITIES = {"low", "medium", "high", "critical"}

# El valor persistido es el de arriba, en ingles, y no cambia: es contrato.
# Pero la interfaz muestra "Baja/Media/Alta/Critica", asi que quien arma un CSV
# escribe lo que ve en pantalla -- y le rechazaba el archivo entero. Encontrado
# importando un CSV con las criticidades tal como aparecen en la UI: 10 filas
# de 10 rechazadas. Mismo problema que ya se corrigio dos veces mostrando
# valores crudos (enums en _enum_labels.py, tacticas de ATT&CK), acá del lado
# de la entrada en vez del de la salida.
#
# Vive en el modelo y no en la capa web a proposito: es parte del contrato de
# importacion, no de presentacion -- `apate.assets` no depende de `apate.web`.
_CRITICALITY_ALIASES = {
    "baja": "low",
    "media": "medium",
    "alta": "high",
    "critica": "critical",
    "crítica": "critical",
}

CRITICALITY_LABELS = {
    "low": _("Baja"),
    "medium": _("Media"),
    "high": _("Alta"),
    "critical": _("Crítica"),
}


def normalize_criticality(value: str) -> str:
    """Lleva una criticidad escrita por una persona al valor interno.

    Acepta tanto el valor persistido (`high`) como la etiqueta que la interfaz
    muestra (`Alta`), con o sin acento. Devuelve el texto original si no lo
    reconoce, para que la validacion informe el error en vez de tragarselo.
    """

    limpio = value.strip().lower()
    return _CRITICALITY_ALIASES.get(limpio, limpio)


@dataclass
class Asset:
    """Activo global reutilizable por cualquier operación.

    ``identifier`` es el identificador estable que se guarda en
    ``AdversaryProfile.target_assets``. ``technical_identifier`` es opcional
    y puede contener un host, IP, dominio u otro dato técnico.
    """

    identifier: str
    name: str
    asset_type: str
    criticality: str
    technical_identifier: str = ""

    def __post_init__(self) -> None:
        self.identifier = self.identifier.strip()
        self.name = self.name.strip()
        self.asset_type = self.asset_type.strip()
        self.criticality = normalize_criticality(self.criticality)
        self.technical_identifier = self.technical_identifier.strip()
        if not self.identifier:
            raise AssetValidationError(gettext("El identificador del activo es obligatorio."))
        if not self.name:
            raise AssetValidationError(gettext("El nombre del activo es obligatorio."))
        if not self.asset_type:
            raise AssetValidationError(gettext("El tipo del activo es obligatorio."))
        if self.criticality not in _CRITICALITIES:
            # El mensaje lista lo que la persona ve en la interfaz, con el valor
            # interno al lado: decir solo "low, medium, high, critical" obliga a
            # adivinar la relacion con las etiquetas de la pantalla.
            opciones = ", ".join(
                f"{etiqueta} ({interno})"
                for interno, etiqueta in CRITICALITY_LABELS.items()
            )
            raise AssetValidationError(
                gettext("La criticidad debe ser una de: %(opciones)s.", opciones=opciones)
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "identifier": self.identifier,
            "name": self.name,
            "asset_type": self.asset_type,
            "criticality": self.criticality,
            "technical_identifier": self.technical_identifier,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "Asset":
        return cls(
            identifier=str(data.get("identifier", "")),
            name=str(data.get("name", "")),
            asset_type=str(data.get("asset_type", "")),
            criticality=str(data.get("criticality", "")),
            technical_identifier=str(data.get("technical_identifier", "")),
        )

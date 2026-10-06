"""Extensiones instaladas y seleccionadas explícitamente por el administrador.

No carga rutas arbitrarias ni activa capacidades porque estén instaladas.
"""
from importlib.metadata import entry_points


def configure_extensions(app):
    selected = app.config.get("APATE_EXTENSIONS", ())
    if isinstance(selected, str):
        selected = [name.strip() for name in selected.split(",") if name.strip()]
    if len(set(selected)) != len(selected):
        raise ValueError("duplicate_extension_selection")
    available = list(entry_points(group="apate.extensions"))
    instances = []
    for name in selected:
        matches = [point for point in available if point.name == name]
        if len(matches) != 1:
            raise ValueError("extension_missing_or_ambiguous:" + name)
        extension = matches[0].load()()
        if getattr(extension, "contract_version", None) != 1:
            raise ValueError("extension_contract_mismatch:" + name)
        extension.configure_app(app)
        instances.append(extension)
    app.extensions["apate.extensions"] = instances


def initialize_extensions(app):
    for extension in app.extensions.get("apate.extensions", ()):
        extension.init_app(app)


def check_ledger_policy(ledger, stage, **context):
    """El mismo control llega a todas las fachadas que comparten el registro."""
    policy = getattr(ledger, "authorization_policy", None)
    if policy is not None:
        return policy.check(stage, **context)

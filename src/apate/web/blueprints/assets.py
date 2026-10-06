"""Inventario global de activos, base del paso 1 de la metodología.

No se aplica aislamiento por equipo: un activo representa infraestructura
compartida y duplicarlo por operación o por equipo degradaría el inventario.
Las operaciones referencian su identificador sin tomar propiedad del activo.
"""

from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from ...assets import (
    Asset,
    AssetImportError,
    AssetNotFoundError,
    CSVAssetImporter,
    CRITICALITY_LABELS,
    list_suggestible_asset_types,
)
from ...i18n import gettext as _


assets_bp = Blueprint("assets", __name__, url_prefix="/assets")

# Fuente unica: las mismas etiquetas que acepta el importador de CSV. Tenerlas
# duplicadas aca fue lo que dejo que la interfaz y la importacion hablaran
# vocabularios distintos.
_CRITICALITY_LABELS = CRITICALITY_LABELS


def _repository():
    return current_app.config["ASSET_REPOSITORY"]


@assets_bp.route("/")
def index():
    assets = sorted(_repository().list(), key=lambda asset: (asset.name.lower(), asset.identifier.lower()))
    return render_template(
        "assets/index.html",
        assets=assets,
        criticality_labels=_CRITICALITY_LABELS,
        suggestible_asset_types=list_suggestible_asset_types(),
    )


@assets_bp.route("/", methods=["POST"])
def create():
    try:
        asset = Asset(
            identifier=request.form.get("identifier", ""),
            name=request.form.get("name", ""),
            asset_type=request.form.get("asset_type", ""),
            criticality=request.form.get("criticality", ""),
            technical_identifier=request.form.get("technical_identifier", ""),
        )
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        _repository().save(asset)
        flash(_("Activo '%(name)s' guardado en el inventario global.", name=asset.name), "success")
    return redirect(url_for("assets.index"))


@assets_bp.route("/<identifier>/edit", methods=["GET", "POST"])
def edit(identifier: str):
    try:
        asset = _repository().get(identifier)
    except AssetNotFoundError:
        abort(404)
    if request.method == "POST":
        try:
            updated = Asset(
                identifier=asset.identifier,
                name=request.form.get("name", ""),
                asset_type=request.form.get("asset_type", ""),
                criticality=request.form.get("criticality", ""),
                technical_identifier=request.form.get("technical_identifier", ""),
            )
        except ValueError as exc:
            flash(str(exc), "error")
        else:
            _repository().save(updated)
            flash(_("Activo '%(name)s' actualizado.", name=updated.name), "success")
            return redirect(url_for("assets.index"))
    return render_template(
        "assets/edit.html",
        asset=asset,
        criticality_labels=_CRITICALITY_LABELS,
        suggestible_asset_types=list_suggestible_asset_types(),
    )


@assets_bp.route("/<identifier>/delete", methods=["POST"])
def delete(identifier: str):
    try:
        _repository().delete(identifier)
    except AssetNotFoundError:
        abort(404)
    flash(_("Activo eliminado del inventario. Las operaciones históricas conservan su texto de referencia."), "success")
    return redirect(url_for("assets.index"))


@assets_bp.route("/import/preview", methods=["POST"])
def preview_csv():
    uploaded = request.files.get("inventory_csv")
    if uploaded is None or not uploaded.filename:
        flash(_("Seleccioná un archivo CSV para previsualizar."), "error")
        return redirect(url_for("assets.index"))
    try:
        preview = CSVAssetImporter().preview(secure_filename(uploaded.filename), uploaded.read())
    except AssetImportError as exc:
        flash(str(exc), "error")
        return redirect(url_for("assets.index"))
    current_app.config["ASSET_IMPORT_PREVIEW_REPOSITORY"].save(preview)
    return render_template("assets/import_preview.html", preview=preview, criticality_labels=_CRITICALITY_LABELS)


@assets_bp.route("/import/<token>/confirm", methods=["POST"])
def confirm_csv(token: str):
    previews = current_app.config["ASSET_IMPORT_PREVIEW_REPOSITORY"]
    try:
        preview = previews.get(token)
    except AssetNotFoundError:
        abort(404)
    for asset in preview.assets:
        _repository().save(asset)
    previews.delete(token)
    flash(
        _(
            "Importación confirmada: %(assets)s activo(s) guardado(s); %(rows)s fila(s) omitida(s).",
            assets=len(preview.assets),
            rows=len(preview.issues),
        ),
        "success",
    )
    return redirect(url_for("assets.index"))

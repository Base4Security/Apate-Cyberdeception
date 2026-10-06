"""Tests de la infraestructura de traduccion (tanda 1 de i18n).

Dos niveles, con proposito distinto:

* **Comportamiento** -- `apate.i18n` degrada al `msgid` fuera de Flask, la
  cascada de `_select_locale()` respeta su orden, y la preferencia por
  usuario se persiste sin invalidar la sesion abierta.

* **Sincronizacion** -- son los tests que hacen que la version inglesa no
  pueda quedarse atras. gettext por si solo no lo garantiza: si alguien
  agrega texto nuevo y no actualiza el catalogo, la aplicacion sigue
  funcionando y le muestra espanol a quien pidio ingles, en silencio.
  Estos fallan en su lugar.
"""

from __future__ import annotations

import re
from pathlib import Path

from babel.messages.extract import DEFAULT_KEYWORDS, extract_from_dir
from babel.messages.frontend import parse_mapping_cfg
from babel.messages.mofile import read_mo
from babel.messages.pofile import read_po
from flask import session

from apate.i18n import (
    DEFAULT_LOCALE,
    EXTRACTION_KEYWORDS,
    SUPPORTED_LOCALES,
    LazyString,
    gettext,
    gettext_noop,
    lazy_gettext,
)
from apate.identity import LocalIdentityProvider
from apate.web._enum_labels import operation_status_label

REPO_ROOT = Path(__file__).resolve().parents[1]
TRANSLATIONS_DIR = REPO_ROOT / "src" / "apate" / "web" / "translations"

# Un producto, estándar o sigla técnica puede ser igual en español e inglés.
# La allowlist deja explícita esa decisión y evita que un término invariante
# futuro se confunda con una traducción olvidada.
MSGIDS_INGLES_INTENCIONALMENTE_IGUALES = frozenset(
    {
        "Docker",
        "YAML",
        "STIX 2.1",
        "TLP",
        "MITRE ATT&CK",
        "MITRE Engage",
        "Playground",
        "WinRM",
        "OIDC",
    }
)
MARCAS_DEL_CASTELLANO = re.compile(
    r"[áéíóúüñ]|&(?:aacute|eacute|iacute|oacute|uacute|ntilde|uuml);",
    re.IGNORECASE,
)
# Las marcas de arriba son tildes y entidades HTML, y por eso dejaron pasar
# "Miga Canarytoken · %(token_type)s": una copia del msgid sin una sola letra
# acentuada. Estas palabras son inequívocamente españolas y no aparecen en una
# traducción inglesa real, así que una entrada idéntica al original que las
# contenga es una traducción olvidada, no un término invariante.
PALABRAS_DEL_CASTELLANO_SIN_ACENTO = re.compile(
    r"\b(?:miga|migas|escenario|escenarios|regla|reglas|adversario|senuelo|senuelos|"
    r"usuario|usuarios|equipo|equipos|pendiente|pendientes|ninguna|ninguno)\b",
    re.IGNORECASE,
)

MIGRATED_TEMPLATE_MSGIDS = {
    "src/apate/web/templates/login.html": {
        "Iniciar sesión - Apate",
        "Iniciar sesión",
        "Esta instancia tiene usuarios configurados. Iniciá sesión para continuar.",
        "Iniciar con el proveedor corporativo",
        "Acceso de emergencia local:",
        "Nombre de usuario",
        "Contraseña",
    },
    "src/apate/web/templates/base.html": {
        "Saltar al contenido",
        "Men&uacute;",
        "Sesi&oacute;n autenticada",
        "Cerrar sesi&oacute;n",
        "La instancia est&aacute; abierta hasta crear el primer usuario. Para protegerla, ejecut&aacute; flask --app \"apate.web:create_app\" create-user &lt;nombre&gt;.",
        "Operador para auditor&iacute;a",
        "Operaciones",
        "Portafolio",
        "Inventario de activos",
        "Reglas",
        "Telemetr&iacute;a",
        "Cat&aacute;logo de capacidades",
        "Salud y configuraci&oacute;n",
        "Playground",
        "Usuarios y acceso",
        "Vista y ayuda",
        "Ayuda y glosario",
        "Tema claro",
        "Vista compacta",
        "Cerrar mensaje",
        "Salir de presentaci&oacute;n",
        "Confirmar acci&oacute;n",
        "Escrib&iacute;",
        "para continuar",
        "Cancelar",
        "Confirmar",
        "Buscar secciones y operaciones",
        "Secci&oacute;n, capacidad u operaci&oacute;n&hellip;",
        "Operaci&oacute;n",
        "M&eacute;tricas operacionales",
        "Runtime de red y host",
        "Generaci&oacute;n de contenido",
        "Administraci&oacute;n de usuarios",
        "Inteligencia de amenazas",
        "SIEM/SOAR",
        "Tipos de actividad",
        "Perfiles de identidad",
        "Contexto de comportamiento",
        "RoE",
        "TTP",
        "MITRE Engage",
        "Capacidad",
        "Despliegue",
        "Efecto medido",
    },
    "src/apate/web/templates/landing.html": {
        "Herramienta para dise&ntilde;ar, desplegar y medir operaciones de enga&ntilde;o.",
        "Decoys de red, identidades simuladas y honeytokens, coordinados por reglas.",
        "Retomar",
        "Todas las operaciones",
        "Crear la primera operaci&oacute;n",
        "Vista de impacto",
        "Funciones disponibles",
        "Operaciones activas",
        "Comprometidas",
        "Cobertura de TTPs",
        "Una operaci&oacute;n re&uacute;ne el perfil de adversario, las reglas de interacci&oacute;n, los escenarios, las capacidades y la narrativa de un mismo enga&ntilde;o. Desde ah&iacute; pod&eacute;s observar lo que ocurre, decidir, desplegar y reajustar el dise&ntilde;o.",
        "Dise&ntilde;ar y operar",
        "Cat&aacute;logo de capacidades",
        "Reglas",
        "Telemetr&iacute;a",
        "Portafolio",
        "Medir y reportar",
        "Entorno y estado",
        "Playground",
        "Corr&eacute; un ataque real contra el stack completo y mir&aacute; c&oacute;mo responde tu operaci&oacute;n.",
        "Salud y configuraci&oacute;n",
    },
    "src/apate/web/templates/_locale_selector.html": {
        "Idioma",
        "Cambiar",
    },
    "src/apate/web/templates/plugins/_nav.html": {
        "Resumen",
        "Perfiles de identidad",
        "Tipos de actividad",
        "Contexto de comportamiento",
    },
    "src/apate/web/templates/plugins/_use_form.html": {
        "Operación",
        "Elegir operación",
        "Usar en una operación",
        "Creá una operación para usarla.",
    },
    "src/apate/web/templates/plugins/catalog.html": {
        "Cat&aacute;logo de capacidades - Apate",
        "Ruta",
        "Inicio",
        "Cat&aacute;logo de capacidades",
        "Motores y recursos reutilizables, organizados por funci&oacute;n y superficie.",
        "resultado(s)",
        "Filtros del cat&aacute;logo",
        "Tipo",
        "Superficie",
        "Proveedor",
        "Disponibilidad",
        "Todos",
        "Motor",
        "Perfil",
        "Actividad",
        "Contexto",
        "Filtrar",
        "Limpiar",
        "Capacidad",
        "Estado",
        "Acciones",
        "No hay capacidades que coincidan con los filtros.",
        "Los recursos externos aparecen como no disponibles hasta preparar sus integraciones en Salud y configuraci&oacute;n.",
    },
    "src/apate/web/templates/operations/compare.html": {
        "Comparar operaciones - Apate",
        "Comparar operaciones",
        "Contraste descriptivo de datos reales. Apate no punt&uacute;a, recomienda ganadores ni decide cu&aacute;l operaci&oacute;n fue “mejor”.",
        "Primera operaci&oacute;n",
        "Segunda operaci&oacute;n",
        "Eleg&iacute; dos operaciones distintas y existentes.",
        "Estado",
        "Esperadas no observadas",
        "Observadas no esperadas",
    },
    "src/apate/web/templates/operations/templates.html": {
        "Plantillas de operaci&oacute;n - Apate",
        "Plantillas de operaci&oacute;n",
        "Empezar en blanco",
        "Una plantilla precarga el perfil, las TTPs esperadas, las reglas de interacci&oacute;n y la narrativa; los escenarios y las capacidades los agreg&aacute;s despu&eacute;s.",
        "Adversario",
        "Entorno sugerido",
        "Usar esta plantilla",
        "No hay plantillas cargadas.",
    },
}


MIGRATED_TEMPLATE_MSGIDS.update(
    {
        "src/apate/web/templates/operations/form.html": {
            "Nueva operaci&oacute;n", "Buscar t&eacute;cnica", "Siguiente", "Crear operaci&oacute;n", "Cancelar",
        },
        "src/apate/web/templates/operations/list.html": {
            "Operaciones", "Comparar operaciones", "Buscar", "Estado", "Limpiar filtros", "Sin coincidencias",
        },
        "src/apate/web/templates/operations/portfolio.html": {
            "Portafolio", "Alcance y forma de c&aacute;lculo", "Abrir todo", "Cerrar todo",
        },
        "src/apate/web/templates/operations/_operation_detail_map_tab.html": {
            "Mapa de la operaci&oacute;n", "Lentes del mapa de la operaci&oacute;n", "Cobertura declarada de activos", "Actividad de la operaci&oacute;n",
        },
        "src/apate/web/templates/operations/_operation_detail_results_tab.html": {
            "Resultados", "Recursos y salida", "Descargar Markdown", "Coincidente",
        },
        "src/apate/web/templates/operations/_operation_detail_design_tab.html": {
            "Perfil de adversario", "Reglas de interacción",
        },
        "src/apate/web/templates/operations/_operation_detail_mechanics_tab.html": {
            "Despliegue contextual",
        },
        "src/apate/web/templates/operations/_operation_detail_review_tab.html": {
            "Preparaci&oacute;n",
        },
        "src/apate/web/templates/telemetry/index.html": {
            "Telemetr&iacute;a", "Buscar operaci&oacute;n", "Sin coincidencias", "Crear operaci&oacute;n",
        },
        "src/apate/web/templates/telemetry/detail.html": {
            "Telemetr&iacute;a de la operaci&oacute;n", "Filtros de an&aacute;lisis", "Guardar filtros actuales", "Agrupar en incidente",
        },
        "src/apate/web/templates/rules/index.html": {
            "Reglas del motor de decisi&oacute;n", "Constructor visual", "Guardar y recargar", "Confirmar y guardar",
        },
        "src/apate/web/templates/playground/index.html": {
            "Playground", "Ruta", "Inicio", "Entorno de simulación", "Nivel de engaño", "Atacante", "Defensor",
        },
        "src/apate/web/templates/playground/attacker.html": {
            "Vista atacante", "Perspectiva de Playground", "Lanzar atacante", "Acciones del atacante", "Fecha y hora",
        },
        "src/apate/web/templates/playground/defender.html": {
            "Vista defensor", "Resumen de observaci&oacute;n", "Notificaciones en vivo", "Esperado vs. observado", "Carga útil",
        },
        "src/apate/web/templates/rules/_rejected_actions.html": {
            "Acciones rechazadas", "Capacidad objetivo", "Evento disparador", "Protección", "Motivo", "Reglas de interacción",
        },
        "src/apate/web/templates/health/index.html": {
            "Salud y configuración", "Disponibilidad local y configuración necesaria antes de operar.", "Resumen de salud", "Siguiente paso",
        },
        "src/apate/web/templates/health/users.html": {
            "Administración de usuarios", "Usuarios locales", "Cambiar contraseña", "Contraseña inicial", "Crear usuario",
        },
        "src/apate/web/templates/health/unavailable.html": {
            "Integración deshabilitada", "Configuración no disponible", "La integración externa está deshabilitada",
        },
        "src/apate/web/templates/plugins/profiles.html": {
            "Perfiles de identidad", "Credenciales", "Crear perfil",
        },
        "src/apate/web/templates/plugins/profile_edit.html": {
            "Editar perfil de identidad", "Reemplazar credenciales (opcional)", "Nueva contraseña",
        },
        "src/apate/web/templates/plugins/activities.html": {
            "Tipos de actividad", "Crear tipo de actividad", "Generar sugerencia con IA",
        },
        "src/apate/web/templates/plugins/activity_edit.html": {
            "Editar actividad", "Editar tipo de actividad", "Perfiles asignados",
        },
        "src/apate/web/templates/plugins/behavior_context.html": {
            "Contexto de comportamiento", "Nueva fuente", "Extraer candidato",
        },
        "src/apate/web/templates/plugins/unavailable.html": {
            "Capacidad no disponible", "Integración no inicializada", "Revisar Salud y configuración",
        },
        "src/apate/web/templates/assets/index.html": {
            "Inventario de activos", "Agregar activo", "Importar CSV",
        },
        "src/apate/web/templates/assets/edit.html": {
            "Editar activo", "Identificador estable:", "Guardar cambios",
        },
        "src/apate/web/templates/assets/import_preview.html": {
            "Previsualizar importación", "Previsualización de importación CSV", "Confirmar importación",
        },
        "src/apate/web/templates/impact.html": {
            "Impacto de ciberengaño", "Cobertura táctica", "Estado de infraestructura",
        },
        "src/apate/web/templates/errors/404.html": {
            "Página no encontrada", "No encontramos esta página", "Volver al inicio",
        },
        "src/apate/web/templates/health/_configuration_nav.html": {
            "Salud y configuración", "Resumen", "Runtime de red / host", "Generación de contenido", "Inteligencia de amenazas",
        },
        "src/apate/web/templates/health/network_host_runtime.html": {
            "Runtime de red y host", "Diagnóstico del runtime", "Cliente Docker", "Validar y guardar cliente",
        },
        "src/apate/web/templates/health/content_generation.html": {
            "Generación de contenido", "Generación, no decisión", "Proveedor y modelo", "Guardar configuración",
        },
        "src/apate/web/templates/health/siem_soar.html": {
            "Envío explícito, nunca automático", "Webhook de salida", "Token bearer opcional", "Entrega del informe",
        },
        "src/apate/web/templates/health/threat_intelligence.html": {
            "Inteligencia de amenazas", "Consulta explícita, nunca automática", "Uso y cuota", "API key de VirusTotal",
        },
    }
)


def _esta_envuelta_como_msgid(texto: str, msgid: str) -> bool:
    escaped = re.escape(msgid)
    patron = r"\{\{\s*_\(\s*['\"]%s['\"]\s*\)\s*\}\}" % escaped
    return re.search(patron, texto) is not None


def test_tanda_2_plantillas_migradas_tienen_texto_envuelto():
    for relativa, msgids in MIGRATED_TEMPLATE_MSGIDS.items():
        path = REPO_ROOT / relativa
        contenido = path.read_text(encoding="utf-8")
        for msgid in msgids:
            assert msgid in contenido, (
                f"Mensaje faltante en la plantilla migrada {relativa}: {msgid}"
            )
            assert _esta_envuelta_como_msgid(contenido, msgid), (
                f"Texto visible no envuelto en {relativa}: {msgid}"
            )



# -- apate.i18n: degradado fuera de Flask ------------------------------


def test_gettext_devuelve_el_msgid_sin_contexto_de_aplicacion():
    # No es un modo de error: el msgid *es* la frase en espanol, asi que
    # `generate_report()` llamada desde seed_demo.py o desde un test sin
    # app sigue produciendo texto correcto.
    assert gettext("Detección temprana") == "Detección temprana"


def test_gettext_interpola_variables_sin_contexto():
    assert gettext("Operando como %(name)s.", name="fede") == "Operando como fede."


def test_gettext_noop_devuelve_el_mensaje_intacto():
    assert gettext_noop("Producción") == "Producción"


def test_lazy_string_se_comporta_como_texto():
    lazy = lazy_gettext("Producción")
    assert isinstance(lazy, LazyString)
    assert str(lazy) == "Producción"
    assert lazy == "Producción"
    assert len(lazy) == len("Producción")
    # __getattr__ delega en el texto ya resuelto: es lo que permite que
    # ocupe el lugar de un `str` en metadata sin que quien lo consume
    # note la diferencia.
    assert lazy.lower() == "producción"
    assert lazy + "!" == "Producción!"


def test_lazy_string_resuelve_recien_al_convertirse_a_texto(app):
    # El caso real es `DeceptionPlugin.plugin_description`, construido al
    # importar el modulo del plugin: traducirlo ahi lo congelaria en el
    # idioma del arranque.
    lazy = lazy_gettext("En preparación")
    with app.test_request_context("/", headers={"Accept-Language": "en"}):
        assert str(lazy) == "Planning"
    with app.test_request_context("/"):
        assert str(lazy) == "En preparación"


# -- Cascada de _select_locale() ---------------------------------------


def _status(current_app, **request_kwargs) -> str:
    with current_app.test_request_context("/", **request_kwargs):
        return operation_status_label("planning")


def test_locale_por_defecto_es_el_idioma_fuente(app):
    assert DEFAULT_LOCALE == "es"
    assert _status(app) == "En preparación"


def test_accept_language_decide_cuando_no_hay_nada_mas(app):
    assert _status(app, headers={"Accept-Language": "en-US,en;q=0.9"}) == "Planning"


def test_apate_locale_gana_sobre_accept_language(app):
    # Es la decision de la instalacion: un visitante con el navegador en
    # ingles no deberia cambiarle el idioma a una demo configurada en
    # espanol, ni al reves.
    app.config["APATE_LOCALE"] = "en"
    assert _status(app, headers={"Accept-Language": "es"}) == "Planning"


def test_la_sesion_gana_sobre_la_configuracion_de_la_instalacion(app):
    app.config["APATE_LOCALE"] = "en"
    with app.test_request_context("/"):
        session["locale"] = "es"
        assert operation_status_label("planning") == "En preparación"


def test_un_locale_desconocido_en_sesion_no_rompe_ni_se_usa(app):
    with app.test_request_context("/"):
        session["locale"] = "klingon"
        assert operation_status_label("planning") == "En preparación"


def test_html_lang_refleja_el_idioma_activo(client, app):
    assert 'lang="es"' in client.get("/operations/").get_data(as_text=True)
    app.config["APATE_LOCALE"] = "en"
    assert 'lang="en"' in client.get("/operations/").get_data(as_text=True)


# -- Preferencia por usuario -------------------------------------------


def test_identity_locale_es_opcional_y_compatible_hacia_atras(tmp_path):
    store = tmp_path / "identities.json"
    # Formato previo a este campo, escrito a mano.
    store.write_text(
        '{"identities": [{"id": "abc", "display_name": "vieja", "active": true,'
        ' "role": "administration", "team_id": null, "password_hash": "x"}]}\n',
        encoding="utf-8",
    )
    identity = LocalIdentityProvider(store).get("abc")
    assert identity is not None
    assert identity.locale is None


def test_set_locale_persiste_y_se_puede_limpiar(tmp_path):
    provider = LocalIdentityProvider(tmp_path / "identities.json")
    created = provider.create("admin", "secreta")
    assert created.locale is None

    assert provider.set_locale(created.id, "en").locale == "en"
    assert provider.get(created.id).locale == "en"
    assert provider.set_locale(created.id, None).locale is None


def test_set_locale_no_invalida_la_sesion_abierta(tmp_path):
    # Cambiar de idioma no es un evento de seguridad: si tocara
    # credential_version expulsaria a la persona de su propia sesion.
    provider = LocalIdentityProvider(tmp_path / "identities.json")
    created = provider.create("admin", "secreta")
    updated = provider.set_locale(created.id, "en")
    assert updated.credential_version == created.credential_version


def test_ruta_locale_cambia_el_idioma_de_la_sesion(client):
    response = client.post("/locale", data={"locale": "en", "next": "/operations/"})
    assert response.status_code == 302
    assert 'lang="en"' in client.get("/operations/").get_data(as_text=True)


def test_ruta_locale_rechaza_un_idioma_no_soportado(client):
    response = client.post("/locale", data={"locale": "klingon"}, follow_redirects=True)
    body = response.get_data(as_text=True)
    assert "Idioma no disponible." in body
    assert 'lang="es"' in body


def test_ruta_locale_solo_redirige_a_rutas_locales(client):
    response = client.post("/locale", data={"locale": "en", "next": "//evil.example"})
    assert "evil.example" not in response.headers["Location"]


# -- Sincronizacion del catalogo ---------------------------------------


def _msgids_en_el_codigo() -> set[str]:
    """Extrae los mensajes marcados en el codigo, con la config de pybabel."""

    # Modo texto, no binario: `parse_mapping_cfg` se lo pasa a configparser,
    # que en Python 3.14 ya no acepta bytes.
    with (REPO_ROOT / "babel.cfg").open("r", encoding="utf-8") as handle:
        method_map, options_map = parse_mapping_cfg(handle)

    keywords = dict(DEFAULT_KEYWORDS)
    for keyword in EXTRACTION_KEYWORDS:
        keywords[keyword] = None

    return {
        message
        for _filename, _lineno, message, _comments, _context in extract_from_dir(
            REPO_ROOT, method_map=method_map, options_map=options_map, keywords=keywords
        )
        if isinstance(message, str) and message
    }


def _catalogo(locale: str):
    path = TRANSLATIONS_DIR / locale / "LC_MESSAGES" / "messages.po"
    with path.open("rb") as handle:
        return read_po(handle, locale=locale)


def test_el_catalogo_ingles_cubre_todo_el_texto_marcado_en_el_codigo():
    """Este es el test que impide que la version inglesa quede atras.

    Si alguien agrega una frase nueva envuelta en `_()` y no corre
    `pybabel update`, esto falla nombrando exactamente lo que falta.
    """

    en_el_codigo = _msgids_en_el_codigo()
    en_el_catalogo = {message.id for message in _catalogo("en") if message.id}

    faltantes = en_el_codigo - en_el_catalogo
    assert not faltantes, (
        "Hay texto marcado como traducible que el catalogo ingles no cubre. "
        "Corre `pybabel extract` + `pybabel update` y traduci lo nuevo. "
        f"Faltan: {sorted(faltantes)}"
    )

    huerfanos = en_el_catalogo - en_el_codigo
    assert not huerfanos, (
        "El catalogo ingles traduce frases que ya no existen en el codigo. "
        f"Corre `pybabel update`. Sobran: {sorted(huerfanos)}"
    )


def test_el_catalogo_ingles_no_tiene_entradas_vacias_ni_dudosas():
    sin_traducir = []
    dudosas = []
    for message in _catalogo("en"):
        if not message.id:
            continue
        if not message.string:
            sin_traducir.append(message.id)
        elif "fuzzy" in message.flags:
            dudosas.append(message.id)

    assert not sin_traducir, f"Sin traducir al ingles: {sorted(sin_traducir)}"
    # `pybabel update` marca fuzzy toda traduccion cuyo original cambio:
    # es exactamente el caso "alguien reformulo la frase en espanol y el
    # ingles quedo diciendo otra cosa".
    assert not dudosas, f"Traducciones marcadas como dudosas (fuzzy): {sorted(dudosas)}"


def test_el_catalogo_ingles_no_copia_msgids_con_marcas_del_castellano():
    """Una copia del msgid no es una traducción, aunque no sea vacía ni fuzzy."""

    copias_en_castellano = [
        message.id
        for message in _catalogo("en")
        if message.id
        and message.id not in MSGIDS_INGLES_INTENCIONALMENTE_IGUALES
        and message.id == message.string
        and (
            MARCAS_DEL_CASTELLANO.search(message.id)
            or PALABRAS_DEL_CASTELLANO_SIN_ACENTO.search(message.id)
        )
    ]

    assert not copias_en_castellano, (
        "El catálogo inglés copia msgids con marcas del castellano. "
        f"Traducí estas entradas: {sorted(copias_en_castellano)}"
    )


def test_el_catalogo_compilado_esta_al_dia_con_el_fuente():
    """El `.mo` es lo que lee la aplicacion; el `.po` es lo que se edita.

    Sin esto, editar el `.po` y olvidar `pybabel compile` deja la
    aplicacion mostrando la traduccion anterior, sin ningun sintoma.
    """

    for locale in SUPPORTED_LOCALES:
        po_path = TRANSLATIONS_DIR / locale / "LC_MESSAGES" / "messages.po"
        if not po_path.exists():
            continue  # el idioma fuente no tiene catalogo propio

        mo_path = po_path.with_suffix(".mo")
        assert mo_path.exists(), (
            f"Falta el catalogo compilado de '{locale}'. Corre `pybabel compile`."
        )
        with mo_path.open("rb") as handle:
            compilado = {message.id: message.string for message in read_mo(handle) if message.id}
        fuente = {
            message.id: message.string
            for message in _catalogo(locale)
            if message.id and message.string
        }
        assert compilado == fuente, (
            f"El catalogo compilado de '{locale}' no coincide con su fuente. "
            "Corre `pybabel compile`."
        )


def test_el_espanol_no_tiene_catalogo_propio():
    """Decision de diseno, no un olvido.

    El espanol es el idioma fuente: sus `msgid` ya son el texto que se
    muestra. Un catalogo `es` seria una copia de si mismo, con la unica
    consecuencia posible de poder desincronizarse del original.
    """

    assert not (TRANSLATIONS_DIR / "es").exists()


def test_ningun_mensaje_traducible_lleva_un_porcentaje_suelto():
    """Un `%` sin duplicar rompe el render, no solo la traduccion.

    `gettext()` aplica formateo de porcentaje sobre el resultado para
    poder interpolar variables, asi que un `%` literal en el `msgid` se
    interpreta como especificador. La cadena "% de similitud" tumbo 271
    tests de una vez: `% d` es una conversion valida de printf, y
    `detail.html` la renderiza casi toda la suite. Si hace falta un
    porcentaje literal, va duplicado (`%%`) o fuera de la cadena
    traducible. Un marcador con nombre (`%(algo)s`) si es valido.
    """

    sueltos = []
    for locale in ("en",):
        for message in _catalogo(locale):
            for texto in (message.id, message.string):
                if not isinstance(texto, str):
                    continue
                if re.search(r"(?<!%)%(?![%(])", texto):
                    sueltos.append(texto)
    assert not sueltos, (
        "Estas cadenas traducibles llevan un '%' sin duplicar y van a fallar al "
        f"renderizarse: {sorted(set(sueltos))}"
    )

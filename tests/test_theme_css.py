"""Guarda de regresion para src/apate/web/static/theme.css -- hallazgo
real de la primera verificacion visual con navegador real (ver
docs/roadmap.md): un comentario que contenia, sin espacio de por
medio, un asterisco seguido de una barra (el cierre de comentario CSS)
en medio de texto explicativo cerraba ese bloque de comentario antes
de tiempo. El resto se parseaba como CSS invalido y el navegador
descartaba en silencio la regla real siguiente (`.engage-matrix
{ display: flex; ... }`) -- sin ningun error visible en ningun lado
(ni consola del navegador, ni test de Python, ni respuesta HTTP), la
matriz de Engage del formulario "Vincular plugin" simplemente se
renderizaba apilada en bloques de ancho completo en vez de columnas
con scroll horizontal.

Ningun test de Python anterior podia haber atrapado esto -- todos
verifican el HTML generado por Jinja, nunca el CSS servido como
archivo estatico. Este test no reemplaza una verificacion visual real
(no puede confirmar que el LAYOUT se vea bien, solo que el archivo
parsea), pero es barato y atrapa la clase exacta de error que ya
rompio algo una vez en silencio."""

from pathlib import Path

_THEME_CSS_PATH = Path(__file__).resolve().parent.parent / "src" / "apate" / "web" / "static" / "theme.css"


def _unmatched_comment_closes(css_text: str) -> list[int]:
    """Lineas (1-indexadas) donde aparece un cierre de comentario "*/"
    sin un "/*" abierto correspondiente antes -- señal de que un
    comentario se cerro antes de lo que su autor queria, dejando texto
    real interpretado como CSS invalido (o, si el desbalance es al
    reves, una porcion de CSS real interpretada como comentario)."""

    depth = 0
    unmatched = []
    i = 0
    n = len(css_text)
    while i < n:
        if css_text[i : i + 2] == "/*":
            depth += 1
            i += 2
            continue
        if css_text[i : i + 2] == "*/":
            if depth == 0:
                line = css_text[:i].count("\n") + 1
                unmatched.append(line)
            else:
                depth -= 1
            i += 2
            continue
        i += 1
    return unmatched


def test_theme_css_file_exists():
    assert _THEME_CSS_PATH.is_file()


def test_theme_css_has_no_unmatched_comment_closes():
    css_text = _THEME_CSS_PATH.read_text(encoding="utf-8")

    unmatched = _unmatched_comment_closes(css_text)

    assert unmatched == [], (
        f"theme.css tiene un cierre de comentario ('*/', con o sin espacio) sin apertura "
        f"correspondiente en la(s) linea(s) {unmatched} -- eso corta el bloque de comentario "
        f"antes de tiempo y el resto se interpreta como CSS invalido, que el navegador "
        f"descarta en silencio (sin ningun error visible). Revisar que ningun comentario "
        f"contenga la secuencia asterisco-barra sin espacio de por medio."
    )


def test_theme_css_all_comments_are_closed():
    # Complementario al anterior: un "/*" abierto que nunca cierra
    # comentaria el resto del archivo entero.
    css_text = _THEME_CSS_PATH.read_text(encoding="utf-8")

    depth = 0
    i = 0
    n = len(css_text)
    while i < n:
        if css_text[i : i + 2] == "/*":
            depth += 1
            i += 2
            continue
        if css_text[i : i + 2] == "*/":
            depth = max(0, depth - 1)
            i += 2
            continue
        i += 1

    assert depth == 0, "theme.css tiene un comentario sin cerrar (/* sin */ correspondiente)."


def test_engage_matrix_rule_is_present_and_not_swallowed_by_a_broken_comment():
    # Chequeo puntual sobre el bug real encontrado -- si algun dia se
    # rompe de nuevo (esta regla en particular, u otra justo despues de
    # un comentario largo), este test lo marca por nombre, no solo el
    # chequeo generico de balance de arriba.
    css_text = _THEME_CSS_PATH.read_text(encoding="utf-8")

    assert ".engage-matrix { display: flex" in css_text


def test_all_custom_properties_used_by_preparation_alert_are_defined():
    # La alerta usaba --warning sin declararlo: el navegador descartaba
    # borde y fondo en silencio aunque el HTML y la suite web estuvieran bien.
    css_text = _THEME_CSS_PATH.read_text(encoding="utf-8")

    assert "--warning:" in css_text
    assert "border: 1px solid var(--warning)" in css_text


def test_search_inputs_share_the_dark_theme_form_control_rule():
    # La verificacion visual encontro los buscadores con fondo blanco:
    # type=search no estaba incluido en la regla comun de formularios.
    css_text = _THEME_CSS_PATH.read_text(encoding="utf-8")

    assert 'input:not([type]), input[type="text"], input[type="search"]' in css_text


def test_table_scroll_contains_wide_content_without_disabling_its_scroll():
    css_text = _THEME_CSS_PATH.read_text(encoding="utf-8")
    rule = css_text.split("\n.table-scroll {", 1)[1].split("}", 1)[0]

    assert "contain: inline-size paint" in rule
    assert "overflow-x: auto" in rule


def test_telemetry_events_layout_collapses_without_inspector():
    css_text = _THEME_CSS_PATH.read_text(encoding="utf-8")
    base_rule = css_text.split("\n.telemetry-events-layout {", 1)[1].split("}", 1)[0]
    has_inspection_rule = (
        css_text.split("\n.telemetry-events-layout.has-inspection {", 1)[1].split("}", 1)[0]
    )
    # El media query de 760px tiene muchas reglas anidadas -- partir por el
    # primer "}" solo captura la primera regla del bloque, no todo el media
    # query (bug real encontrado al correr este test). Basta confirmar que
    # la regla mobile de .telemetry-events-layout sigue presente en algun
    # punto despues de que abre el media query de 760px.
    media_start = css_text.index("@media (max-width: 760px) {")

    assert "grid-template-columns: minmax(0, 1fr);" in base_rule
    assert "grid-template-columns: minmax(0, 1fr) minmax(220px, 360px);" in has_inspection_rule
    assert (
        ".telemetry-events-layout { grid-template-columns: minmax(0, 1fr); }"
        in css_text[media_start:]
    )


def test_every_wrapper_class_used_in_templates_exists_in_the_stylesheet():
    """Un contenedor con una clase que el CSS no define es markup muerto:
    la tabla queda con el `display: block` global, que es justo lo que
    rompe la agrupación fila/columna cuando una columna envuelve. Pasó con
    `.table-wrap` en el Portafolio — cuatro tablas nuevas envueltas en una
    clase inexistente mientras el resto de la app usa `.table-scroll`.
    """

    import pathlib
    import re

    raiz = pathlib.Path(__file__).resolve().parent.parent / "src" / "apate" / "web"
    css = (raiz / "static" / "theme.css").read_text(encoding="utf-8")

    usadas = set()
    for plantilla in (raiz / "templates").rglob("*.html"):
        texto = plantilla.read_text(encoding="utf-8")
        usadas.update(re.findall(r'class="([^"{}]*\btable-[a-z-]+\b[^"{}]*)"', texto))

    clases = {c for grupo in usadas for c in grupo.split() if c.startswith("table-")}

    assert clases, "no se encontró ninguna clase table-* en las plantillas"
    for clase in sorted(clases):
        assert f".{clase}" in css, f"la clase '{clase}' se usa en una plantilla pero no existe en theme.css"

"""Tests de nivel app (`create_app()`) que no pertenecen a ningun
blueprint puntual -- landing raiz (`GET /`) y favicon.

La raiz dejo de ser un `redirect()` a `/operations/` -- ahora es una
landing propia (`landing.html`), con pitch + tarjetas de las secciones
principales + un vistazo de KPIs reales (`apate.web._dashboard.
dashboard_kpis()`, misma agregacion que ya usa el dashboard de
Operaciones, M13d) cuando hay operaciones cargadas."""

from html import unescape
import re

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement


def _save_operation(app, **overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    operation = Operation(**defaults)
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


def test_root_is_no_longer_a_redirect(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 200


def test_root_shows_the_approved_pitch_and_ctas(client):
    response = client.get("/")
    text = response.data.decode()
    visible_text = unescape(text)

    assert "Apate" in visible_text
    assert "Herramienta para diseñar, desplegar y medir operaciones de engaño." in visible_text
    assert "Decoys de red, identidades simuladas y honeytokens, coordinados por reglas." in visible_text
    assert f'href="{"/operations/"}"' in text
    # El CTA principal dejo de ser "ir al listado" (duplicaba la tarjeta
    # "Operaciones") y pasó a ser la accion siguiente; sin operaciones
    # cargadas, crear la primera desde el catalogo de plantillas.
    assert 'href="/operations/templates"' in text
    assert "Crear la primera operaci" in visible_text
    assert "Todas las operaciones" in visible_text


def test_root_shows_section_cards_with_correct_links(client):
    response = client.get("/")
    text = response.data.decode()
    visible_text = unescape(text)
    plain_text = re.sub(r"<[^>]+>", "", visible_text)

    cards = {
        "Operaciones": ("/operations/", "Cada operación de punta a punta: perfil de adversario, reglas, escenarios, capacidades y narrativa en un solo lugar."),
        "Portafolio": ("/operations/portfolio", "Cobertura de TTPs, activos y resultados medidos con eventos vinculados, reunidos entre operaciones."),
        "Telemetría": ("/telemetry/", "Eventos, IoCs y TTPs observadas, con incidentes, TLP, archivo de evidencia verificable y entrega manual a SIEM."),
        "Reglas": ("/rules/", "El motor de decisión determinista: condición → acción en YAML, sin que un LLM decida por vos."),
        "Catálogo de capacidades": ("/capabilities/", "Decoys, honeytokens, canarytokens, identidades simuladas: qué hay disponible y listo para usar."),
        "Salud y configuración": ("/health/", "Estado de integraciones y salud operativa: recurso, sondeo y actividad se muestran por separado."),
        "Playground": ("/playground/", "Corré un ataque real contra el stack completo y mirá cómo responde tu operación."),
        "Inventario de activos": ("/assets/", "Importá activos por CSV, vinculalos a capacidades y revisá sugerencias de colocación y cobertura."),
        "Destinos de despliegue": ("/deployments/targets", "Prepará planes confirmables para honeyusers AD y honeyfiles locales o en SMB montado; seguí su estado y frescura."),
        "Bandeja SOC": ("/attention", "Reconocé, asigná y resolvé señales y casos con evidencia y auditoría de las acciones del operador."),
    }
    assert text.count('<div class="card">') == len(cards)
    for section, (href, description) in cards.items():
        assert f'href="{href}"' in text
        assert f"<h3>{section}</h3>" in visible_text
        assert description in plain_text


def test_root_does_not_link_to_herramientas_section(client):
    # Herramientas es mecanica especifica, no una seccion de primer
    # nivel -- explicito en el pedido, no deberia aparecer como tarjeta.
    response = client.get("/")
    assert b"Herramientas" not in response.data


def test_root_without_operations_shows_explicit_empty_state_not_zeroed_kpis(client):
    response = client.get("/")
    text = response.data.decode()

    assert "Una operaci" in text and "perfil de adversario" in text
    assert "observar lo que ocurre, decidir, desplegar y reajustar" in text
    assert 'class="card kpi-card"' not in text


def test_root_with_operations_shows_real_kpis(client, app):
    _save_operation(app)
    op2 = _save_operation(app, name="Operacion 2")
    op2.mark_active()
    app.config["OPERATION_REPOSITORY"].save(op2)

    response = client.get("/")
    text = response.data.decode()

    # Los KPI se mudaron de una seccion 'De un vistazo' con tarjetas al
    # propio hero, para llenar el tercio derecho que quedaba vacio: ya no
    # son '.card.kpi-card' sino una '<dl class="hero-kpis">'.
    assert 'class="hero-kpis"' in text
    assert "<dd class=\"kpi-value\">1</dd>" in text  # 1 activa
    assert "<dd class=\"kpi-value\">0</dd>" in text  # 0 comprometidas
    assert "perfil de adversario, las reglas de interacci" not in text


def test_root_hides_the_sidebar_via_the_landing_body_class(client):
    response = client.get("/")
    text = response.data.decode()

    assert '<body class="landing">' in text


def test_locale_selector_is_visible_on_the_landing_and_returns_to_it(client):
    landing = client.get("/").get_data(as_text=True)

    assert 'id="landing-locale-select"' in landing
    assert 'name="next" value="/"' in landing
    assert landing.index('class="landing-header"') < landing.index('class="hero"')

    response = client.post("/locale", data={"locale": "en", "next": "/"})

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_operations_dashboard_still_reachable_directly(client):
    response = client.get("/operations/")
    assert response.status_code == 200
    assert b"Operaciones" in response.data


def test_base_template_declares_a_favicon(client):
    response = client.get("/")
    assert b'rel="icon"' in response.data


def test_the_brand_links_back_to_the_landing(client):
    """La marca de la barra lateral era un `<span>`: el gesto universal de
    volver al inicio clickeando el logo no hacía nada."""

    body = client.get("/operations/").get_data(as_text=True)

    assert '<a class="brand" href="/">Apate</a>' in body


def test_the_hero_offers_the_next_action_instead_of_duplicating_a_card(client, app):
    """El CTA principal iba a `/operations/`, el mismo destino que la tarjeta
    "Operaciones" de más abajo: duplicaba una tarjeta en el lugar más visible
    de la pantalla. Ahora es la acción siguiente — retomar la última operación
    tocada, o crear la primera —, que no se alcanza desde ninguna tarjeta.
    """

    vacia = client.get("/").get_data(as_text=True)
    hero_vacio = vacia[vacia.index("hero-actions") : vacia.index("Vista de impacto")]
    assert "Crear la primera operaci" in hero_vacio

    operacion = _save_operation(app, name="Operacion reciente")

    body = client.get("/").get_data(as_text=True)
    hero = body[body.index("hero-actions") : body.index("Vista de impacto")]

    assert "Retomar" in hero
    assert f"/operations/{operacion.id}" in hero


def test_the_landing_groups_its_sections_by_purpose(client):
    """Siete tarjetas planas eran un muro para quien entra por primera vez."""

    body = client.get("/").get_data(as_text=True)

    for grupo in ("Dise&ntilde;ar y operar", "Medir y reportar", "Entorno y estado"):
        assert grupo in body
    assert "Secciones principales" not in body

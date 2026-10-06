"""`apate.web._operation_templates` -- catálogo de plantillas de
operación (referencia declarada: CounterCraft Campaign Builder). Ver
docstring del módulo para el diseño completo: una plantilla precarga
el wizard, nunca crea una `Operation` sola."""

from datetime import date, timedelta

from apate.web._operation_templates import (
    describe_next_steps,
    get_template,
    list_templates,
    resolve_operation_fields,
)


def test_catalog_has_a_few_well_built_templates_not_dozens():
    templates = list_templates()
    assert 2 <= len(templates) <= 6


def test_catalog_uses_the_active_locale_inside_a_web_request(app):
    app.config["APATE_LOCALE"] = "en"

    with app.test_request_context("/operations/templates"):
        template = get_template("apt28-lateral-finance")

    assert template["operation"]["name"] == "APT28 — Lateral movement to the financial segment"
    assert template["plugins"][0]["plugin_id"] == "dolost-apt28-finance"


def test_catalog_keeps_spanish_as_the_non_request_default():
    assert list_templates() == list_templates(locale="es")


def test_every_template_has_id_summary_and_operation_fields():
    for template in list_templates():
        assert template["id"]
        assert template["summary"]
        assert template["operation"]["name"]
        assert template["operation"]["adversary_name"]
        assert template["operation"]["expected_ttps"]


def test_template_ids_are_unique():
    ids = [template["id"] for template in list_templates()]
    assert len(ids) == len(set(ids))


def test_get_template_returns_none_for_unknown_id():
    assert get_template("no-existe") is None


def test_get_template_returns_the_matching_template():
    template = list_templates()[0]
    found = get_template(template["id"])
    assert found is not None
    assert found["id"] == template["id"]
    assert found["operation"]["name"] == template["operation"]["name"]


def test_list_templates_returns_a_copy_not_the_cached_list():
    first = list_templates()
    first.append({"id": "inyectado"})
    assert "inyectado" not in [t["id"] for t in list_templates()]


def test_resolve_operation_fields_computes_absolute_end_date_from_relative_days():
    template = get_template("apt28-lateral-finance")
    fields = resolve_operation_fields(template)

    assert "end_date_days" not in fields
    expected = (date.today() + timedelta(days=template["operation"]["end_date_days"])).isoformat()
    assert fields["end_date"] == expected


def test_resolve_operation_fields_keeps_the_rest_of_the_operation_dict_untouched():
    template = get_template("fin7-support-hr")
    fields = resolve_operation_fields(template)

    assert fields["name"] == template["operation"]["name"]
    assert fields["adversary_name"] == template["operation"]["adversary_name"]
    assert fields["expected_ttps"] == template["operation"]["expected_ttps"]
    assert fields["objectives"] == template["operation"]["objectives"]


def test_resolve_operation_fields_does_not_mutate_the_cached_template():
    template = get_template("apt28-lateral-finance")
    resolve_operation_fields(template)
    assert "end_date_days" in template["operation"]
    assert "end_date" not in template["operation"]


def test_describe_next_steps_summarizes_scenario_and_plugin_kinds():
    template = get_template("lazarus-exfil-validation")
    next_steps = describe_next_steps(template)

    assert next_steps["scenario_description"] == template["scenario"]["description"]
    assert next_steps["scenario_related_ttps"] == template["scenario"]["related_ttps"]
    assert next_steps["plugin_kinds"] == ["dolost", "buda", "canarytoken", "opencanary"]


def test_describe_next_steps_never_leaks_technical_plugin_config():
    """El texto informativo de 'que sigue' es a proposito superficial
    (kind nomas) -- no debe traer hostnames/IPs/config tecnica, que solo
    tiene sentido para `examples/seed_demo.py`, no para una tarjeta de
    catalogo."""

    template = get_template("apt28-lateral-finance")
    next_steps = describe_next_steps(template)

    assert "Hostname" not in next_steps
    assert "IP" not in str(next_steps)

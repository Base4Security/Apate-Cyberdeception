"""`apate.web._narrative_coherence.build_narrative_coherence()` --
coherencia de la ficción de una operación (referencia declarada:
CounterCraft). Ver docstring del módulo para el diseño completo."""

from __future__ import annotations

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario
from apate.web._narrative_coherence import build_narrative_coherence


def _operation(**kwargs) -> Operation:
    return Operation(
        name=kwargs.pop("name", "Operación de prueba"),
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=kwargs.pop("narrative", Narrative(name="Narrativa")),
        **kwargs,
    )


def _build(operation, **panels):
    return build_narrative_coherence(
        operation,
        dolost_panels=panels.get("dolost_panels", {}),
        buda_panels=panels.get("buda_panels", {}),
        honeytoken_panels=panels.get("honeytoken_panels", {}),
        canarytoken_panels=panels.get("canarytoken_panels", {}),
        opencanary_panels=panels.get("opencanary_panels", {}),
    )


# -- Caso vacío ---------------------------------------------------------


def test_empty_operation_has_no_content():
    result = _build(_operation())
    assert result["has_content"] is False
    assert result["employees"] == []
    assert result["infrastructure"] == []
    assert result["documents"] == []
    assert result["checks"] == []


def test_operation_with_only_target_assets_has_content():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["ERP financiero"]))
    result = _build(operation)
    assert result["has_content"] is True


# -- Recolección de piezas ------------------------------------------------


def test_gathers_employees_only_from_buda_bindings():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity"))
    buda_panels = {
        "buda-1": {
            "found": True,
            "narrative_id": 1,
            "is_running": False,
            "user_profiles": [{"id": 1, "name": "Ana Gómez", "role": "Contadora", "winrm_server": "x"}],
        }
    }

    result = _build(operation, buda_panels=buda_panels)

    assert result["employees"] == [{"plugin_id": "buda-1", "name": "Ana Gómez", "role": "Contadora"}]


def test_gathers_infrastructure_directly_from_config_without_docker_panels():
    """No hace falta `dolost_panels` (estado EN VIVO) -- hostname/
    descripción vienen directo de `binding.config`, sin Docker."""

    operation = _operation()
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            config={"decoys": [{"Hostname": "FileServerBackup", "Description": "Servidor de backups"}]},
        )
    )

    result = _build(operation)  # sin dolost_panels

    assert result["infrastructure"] == [
        {"plugin_id": "dolost-1", "hostname": "FileServerBackup", "description": "Servidor de backups"}
    ]


def test_gathers_documents_from_honeytoken_panels():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data"))
    honeytoken_panels = {
        "honeytoken-1": {
            "configured": True,
            "directory": "C:\\deception\\finance",
            "filenames": ["credenciales.xlsx"],
            "paths": [],
        }
    }

    result = _build(operation, honeytoken_panels=honeytoken_panels)

    assert result["documents"] == [
        {"plugin_id": "honeytoken-1", "directory": "C:\\deception\\finance", "filenames": ["credenciales.xlsx"]}
    ]


def test_unconfigured_honeytoken_is_not_listed_as_a_document():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data"))

    result = _build(operation, honeytoken_panels={"honeytoken-1": {"configured": False, "directory": "", "filenames": []}})

    assert result["documents"] == []


def test_canarytoken_is_grouped_as_lure_without_exposing_auth_token():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="canarytoken-1", plugin_kind="canarytoken", surface="data")
    )

    result = _build(
        operation,
        canarytoken_panels={
            "canarytoken-1": {
                "configured": True,
                "token_type": "dns",
                "memo": "Portal proveedores",
                "auth_token": "secreto",
            }
        },
    )

    assert result["documents"] == [
        {
            "plugin_id": "canarytoken-1",
            "directory": "Canarytoken · dns",
            "filenames": ["Portal proveedores"],
        }
    ]
    assert "secreto" not in str(result)


def test_opencanary_services_are_grouped_as_infrastructure():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="opencanary-1", plugin_kind="opencanary", surface="network")
    )

    result = _build(
        operation,
        opencanary_panels={
            "opencanary-1": {
                "configured": True,
                "services": {"ssh": {"enabled": True, "port": 2222}},
            }
        },
    )

    assert result["infrastructure"] == [
        {
            "plugin_id": "opencanary-1",
            "hostname": "ssh:2222",
            "description": "Servicio señuelo de OpenCanary",
        }
    ]


# -- Chequeo: narrativa sin empleados ------------------------------------


def test_narrative_without_employees_is_flagged():
    operation = _operation(narrative=Narrative(name="N", description="Historia real cargada", psychological_impact="sesgo"))

    result = _build(operation)

    categories = [c["category"] for c in result["checks"]]
    assert "narrative_without_employees" in categories
    check = next(c for c in result["checks"] if c["category"] == "narrative_without_employees")
    assert check["severity"] == "info"


def test_empty_narrative_does_not_trigger_the_check():
    operation = _operation(narrative=Narrative(name="N"))  # sin descripcion ni impacto

    result = _build(operation)

    assert result["checks"] == []


def test_narrative_with_employees_does_not_trigger_the_check():
    operation = _operation(narrative=Narrative(name="N", description="Historia real"))
    operation.plugins.append(PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity"))
    buda_panels = {"buda-1": {"found": True, "is_running": False, "user_profiles": [{"id": 1, "name": "Ana", "role": "R"}]}}

    result = _build(operation, buda_panels=buda_panels)

    assert "narrative_without_employees" not in [c["category"] for c in result["checks"]]


# -- Chequeo: infraestructura/empleados sin el otro -----------------------


def test_infrastructure_without_employees_is_flagged():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            config={"decoys": [{"Hostname": "Host1"}]},
        )
    )

    result = _build(operation)

    assert "infrastructure_without_employees" in [c["category"] for c in result["checks"]]


def test_employees_without_infrastructure_is_flagged():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity"))
    buda_panels = {"buda-1": {"found": True, "is_running": False, "user_profiles": [{"id": 1, "name": "Ana", "role": "R"}]}}

    result = _build(operation, buda_panels=buda_panels)

    assert "employees_without_infrastructure" in [c["category"] for c in result["checks"]]


def test_both_infrastructure_and_employees_present_triggers_neither():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", config={"decoys": [{"Hostname": "H"}]})
    )
    operation.plugins.append(PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity"))
    buda_panels = {"buda-1": {"found": True, "is_running": False, "user_profiles": [{"id": 1, "name": "Ana", "role": "R"}]}}

    result = _build(operation, buda_panels=buda_panels)

    categories = [c["category"] for c in result["checks"]]
    assert "infrastructure_without_employees" not in categories
    assert "employees_without_infrastructure" not in categories


# -- Chequeo: activo objetivo sin representación --------------------------


def test_target_asset_without_any_textual_echo_is_flagged():
    operation = _operation(
        adversary_profile=AdversaryProfile(name="Actor", target_assets=["Base de datos de clientes premium"])
    )
    operation.scenarios.append(Scenario(description="Detectar acceso no autorizado a servidores de correo"))

    result = _build(operation)

    check = next(c for c in result["checks"] if c["category"] == "target_asset_without_representation")
    assert "Base de datos de clientes premium" in check["message"]
    assert check["severity"] == "info"


def test_target_asset_with_a_matching_scenario_keyword_is_not_flagged():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["Backups financieros"]))
    operation.scenarios.append(Scenario(description="Proteger los backups financieros del cierre de trimestre"))

    result = _build(operation)

    assert "target_asset_without_representation" not in [c["category"] for c in result["checks"]]


def test_target_asset_with_matching_infrastructure_keyword_is_not_flagged():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["Backups financieros"]))
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            config={"decoys": [{"Hostname": "FileServerBackup", "Description": "Servidor de backups financieros"}]},
        )
    )

    result = _build(operation)

    assert "target_asset_without_representation" not in [c["category"] for c in result["checks"]]


def test_target_asset_check_is_silent_without_anything_deployed_yet():
    """Sin nada desplegado (ni escenarios ni infraestructura), marcar
    cada activo como "sin representacion" seria puro ruido -- nada
    podria representarlo todavia."""

    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["Algo muy especifico"]))

    result = _build(operation)

    assert result["checks"] == []


# -- Chequeo: honeytoken sin relación --------------------------------------


def test_honeytoken_without_any_relation_is_flagged():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["Contratos legales"]))
    operation.plugins.append(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data"))
    honeytoken_panels = {
        "honeytoken-1": {"configured": True, "directory": "C:\\random\\unrelated", "filenames": ["notas.txt"]}
    }

    result = _build(operation, honeytoken_panels=honeytoken_panels)

    check = next(c for c in result["checks"] if c["category"] == "honeytoken_without_relation")
    assert check["severity"] == "info"


def test_honeytoken_with_matching_target_asset_keyword_is_not_flagged():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["Contratos legales"]))
    operation.plugins.append(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data"))
    honeytoken_panels = {
        "honeytoken-1": {"configured": True, "directory": "C:\\legal", "filenames": ["contratos_2026.xlsx"]}
    }

    result = _build(operation, honeytoken_panels=honeytoken_panels)

    assert "honeytoken_without_relation" not in [c["category"] for c in result["checks"]]


def test_honeytoken_check_is_silent_without_anything_to_compare_against():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data"))
    honeytoken_panels = {"honeytoken-1": {"configured": True, "directory": "C:\\x", "filenames": ["y.txt"]}}

    result = _build(operation, honeytoken_panels=honeytoken_panels)

    assert result["checks"] == []


# -- Todos los chequeos son "info", nunca "gap" ----------------------------


def test_every_check_severity_is_info_never_gap():
    """Ninguno de estos chequeos es lo bastante confiable como para
    llamarlo un hueco objetivo (a diferencia de apate.reporting.dry_run)
    -- ver docstring del modulo."""

    operation = _operation(
        adversary_profile=AdversaryProfile(name="Actor", target_assets=["Algo sin relacion textual alguna"]),
        narrative=Narrative(name="N", description="Historia con contenido real"),
    )
    operation.scenarios.append(Scenario(description="Escenario totalmente distinto"))
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", config={"decoys": [{"Hostname": "H"}]})
    )
    operation.plugins.append(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data"))

    result = _build(operation, honeytoken_panels={"honeytoken-1": {"configured": True, "directory": "C:\\nada", "filenames": []}})

    assert result["checks"]
    assert all(c["severity"] == "info" for c in result["checks"])


# -- Solo lectura: no muta nada -------------------------------------------


def test_does_not_mutate_the_operation():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["X"]))
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    before = operation.to_dict()

    _build(operation)

    assert operation.to_dict() == before

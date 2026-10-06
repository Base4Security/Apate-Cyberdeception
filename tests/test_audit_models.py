from apate.audit import OperatorAction


def _make_action(**overrides) -> OperatorAction:
    defaults = dict(
        operation_id="op-1",
        action="dolost_deploy",
        operator="fede",
        outcome="success",
        detail="DOLOS-T: collector y decoys de 'dolost-1' desplegados.",
    )
    defaults.update(overrides)
    return OperatorAction(**defaults)


def test_defaults_generate_id_and_timestamp():
    action = _make_action()
    assert action.id
    assert action.timestamp is not None
    assert action.plugin_id is None
    assert action.target is None


def test_roundtrip_to_dict_from_dict():
    action = _make_action(plugin_id="dolost-1", target="ssh1")
    restored = OperatorAction.from_dict(action.to_dict())

    assert restored.id == action.id
    assert restored.operation_id == action.operation_id
    assert restored.action == action.action
    assert restored.operator == action.operator
    assert restored.outcome == action.outcome
    assert restored.detail == action.detail
    assert restored.plugin_id == action.plugin_id
    assert restored.target == action.target
    assert restored.timestamp == action.timestamp


def test_from_dict_without_target_or_plugin_id_defaults_to_none():
    action = _make_action()
    data = action.to_dict()
    del data["plugin_id"]
    del data["target"]

    restored = OperatorAction.from_dict(data)

    assert restored.plugin_id is None
    assert restored.target is None


def test_verification_reports_entries_the_chain_does_not_cover(tmp_path):
    """Un historial mixto informaba `"valid"` a secas, y quien lo leyera
    concluía que todo el registro estaba íntegro. Confirmado alterando una
    entrada heredada: la verificación seguía diciendo "válido", porque esa
    entrada no participa de ningún enlace.

    La cadena hace lo que promete; el problema era cómo se comunicaba el
    resultado. Una auditoría presentada como completa cuando cubre solo una
    parte es peor que una honesta: alguien va a apoyar una decisión en ella.
    """

    import json

    from apate.audit import JSONFileOperatorActionRepository, OperatorAction

    repositorio = JSONFileOperatorActionRepository(tmp_path)
    archivo = tmp_path / "op-mixta.json"
    archivo.write_text(
        json.dumps(
            [
                {
                    "operation_id": "op-mixta",
                    "action": "heredada",
                    "operator": "Ana",
                    "outcome": "success",
                    "detail": "anterior a la cadena",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                }
            ]
        ),
        encoding="utf-8",
    )
    repositorio.append(
        OperatorAction(
            operation_id="op-mixta",
            action="nueva",
            operator="Ana",
            outcome="success",
            detail="ya encadenada",
        )
    )

    verificacion = repositorio.verify("op-mixta")

    assert verificacion.status == "valid"
    assert verificacion.unchained_count == 1
    assert not verificacion.covers_everything

    # Y cuando toda la lista está encadenada, no hay salvedad que hacer.
    repositorio.append(
        OperatorAction(
            operation_id="op-limpia",
            action="a",
            operator="Ana",
            outcome="success",
            detail="d",
        )
    )
    limpia = repositorio.verify("op-limpia")
    assert limpia.covers_everything
    assert limpia.unchained_count == 0

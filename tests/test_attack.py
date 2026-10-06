"""Tests para apate.attack (M12j) - catalogo de MITRE ATT&CK, ver
docs/analisis-engage-integral.md y src/apate/data/mitre_attack_groups.json.

Contra el dataset real (no mockeado): el catalogo es un archivo de
datos versionado, verificado contra las Navigator layer JSON reales de
MITRE (ver el campo _meta del propio JSON) -- probarlo contra el
dataset real es lo que confirma que la carga y las consultas funcionan
sobre esos datos concretos, no sobre un fixture inventado."""

from apate.attack import Group, Technique, get_group, list_groups, list_techniques


def test_list_techniques_without_filter_returns_all_41():
    techniques = list_techniques()
    assert len(techniques) == 41
    assert all(isinstance(t, Technique) for t in techniques)


def test_list_techniques_includes_known_technique():
    techniques = list_techniques()
    valid_accounts = next(t for t in techniques if t.id == "T1078")
    assert valid_accounts.name == "Valid Accounts"
    assert valid_accounts.tactic == "defense-evasion"


def test_list_techniques_filters_by_tactic():
    discovery = list_techniques(tactic="discovery")
    assert len(discovery) > 0
    assert all(t.tactic == "discovery" for t in discovery)
    assert {t.id for t in discovery} == {
        "T1033", "T1057", "T1069", "T1082", "T1083", "T1087",
    }


def test_list_techniques_with_unknown_tactic_returns_empty():
    assert list_techniques(tactic="no-existe-esta-tactica") == []


def test_list_techniques_returns_a_copy_not_shared_state():
    first = list_techniques()
    first.append(Technique(id="T9999", name="fake", tactic="fake"))
    second = list_techniques()
    assert len(second) == 41
    assert "T9999" not in {t.id for t in second}


def test_list_groups_returns_the_four_curated_groups():
    groups = list_groups()
    assert len(groups) == 4
    assert {g.id for g in groups} == {"G0007", "G0016", "G0032", "G0046"}
    assert all(isinstance(g, Group) for g in groups)


def test_list_groups_returns_a_copy_not_shared_state():
    first = list_groups()
    first.pop()
    assert len(list_groups()) == 4


def test_get_group_with_valid_id():
    group = get_group("G0007")
    assert group is not None
    assert group.name == "APT28"
    assert "Fancy Bear" in group.aliases
    assert "T1566" in group.technique_ids
    assert group.verification.startswith("completa")


def test_get_group_with_invalid_id_returns_none():
    assert get_group("G9999-no-existe") is None


def test_all_group_technique_ids_resolve_to_known_techniques():
    # Chequeo de integridad del dataset: todo technique_id referenciado
    # por un grupo tiene que existir en la lista de tecnicas -- si no,
    # el selector "cargar desde grupo APT" del formulario web
    # marcaria un checkbox que no existe.
    known_ids = {t.id for t in list_techniques()}
    for group in list_groups():
        missing = set(group.technique_ids) - known_ids
        assert not missing, f"{group.id} ({group.name}) referencia tecnicas desconocidas: {missing}"


def test_partial_verification_groups_are_flagged_as_such():
    # APT29 y Lazarus Group estan marcados como verificacion parcial
    # en el dataset (ver _meta.note) -- este test fija esa distincion
    # como algo que no deberia perderse silenciosamente si el dataset
    # se edita mas adelante.
    partial = {g.id for g in list_groups() if "parcial" in g.verification}
    complete = {g.id for g in list_groups() if "completa" in g.verification}
    assert partial == {"G0016", "G0032"}
    assert complete == {"G0007", "G0046"}

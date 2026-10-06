"""Tests para apate.engage.suggest_activities() (M12d) - motor
determinista de sugerencia TTP -> actividades de Engage, ver
docs/analisis-engage-integral.md y src/apate/data/engage_ttp_suggestions.json.

Contra el dataset real (no mockeado): igual que apate.attack/
apate.engage.catalog (M12a/M12j), este dataset es un archivo de datos
versionado, con metodologia documentada en su propio _meta -- probarlo
contra el dataset real es lo que confirma que la resolucion tecnica->
tactica->actividad funciona sobre esos datos concretos."""

from apate.attack import list_techniques
from apate.engage import Activity, get_activity, suggest_activities

# Tacticas con mapeo real en el dataset (ver tactic_activity_map).
_MAPPED_TACTICS = {
    "credential-access", "collection", "lateral-movement", "defense-evasion",
    "discovery", "execution", "command-and-control", "persistence",
    "privilege-escalation",
}

# Hallazgo real documentado en el _meta del dataset: estas cuatro
# tacticas no tienen ninguna entrada en attack_mapping.json para las
# tecnicas muestreadas -- deliberadamente sin sugerencia.
_UNMAPPED_TACTICS = {"initial-access", "impact", "exfiltration", "resource-development"}


def _first_technique_id_for_tactic(tactic: str) -> str:
    techniques = list_techniques(tactic=tactic)
    assert techniques, f"no hay tecnicas de muestra para la tactica {tactic!r} en el catalogo de M12j"
    return techniques[0].id


def test_suggest_activities_with_empty_ttps_returns_empty_list():
    assert suggest_activities([]) == []


def test_suggest_activities_for_known_mapped_technique_returns_expected_activities():
    # T1003 (OS Credential Dumping, tactic=credential-access) ->
    # tactic_activity_map["credential-access"] == ["EAC0005"].
    result = suggest_activities(["T1003"])
    assert result == [get_activity("EAC0005")]
    assert all(isinstance(a, Activity) for a in result)


def test_suggest_activities_returns_real_activity_objects_not_ids():
    result = suggest_activities(["T1005"])  # collection
    assert result
    for activity in result:
        assert isinstance(activity, Activity)
        assert hasattr(activity, "name")


def test_suggest_activities_deduplicates_across_multiple_ttps_same_tactic():
    # T1033 y T1057 son ambas 'discovery' -- no deberia duplicar los
    # eac_id de esa tactica solo porque aparecen dos veces.
    discovery_techniques = list_techniques(tactic="discovery")
    assert len(discovery_techniques) >= 2
    ttps = [discovery_techniques[0].id, discovery_techniques[1].id]

    result = suggest_activities(ttps)
    result_ids = [a.id for a in result]
    assert len(result_ids) == len(set(result_ids))


def test_suggest_activities_combines_activities_from_different_tactics():
    # T1003 (credential-access -> EAC0005) + T1071 (command-and-control
    # -> EAC0016): la union de ambas tacticas, sin duplicar EAC0005 si
    # apareciera en las dos (no es el caso aca, pero confirma que junta
    # de mas de una tactica).
    result = suggest_activities(["T1003", "T1071"])
    result_ids = {a.id for a in result}
    assert result_ids == {"EAC0005", "EAC0016"}


def test_suggest_activities_for_each_mapped_tactic_is_non_empty():
    for tactic in _MAPPED_TACTICS:
        technique_id = _first_technique_id_for_tactic(tactic)
        result = suggest_activities([technique_id])
        assert result, f"tactica mapeada {tactic!r} (via {technique_id}) no sugirio ninguna actividad"


def test_suggest_activities_for_each_unmapped_tactic_returns_empty_list():
    # El hallazgo central de M12d: estas cuatro tacticas no tienen
    # ninguna entrada real en el dataset oficial -- no se inventa nada.
    for tactic in _UNMAPPED_TACTICS:
        technique_id = _first_technique_id_for_tactic(tactic)
        result = suggest_activities([technique_id])
        assert result == [], f"tactica sin mapeo {tactic!r} (via {technique_id}) sugirio algo inventado: {result}"


def test_suggest_activities_ignores_ttp_not_in_attack_catalog():
    # Un TTP que no esta entre las 41 tecnicas curadas de M12j no
    # tiene tactica resoluble -- se ignora, no rompe ni asume nada.
    known_ids = {t.id for t in list_techniques()}
    unknown_ttp = "T9999"
    assert unknown_ttp not in known_ids

    assert suggest_activities([unknown_ttp]) == []


def test_suggest_activities_mixes_known_and_unknown_ttps():
    result = suggest_activities(["T1003", "T9999-no-existe-en-el-catalogo"])
    assert result == [get_activity("EAC0005")]


def test_all_mapped_and_unmapped_tactics_cover_every_technique_tactic_in_the_catalog():
    # Chequeo de integridad: toda tactica que aparece en el catalogo
    # de 41 tecnicas de M12j deberia estar contemplada (mapeada o
    # explicitamente sin mapeo) en este test -- si el dataset de M12d
    # suma o saca una tactica, este test lo va a marcar.
    catalog_tactics = {t.tactic for t in list_techniques()}
    accounted_for = _MAPPED_TACTICS | _UNMAPPED_TACTICS
    assert catalog_tactics == accounted_for, catalog_tactics.symmetric_difference(accounted_for)

"""Tests para el matching determinista de apate.cti.extraction --
Fase 6 post-BlackHat (ver docs/roadmap.md). Contra el catalogo REAL de
apate.attack (41 tecnicas, 4 grupos), no un catalogo de prueba
inyectado -- mismo criterio que tests/test_web_operations_ttp_heatmap.py
(M13a) confirmando ids reales del catalogo curado."""

from apate.cti.extraction import extract_candidates


def _ids(result):
    return [match.technique.id for match in result.technique_matches]


def _group_ids(result):
    return [match.group.id for match in result.group_matches]


# -- Tecnicas por id -----------------------------------------------------


def test_finds_technique_by_id_in_text():
    result = extract_candidates("Se observo la tecnica T1566 durante la campaña.")

    assert "T1566" in _ids(result)
    match = next(m for m in result.technique_matches if m.technique.id == "T1566")
    assert match.matched_via == "id"
    assert match.raw_match == "T1566"


def test_normalizes_subtechnique_id_to_parent_technique():
    result = extract_candidates("El actor uso T1566.001 (spearphishing attachment).")

    assert "T1566" in _ids(result)
    match = next(m for m in result.technique_matches if m.technique.id == "T1566")
    assert match.raw_match == "T1566.001"


def test_ignores_technique_id_outside_curated_catalog():
    # T9999 no existe en ningun catalogo real de ATT&CK -- confirma
    # que un id con la forma correcta pero inexistente no genera un
    # TechniqueMatch con technique=None ni rompe nada.
    result = extract_candidates("Referencia invalida: T9999.")

    assert _ids(result) == []


def test_technique_id_matching_is_case_insensitive():
    result = extract_candidates("tecnica t1566 observada")

    assert "T1566" in _ids(result)


def test_technique_id_requires_word_boundary_no_partial_match():
    # "T15660" no es T1566 -- el regex no debe recortar el sufijo.
    result = extract_candidates("codigo interno T15660 sin relacion")

    assert "T1566" not in _ids(result)


def test_duplicate_technique_id_mentions_produce_a_single_match():
    result = extract_candidates("T1566 aparece dos veces: T1566 de nuevo.")

    assert _ids(result).count("T1566") == 1


# -- Tecnicas por nombre ---------------------------------------------------


def test_finds_technique_by_name_when_no_id_present():
    result = extract_candidates("El atacante uso Phishing como vector de acceso inicial.")

    matches = [m for m in result.technique_matches if m.matched_via == "name"]
    assert any(m.technique.name == "Phishing" for m in matches)


def test_technique_matched_by_id_is_not_duplicated_by_name_match():
    # Mismo TTP mencionado por id Y por nombre en el mismo informe --
    # una sola sugerencia, marcada como encontrada por id (prioridad).
    result = extract_candidates("T1566 (Phishing) fue el vector inicial.")

    matching = [m for m in result.technique_matches if m.technique.id == "T1566"]
    assert len(matching) == 1
    assert matching[0].matched_via == "id"


def test_technique_name_matching_is_case_insensitive():
    result = extract_candidates("se detecto phishing dirigido")

    assert any(m.technique.name == "Phishing" for m in result.technique_matches)


def test_no_technique_mentioned_returns_empty_list():
    result = extract_candidates("Documento sin ninguna referencia relevante.")

    assert result.technique_matches == []


# -- Grupos ------------------------------------------------------------


def test_finds_group_by_canonical_name():
    result = extract_candidates("El informe atribuye la campaña a APT28.")

    assert "G0007" in _group_ids(result)
    match = next(m for m in result.group_matches if m.group.id == "G0007")
    assert match.raw_match == "APT28"


def test_finds_group_by_alias():
    result = extract_candidates("Fancy Bear fue identificado como el actor responsable.")

    assert "G0007" in _group_ids(result)
    match = next(m for m in result.group_matches if m.group.id == "G0007")
    assert match.raw_match == "Fancy Bear"


def test_group_matched_once_even_with_multiple_aliases_present():
    result = extract_candidates("APT28, tambien conocido como Fancy Bear o Sofacy.")

    assert _group_ids(result).count("G0007") == 1


def test_group_name_matching_is_case_insensitive():
    result = extract_candidates("el grupo apt28 fue responsable")

    assert "G0007" in _group_ids(result)


def test_no_group_mentioned_returns_empty_list():
    result = extract_candidates("Informe generico sin atribucion.")

    assert result.group_matches == []


def test_multiple_different_groups_all_matched():
    result = extract_candidates("Se compararon tacticas de APT28 y de FIN7 en el mismo informe.")

    assert {"G0007", "G0046"}.issubset(set(_group_ids(result)))


# -- Resultado combinado --------------------------------------------------


def test_empty_text_returns_empty_result():
    result = extract_candidates("")

    assert result.technique_matches == []
    assert result.group_matches == []

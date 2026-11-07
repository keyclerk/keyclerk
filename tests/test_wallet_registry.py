# SPDX-License-Identifier: EUPL-1.2
"""The wallet registry (0034 W0): the registry generates the queries and the registration export, and the check
refuses what a wallet would warn about or the law forbids."""
import copy
from pathlib import Path

import pytest
import yaml

from keyclerk import wallet_registry as R

EXAMPLE = Path(__file__).resolve().parent.parent / "docs" / "examples" / "wallet-registry.yaml"


@pytest.fixture
def doc():
    return R.load(EXAMPLE)


def use(doc, uid):
    return next(u for u in doc["intended_uses"] if u["use_id"] == uid)


def test_the_example_registry_passes_and_matches_its_own_export(doc):
    assert R.check(doc) == []
    assert R.check(doc, R.export(doc)) == []


def test_the_dcql_query_asks_for_exactly_the_registered_claims(doc):
    q = R.dcql(doc, "contractor-onboarding")
    assert q == {"credentials": [{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]},
                                  "claims": [{"path": ["given_name"]}, {"path": ["family_name"]},
                                             {"path": ["birthdate"]}]}]}


def test_an_mdoc_element_is_asked_inside_its_namespace(doc):
    q = R.dcql(doc, "desk-check-in")
    assert q["credentials"][0]["claims"] == [{"path": ["eu.europa.ec.eudi.pid.1", "age_over_18"]}]


def test_an_attribute_that_is_not_registered_is_refused(doc):
    reg = R.export(doc)
    use(doc, "contractor-onboarding")["credentials"][0]["claims"].append("nationalities")
    assert any("nationalities'] is asked but not registered" in e for e in R.check(doc, reg))


def test_a_registered_attribute_that_is_not_asked_is_refused_too(doc):
    reg = R.export(doc)
    use(doc, "contractor-onboarding")["credentials"][0]["claims"].remove("birthdate")
    assert any("registered but not asked" in e for e in R.check(doc, reg))


def test_an_identifying_attribute_in_a_pseudonymous_use_is_refused(doc):
    use(doc, "desk-check-in")["credentials"][0]["claims"].append("family_name")
    assert any("names family_name, which identifies the person" in e for e in R.check(doc))


def test_each_use_needs_a_privacy_policy_and_identification_needs_its_law(doc):
    d = copy.deepcopy(doc)
    del use(d, "desk-check-in")["privacy_policy"]
    del use(d, "contractor-onboarding")["legal_reference"]
    errs = R.check(d)
    assert any("privacy-policy URL" in e for e in errs) and any("legal reference" in e for e in errs)


def test_a_format_outside_the_pinned_version_table_is_refused(doc):
    use(doc, "desk-check-in")["credentials"][0]["format"] = "jwt_vc_json"
    assert any("not in the pinned version table" in e for e in R.check(doc))


def test_every_format_rests_on_pinned_versions():
    assert all(v in R.VERSIONS for vs in R.FORMATS.values() for v in vs)


def test_a_whole_credential_is_never_asked(doc):
    use(doc, "desk-check-in")["credentials"][0]["claims"] = []
    assert any("asks for no claim" in e for e in R.check(doc))


def test_the_cli_check_exits_nonzero_on_a_finding(tmp_path, doc, capsys):
    use(doc, "desk-check-in")["credentials"][0]["claims"].append("given_name")
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    assert R.main(["check", str(p), "--draft"]) == 1 and "given_name" in capsys.readouterr().err
    assert R.main(["check", str(EXAMPLE), "--draft"]) == 0


def test_w4_any_name_along_the_path_counts_and_the_rulebooks_names_are_known(doc):
    """0.29 review W4: the identifying check read only the last path element, so a nested address part passed."""
    use(doc, "desk-check-in")["credentials"][0]["claims"].append(["address", "street_address"])
    errs = R.check(doc)
    assert any("names address" in e for e in errs)
    use(doc, "desk-check-in")["credentials"][0]["claims"][-1] = "birth_country"
    assert any("names birth_country" in e for e in R.check(doc))


def test_w5_registrations_compare_paths_never_joined_strings(doc, tmp_path, capsys):
    """0.29 review W5: a path joined with "/" could stand for another path; the registration is required (or --draft)
    and dcql refuses a registry the check refuses."""
    reg = R.export(doc)
    assert all(isinstance(x, list) for u in reg["intended_uses"] for x in u["data"])
    assert R.check(doc, reg) == []
    joined = {**reg, "intended_uses": [{**u, "data": ["/".join(x) for x in u["data"]]} for u in reg["intended_uses"]]}
    with pytest.raises(R.RegistryError, match="never a joined string"):
        R.check(doc, joined)
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    assert R.main(["check", str(p)]) == 1 and "--draft" in capsys.readouterr().err
    use(doc, "desk-check-in")["credentials"][0]["claims"].append("given_name")
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    assert R.main(["dcql", str(p), "desk-check-in"]) == 1 and "given_name" in capsys.readouterr().err

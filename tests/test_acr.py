# SPDX-License-Identifier: EUPL-1.2
"""Decision 0030 point 5: an approval names its sign-in level. approvals.acr is required; init proposes one from the
realm and writes it only once confirmed; acr: none is allowed when written and is a finding at every start."""
import pytest
import yaml

from keyclerk import config, init

WELL_KNOWN = {"issuer": "https://id.example/realms/example", "acr_values_supported": ["0", "1", "2"]}


def _base():
    doc = dict(config.current())
    doc.pop("approvals", None)
    return doc


def test_a_configuration_without_approvals_acr_is_refused_with_the_next_step():
    errs = config.validate(_base())
    assert any("approvals.acr is missing" in e and "keyclerk.init acr" in e and "acr: none" in e for e in errs)
    assert config.validate({**_base(), "approvals": {"proofs": "off", "acr": "2"}}) == []


def test_acr_none_is_allowed_and_a_finding():
    none = {**_base(), "approvals": {"proofs": "off", "acr": "none"}}
    assert config.validate(none) == [] and config.approval_acr(none) is None
    assert "no required sign-in level" in config.acr_finding(none)
    level = {**_base(), "approvals": {"proofs": "required", "acr": "2"}}
    assert config.approval_acr(level) == "2" and config.acr_finding(level) is None


@pytest.mark.parametrize("values, proposed", [(["0", "1", "2"], "2"), (["silver", "gold"], "gold"),
                                             (["pwd", "passkey-only"], "passkey-only"), (["a", "b"], "b"), ([], None)])
def test_init_proposes_the_strongest_published_level(values, proposed):
    assert init.propose_acr(values) == proposed


def _cfg(tmp_path, approvals=None):
    f = tmp_path / "keyclerk.yaml"
    doc = _base() if approvals is None else {**_base(), "approvals": approvals}
    f.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return f


def _run(tmp_path, *args, ask=None, approvals=None):
    f = _cfg(tmp_path, approvals)
    code = init.acr_main(["--keycloak", "https://id.example", "--realm", "example", "--config", str(f), *args],
                         ask=ask, fetch=lambda url: WELL_KNOWN)
    return code, yaml.safe_load(f.read_text(encoding="utf-8")).get("approvals")


def test_init_writes_only_a_confirmed_published_value(tmp_path, capsys):
    code, ap = _run(tmp_path, "--write", "--accept", "2")
    assert code == 0 and ap["acr"] == "2"
    assert config.validate({**_base(), "approvals": ap}) == []
    code, ap = _run(tmp_path, "--write", "--accept", "3")                   # not published: refused
    assert code == 1 and ap is None
    code, ap = _run(tmp_path, "--write", ask=lambda p: "2")                  # confirmed in the terminal
    assert code == 0 and ap["acr"] == "2"
    code, ap = _run(tmp_path, "--write", ask=lambda p: "")                   # not confirmed: nothing written
    assert code == 1 and ap is None
    code, ap = _run(tmp_path, "--write", "--no-input")                       # never silently
    assert code == 1 and ap is None
    assert "proposed approvals.acr: 2" in capsys.readouterr().out


def test_init_keeps_an_existing_approvals_section_and_never_replaces_an_acr(tmp_path):
    code, ap = _run(tmp_path, "--write", "--accept", "1", approvals={"proofs": "required"})
    assert code == 0 and ap == {"acr": "1", "proofs": "required"}
    code, ap = _run(tmp_path, "--write", "--accept", "1", approvals={"proofs": "off", "acr": "0"})
    assert code == 1 and ap["acr"] == "0"

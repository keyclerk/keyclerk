# SPDX-License-Identifier: EUPL-1.2
"""The deployer contract (keyclerk/contract.py): it matches each service's own parser, the preflight names everything
missing at once (the edge implementation's ask after its 0.27.0 upgrade took three attempts, one refusal per start), and the guide
generated from it is current."""
from pathlib import Path

import pytest
import yaml

from keyclerk import contract as K
from keyclerk import init as I

ROOT = Path(__file__).resolve().parent.parent
CFG = yaml.safe_load((ROOT / "tests" / "fixtures" / "config.yaml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("s", K.SERVICES, ids=lambda s: s.name)
def test_the_contract_names_exactly_the_flags_each_parser_requires(s):
    assert set(s.required) == K.required_flags(K.parser_of(s))


@pytest.mark.parametrize("s", K.SERVICES, ids=lambda s: s.name)
def test_every_flag_the_contract_names_exists_in_the_service(s):
    known = {o for a in K.parser_of(s)._actions for o in a.option_strings}
    assert set(s.required) | set(s.files) | set(s.dirs) <= known


def test_the_preflight_names_everything_missing_at_once(tmp_path):
    cfg = {k: v for k, v in CFG.items() if k != "approvals"}
    got = K.check("reconciler", ["--config", str(tmp_path / "keyclerk.yaml"), "--realm", "example"], cfg)
    assert "reconciler: the configuration needs approvals.acr" in got
    assert "reconciler: --keycloak is required" in got and "reconciler: --state is required" in got
    assert any("--mark-key" in x for x in got)                       # 0.27.0's second refusal, named in the same run
    assert any("no such file" in x for x in got)


def test_a_rule_between_flags_is_named():
    got = K.check("signer", ["--key", __file__, "--state", "s", "--config", __file__, "--listen", "tcp:127.0.0.1:1",
                             "--token", __file__, "--ha-node", "node-a"], CFG)
    assert "signer: HA: --ha-node and --commit-witness together" in got


def test_a_complete_command_line_passes(tmp_path):
    key = tmp_path / "k"
    key.write_text("00" * 32, encoding="utf-8")
    assert K.check("witness", ["--key", str(key), "--name", "w.example/a", "--state", str(tmp_path / "w"),
                               "--log", "a+1+x"], CFG) == []


def test_init_check_prints_every_problem_and_exits_1(tmp_path, capsys):
    c = tmp_path / "keyclerk.yaml"
    c.write_text(yaml.safe_dump({k: v for k, v in CFG.items() if k != "approvals"}), encoding="utf-8")
    rc = I.main(["check", "--config", str(c), "--for", "desk,reconciler", "--reconciler-args", "--realm example"])
    err = capsys.readouterr()
    assert rc == 1
    assert "approvals" in err.out + err.err and "--keycloak is required" in err.out + err.err


def test_the_deployer_guide_is_generated_from_the_contract():
    assert (ROOT / "docs" / "deployer-contract.md").read_text(encoding="utf-8") == K.render()

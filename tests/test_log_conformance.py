"""Decision 0022: the change log's conformance set (canonical bytes and tree, with vectors). A verifier in another
language runs the same file;
regenerate with tools/gen_log_conformance.py after changing the formats."""
import json
import subprocess
import sys
from pathlib import Path

from keyclerk import log_conformance as C
from keyclerk.store import link as L
from keyclerk.store import merkle

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / "tests" / "conformance" / "log.json"
SET = json.loads(FILE.read_text(encoding="utf-8"))


def test_every_case_gives_its_recorded_verdict():
    assert C.count(SET) >= 30
    assert C.failures(SET) == []


def test_the_generator_writes_the_same_file(tmp_path):
    """Fixed seed keys and deterministic signatures: the file is reproducible, so a format change shows as a diff."""
    before = FILE.read_bytes()
    subprocess.run([sys.executable, str(ROOT / "tools" / "gen_log_conformance.py")], check=True, capture_output=True)
    assert FILE.read_bytes() == before


def test_each_refusal_is_refused_for_its_own_reason():
    """A vector that is refused for the wrong reason would pass a verifier that misses the check it was written for."""
    why = {
        "a byte of the body changed": "not signed by the records key",
        "signed by another key": "not signed by the records key",
        "signed under the checkpoint label": "not signed by the records key",
        "not canonical: a space after a colon": "not canonical",
        "a duplicate key": "not canonical",
        "a float": "not canonical",
        "base64 with a line break": "not base64",
        "the link before it, again": "link 1 where link 2 comes next",
        "prev names another link": "does not follow the head",
        "seq skipped": "link 3 where link 2 comes next",
        "fence lower than the link before": "fence 1 after fence 2",
        "another realm": "a link of realm elsewhere",
        "a visit in the log": "outside the log",
        "a proof that carries its token": "never the token",
        "ops out of order": "sorted by kind and key",
        "a key that is not the record's own": "not the record's own",
    }
    refused = [c for c in SET["links"]["cases"] if not c["expected"]["ok"]]
    assert {c["name"] for c in refused} == set(why)
    for c in refused:
        try:
            L.check_next(c["sealed"], c["pinned"], c["realm"], c["size"], bytes.fromhex(c["head"]) if c["head"] else None,
                         c["fence"])
        except L.StoreRefused as e:
            assert why[c["name"]] in str(e), (c["name"], str(e))
        else:
            raise AssertionError(c["name"])


def test_the_link_hash_is_the_leaf_hash_of_message_and_signature():
    import base64
    c = SET["links"]["cases"][0]
    raw = base64.b64decode(c["sealed"]["bytes"])
    data = L.LINK_FORMAT.encode() + b"\n" + raw + bytes.fromhex(c["sealed"]["signature"])
    assert merkle.leaf(data).hex() == c["expected"]["hash"]
    assert SET["links"]["cases"][1]["head"] == c["expected"]["hash"]       # the next link's prev names it


def test_the_tree_matches_the_rfc_6962_reference_roots():
    """The certificate-transparency reference inputs and roots (RFC 6962 test data), against both the recursion and
    the frontier."""
    inputs = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
    leaves = [merkle.leaf(bytes.fromhex(x)) for x in inputs]
    assert merkle.mth(leaves[:1]).hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert merkle.mth(leaves).hex() == "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
    frontier: list = []
    for i, h in enumerate(leaves):
        frontier = merkle.push(frontier, h)
        assert merkle.root(frontier) == merkle.mth(leaves[:i + 1]) and merkle.size(frontier) == i + 1


def test_the_migration_logs_end_where_their_rules_say():
    """Decision 0022 S2: what a verifier must accept of each whole log, and what it must say of the migration."""
    want = {
        "a migration in two parts, proven at link 2, then a change": (4, "proven"),
        "the YAML bytes erased: accepted, not re-provable": (4, "not re-provable: the YAML bytes were erased"),
        "a change inside the migration": (2, None),
        "a migrate link after the migration": (3, "proven"),
        "a record left out of the migration": (2, None),
        "the YAML revision signed by another key": (2, None),
    }
    got = {c["name"]: (c["expected"]["accepted"], c["expected"]["migration"]) for c in SET["logs"]["cases"]}
    assert got == want
    import base64
    for c in SET["logs"]["cases"]:                       # no token and no YAML text ever inside a link
        for sealed in c["links"]:
            assert b"broker-id-token" not in base64.b64decode(sealed["bytes"])

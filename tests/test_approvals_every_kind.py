# SPDX-License-Identifier: EUPL-1.2
"""Every kind whose rules read approved_by has its approvals proved (decision 0006)."""
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import approvals, records
from keyclerk.signer import Signer, SignerRefused
from tests.test_approvals import FIXTURES, broker, proofs, required  # noqa: F401 - fixtures


def _signer(tmp_path, proofs, policy):
    key = Ed25519PrivateKey.generate()
    signer = Signer(key, tmp_path / "state", proofs)
    signer.proofs.policy = policy
    raw = (FIXTURES / "records.yaml").read_text(encoding="utf-8")
    signer.adopt(raw, key.sign(raw.encode("utf-8")).hex())
    return signer, records.loads(raw)


def _lowering(doc):
    """The officer lowers the tenant-wide level, the owner's name written in as the second key; no proof anywhere."""
    new = copy.deepcopy(doc)
    new["revision"] = int(doc.get("revision") or 0) + 1
    new["situations"].append({"situation_id": "S-example-0099", "level": "normal", "scope": {"kind": "tenant"},
                              "source": "officer", "by": "idp:31ee-ingrid", "approved_by": ["idp:2b9e-owner"],
                              "at": "2026-10-25T09:00:00Z", "reason": "all clear"})
    return new


def test_a_second_key_on_a_situation_needs_a_proof(tmp_path, proofs, required):
    policy = required()
    _, doc = _signer(tmp_path, proofs, policy)
    new = _lowering(doc)
    assert records.validate(new) == [], records.validate(new)[:2]
    added = set(approvals.check(new, proofs, policy)) - set(approvals.check(doc, proofs, policy))
    assert added, "an approval on a situation without any proof is not reported"


def test_the_signer_refuses_an_unproved_second_key_on_a_situation(tmp_path, proofs, required):
    import hashlib
    import json

    import yaml
    policy = required()
    signer, doc = _signer(tmp_path, proofs, policy)
    new = _lowering(doc)
    raw = yaml.safe_dump(new, sort_keys=False, default_flow_style=False)
    body = {"seq": 2, "at": "2026-10-25T09:00:00Z", "revision": new["revision"], "action": "forged", "actor": None,
            "outcome": "applied", "records_sha256": hashlib.sha256(raw.encode()).hexdigest(), "prev": "0" * 64}
    body["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    with pytest.raises(SignerRefused, match="approval without a valid proof"):
        signer.commit(raw, body)


def test_a_surge_package_and_a_lease_approval_need_proofs_too(proofs, required):
    required()
    doc = records.loads((FIXTURES / "records.yaml").read_text(encoding="utf-8"))
    has = {k: [r for r in doc.get(k) or [] if r.get("approved_by")] for k in ("surge_packages", "leases", "situations")}
    walked = {kind for kind, *_ in approvals.keys_in(doc)}
    missing = [k for k, recs in has.items() if recs and k not in walked]
    assert not missing, f"approvals in {missing} are never checked for a proof"

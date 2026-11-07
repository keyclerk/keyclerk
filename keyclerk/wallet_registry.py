# SPDX-License-Identifier: EUPL-1.2
"""The home's wallet registry: intended uses and what each asks a wallet for (decision 0034 points 2 and 12, W0).

One YAML file the deployer owns is the source. From it come the wallet queries (DCQL, OpenID4VP 1.0 section 6) and
the registration export (the data the home registers per intended use). The check refuses:
- a query that differs from what the home registered for that use, in either direction: a wallet warns on a request
  beyond the registration, and the registrar's record is the authority (CIR 2026/1730);
- an identifying attribute in an intended use whose engagement kind allows pseudonyms (0032 A27, 0034 point 12);
- an intended use without its privacy-policy URL, or with identification required but no legal reference;
- a credential format or profile not in the pinned version table (point 6).

    python -m keyclerk.wallet_registry check REGISTRY.yaml --registration REGISTERED.json | --draft
    python -m keyclerk.wallet_registry dcql REGISTRY.yaml USE_ID [--registration REGISTERED.json]
    python -m keyclerk.wallet_registry export REGISTRY.yaml

The registration is compared path by path (each a list of names, never a joined string), and is required: `--draft`
checks a registry before the home has registered, and says so (0.29 review W5).
"""
import json
import re
import sys
from pathlib import Path

import yaml

# Point 6: the versions HAIP 1.0 (final, December 2025) names in its references; CI fails on anything else.
VERSIONS = {
    "openid4vp": "OpenID for Verifiable Presentations 1.0 (final)",
    "haip": "OpenID4VC High Assurance Interoperability Profile 1.0 (final)",
    "sd-jwt": "RFC 9901",
    "sd-jwt-vc": "draft-ietf-oauth-sd-jwt-vc-13",
    "token-status-list": "draft-ietf-oauth-status-list-14",
    "mdoc": "ISO/IEC 18013-5:2021",
}
FORMATS = {"dc+sd-jwt": ("sd-jwt", "sd-jwt-vc", "token-status-list"), "mso_mdoc": ("mdoc",)}
PID_VCT, PID_DOCTYPE = "urn:eudi:pid:1", "eu.europa.ec.eudi.pid.1"
# PID attributes that identify a person (the PID rulebook's names, SD-JWT VC and mdoc spellings); an age statement,
# an issuing country or an expiry does not.
IDENTIFYING = {"family_name", "given_name", "birthdate", "birth_date", "birth_family_name", "birth_given_name",
               "family_name_birth", "given_name_birth", "place_of_birth", "birth_place", "address", "resident_address",
               "resident_street", "resident_house_number", "resident_postal_code", "resident_city", "nationalities",
               "nationality", "personal_administrative_number", "picture", "portrait", "document_number", "email",
               "email_address", "phone_number", "mobile_phone_number", "sub", "trust_anchor",
               # 0.29 review W4: the rest of the PID rulebook's and ISO 18013-5's names that point at a person
               "resident_country", "resident_state", "birth_city", "birth_state", "birth_country", "age_birth_year",
               "sex", "street_address", "locality", "region", "postal_code", "house_number", "formatted",
               "signature_usual_mark", "un_distinguishing_sign", "biometric_template_face"}
ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class RegistryError(ValueError):
    pass


def load(path: Path) -> dict:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict) or not isinstance(doc.get("intended_uses"), list):
        raise RegistryError("a registry has relying_party and intended_uses")
    return doc


def _paths(cred: dict) -> list[list[str]]:
    out = []
    for c in cred.get("claims") or []:
        p = c if isinstance(c, list) else [c]
        if cred["format"] == "mso_mdoc" and len(p) == 1:
            p = [cred.get("namespace") or cred["doctype"], p[0]]     # an mdoc element sits in its namespace
        out.append([str(x) for x in p])
    return out


def dcql(doc: dict, use_id: str) -> dict:
    """The DCQL query for one intended use: exactly its credentials and claims, nothing optional added."""
    use = next((u for u in doc["intended_uses"] if u.get("use_id") == use_id), None)
    if use is None:
        raise RegistryError(f"no intended use {use_id!r}")
    creds = []
    for c in use.get("credentials") or []:
        q = {"id": c["id"], "format": c["format"]}
        q["meta"] = {"vct_values": [c["vct"]]} if c["format"] == "dc+sd-jwt" else {"doctype_value": c["doctype"]}
        q["claims"] = [{"path": p} for p in _paths(c)]
        creds.append(q)
    return {"credentials": creds}


def requested(doc: dict, use_id: str) -> set[tuple[str, ...]]:
    """What a use asks for, as (credential type, path...) tuples: the unit a registration is compared in."""
    q = dcql(doc, use_id)
    return {(((c.get("meta") or {}).get("vct_values") or [None])[0] or c["meta"]["doctype_value"], *cl["path"])
            for c in q["credentials"] for cl in c["claims"]}


def _keys(rows) -> set[tuple[str, ...]]:
    """Registered data as path tuples: each entry a list of names (W5); a legacy joined string is refused."""
    out = set()
    for r in rows or []:
        if not isinstance(r, list) or not r or not all(isinstance(x, str) for x in r):
            raise RegistryError("registered data are paths, each a list of names (credential type first), never a "
                                "joined string: export again")
        out.add(tuple(r))
    return out


def export(doc: dict) -> dict:
    """The registration data per intended use, machine-readable, from the registry (what the home submits; the
    registrar's certificate it gets back is what a request is checked against at run time)."""
    rp = doc.get("relying_party") or {}
    return {"relying_party": {k: rp.get(k) for k in ("name", "identifier", "address", "url", "contact", "services")},
            "intermediary": None,      # a home is its own relying party, never through an intermediary (point 10)
            "intended_uses": [{"use_id": u["use_id"], "purpose": u.get("purpose"),
                               "privacy_policy": u.get("privacy_policy"),
                               "pseudonymous": u.get("identification") == "pseudonym_allowed",
                               "data": [list(r) for r in sorted(requested(doc, u["use_id"]))]}
                              for u in doc["intended_uses"]]}


def check(doc: dict, registration: dict | None = None) -> list[str]:
    """Why this registry may not be used as it stands; [] when it may."""
    errs = []
    rp = doc.get("relying_party") or {}
    for k in ("name", "identifier", "url", "contact"):
        if not rp.get(k):
            errs.append(f"relying_party: {k} is missing")
    seen = set()
    reg = {u["use_id"]: _keys(u.get("data")) for u in (registration or {}).get("intended_uses") or []}
    for u in doc["intended_uses"]:
        uid = u.get("use_id")
        where = f"intended use {uid!r}"
        if not isinstance(uid, str) or not ID.match(uid):
            errs.append(f"{where}: use_id is lower-case letters, digits, - and _")
            continue
        if uid in seen:
            errs.append(f"{where}: listed twice")
        seen.add(uid)
        if not str(u.get("privacy_policy") or "").startswith("https://"):
            errs.append(f"{where}: a privacy-policy URL (https) is required per intended use")
        ident = u.get("identification")
        if ident not in ("required", "pseudonym_allowed"):
            errs.append(f"{where}: identification is required or pseudonym_allowed")
        if ident == "required" and not u.get("legal_reference"):
            errs.append(f"{where}: identification required needs its legal reference (0032 A27)")
        creds = u.get("credentials") or []
        if not creds:
            errs.append(f"{where}: asks for no credential")
        for c in creds:
            f = c.get("format")
            if f not in FORMATS:
                errs.append(f"{where}: format {f!r} is not in the pinned version table")
                continue
            if not all(v in VERSIONS for v in FORMATS[f]):
                errs.append(f"{where}: format {f!r} rests on an unpinned version")
            if f == "dc+sd-jwt" and not c.get("vct") or f == "mso_mdoc" and not c.get("doctype"):
                errs.append(f"{where}: credential {c.get('id')!r} names no vct or doctype")
                continue
            if not c.get("claims"):
                errs.append(f"{where}: credential {c.get('id')!r} asks for no claim: a whole credential is never asked")
            if ident == "pseudonym_allowed":
                for p in _paths(c):                     # W4: any name along the path, not the last one alone
                    hit = next((x for x in p if x in IDENTIFYING), None)
                    if hit:
                        errs.append(f"{where}: {'/'.join(p)} names {hit}, which identifies the person, and this use "
                                    "allows pseudonyms")
        if registration is not None and not errs:
            asked = requested(doc, uid)
            if uid not in reg:
                errs.append(f"{where}: not registered")
            else:
                for a in sorted(asked - reg[uid]):
                    errs.append(f"{where}: {list(a)} is asked but not registered")
                for a in sorted(reg[uid] - asked):
                    errs.append(f"{where}: {list(a)} is registered but not asked (the request must match exactly)")
    return errs


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in ("check", "dcql", "export"):
        print(__doc__.strip().splitlines()[-3].strip(), file=sys.stderr)
        return 2
    try:
        doc = load(Path(argv[1]))
        reg = json.loads(Path(argv[argv.index("--registration") + 1]).read_text(encoding="utf-8")) \
            if "--registration" in argv else None
        if argv[0] == "export":
            print(json.dumps(export(doc), indent=1))
            return 0
        if argv[0] == "check" and reg is None and "--draft" not in argv:
            print("refused: give --registration REGISTERED.json (what the registrar recorded), or --draft before the "
                  "home is registered", file=sys.stderr)
            return 1
        errs = check(doc, reg)
        if argv[0] == "dcql":                          # W5: a query only from a registry the check accepts
            if errs:
                for e in errs:
                    print(e, file=sys.stderr)
                return 1
            print(json.dumps(dcql(doc, argv[2]), indent=1))
            return 0
        if reg is None:
            print("draft: checked without the registration; a request is checked against it once registered",
                  file=sys.stderr)
    except (RegistryError, OSError, ValueError, KeyError, IndexError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    for e in errs:
        print(e, file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

# What KeyClerk builds on

The standards KeyClerk implements, the conventions it follows in how it is made and released, and the projects whose
work it stands on, each with a link. Tags are the ones the decision records and the code use; `tests/test_references.py`
fails when a standard the engine names, or a package it depends on, has no entry here. The edge protocol, the
contract an edge implements, has its own list: github.com/keyclerk/edge-protocol, its References section.

## Standards KeyClerk implements

### Identity and access
- [OIDC] N. Sakimura et al., *OpenID Connect Core 1.0*: sign-in at the desk, ID tokens as approval proofs.
  <https://openid.net/specs/openid-connect-core-1_0.html>
- [RFC6749] D. Hardt, *The OAuth 2.0 Authorization Framework*: the reconciler's client credentials, API clients.
  <https://www.rfc-editor.org/rfc/rfc6749>
- [RFC9449] D. Fett et al., *OAuth 2.0 Demonstrating Proof of Possession (DPoP)*: sender-constrained API tokens.
  <https://www.rfc-editor.org/rfc/rfc9449>
- [RFC7519] M. Jones, J. Bradley, N. Sakimura, *JSON Web Token (JWT)*. <https://www.rfc-editor.org/rfc/rfc7519>
- [RFC7515] M. Jones, J. Bradley, N. Sakimura, *JSON Web Signature (JWS)*: RS256 tokens from the broker.
  <https://www.rfc-editor.org/rfc/rfc7515>
- [RFC7517] M. Jones, *JSON Web Key (JWK)*: the broker's published keys. <https://www.rfc-editor.org/rfc/rfc7517>
- [RFC7638] M. Jones, N. Sakimura, *JSON Web Key (JWK) Thumbprint*: the DPoP key a token is bound to.
  <https://www.rfc-editor.org/rfc/rfc7638>
- [RFC7643] P. Hunt et al., *System for Cross-domain Identity Management: Core Schema*.
  <https://www.rfc-editor.org/rfc/rfc7643>
- [RFC7644] P. Hunt et al., *System for Cross-domain Identity Management: Protocol*: how the reconciler writes groups.
  <https://www.rfc-editor.org/rfc/rfc7644>
- [WEBAUTHN] W3C, *Web Authentication: An API for accessing Public Key Credentials, Level 3*: the PRF extension a
  passkey derives a person's key with. <https://www.w3.org/TR/webauthn-3/>

### Cryptography
- [RFC8032] S. Josefsson, I. Liusvaara, *Edwards-Curve Digital Signature Algorithm (EdDSA)*: Ed25519, every signature
  on records, links, checkpoints and bundles. <https://www.rfc-editor.org/rfc/rfc8032>
- [RFC7748] A. Langley, M. Hamburg, S. Turner, *Elliptic Curves for Security*: X25519, envelopes to people.
  <https://www.rfc-editor.org/rfc/rfc7748>
- [SP800-186] NIST, *Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters*:
  P-256, phoned unlock. <https://doi.org/10.6028/NIST.SP.800-186>
- [SP800-56A] NIST, *Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography*,
  revision 3: ECDH on P-256. <https://doi.org/10.6028/NIST.SP.800-56Ar3>
- [SEC1] Certicom Research, *SEC 1: Elliptic Curve Cryptography*, version 2.0: point encoding.
  <https://www.secg.org/sec1-v2.pdf>
- [RFC5869] H. Krawczyk, P. Eronen, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*.
  <https://www.rfc-editor.org/rfc/rfc5869>
- [RFC2104] H. Krawczyk, M. Bellare, R. Canetti, *HMAC: Keyed-Hashing for Message Authentication*.
  <https://www.rfc-editor.org/rfc/rfc2104>
- [FIPS180-4] NIST, *Secure Hash Standard (SHS)*, FIPS 180-4: SHA-256, the hashes and commitments.
  <https://doi.org/10.6028/NIST.FIPS.180-4>
- [SP800-38D] NIST, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*:
  AES-256-GCM. <https://doi.org/10.6028/NIST.SP.800-38D>
- [RFC6962] B. Laurie, A. Langley, E. Kasper, *Certificate Transparency*: the Merkle tree hashing of the signed change
  log (section 2.1). <https://www.rfc-editor.org/rfc/rfc6962>
- [TPM2] Trusted Computing Group, *TPM 2.0 Library*: the attestation an edge proves itself with.
  <https://trustedcomputinggroup.org/resource/tpm-library-specification/>

### Data, interfaces and formats
- [RFC8259] T. Bray, *The JavaScript Object Notation (JSON) Data Interchange Format*.
  <https://www.rfc-editor.org/rfc/rfc8259>
- [JSONSCHEMA] JSON Schema, *Draft 2020-12*: the records, configuration and trust-input schemas.
  <https://json-schema.org/draft/2020-12>
- [YAML] *YAML Ain't Markup Language, version 1.2.2*: the records and configuration as code.
  <https://yaml.org/spec/1.2.2/>
- [RFC3339] G. Klyne, C. Newman, *Date and Time on the Internet: Timestamps*. <https://www.rfc-editor.org/rfc/rfc3339>
- [RFC4648] S. Josefsson, *The Base16, Base32, and Base64 Data Encodings*. <https://www.rfc-editor.org/rfc/rfc4648>
- [RFC9110] R. Fielding, M. Nottingham, J. Reschke, *HTTP Semantics*. <https://www.rfc-editor.org/rfc/rfc9110>
- [OPENAPI] OpenAPI Initiative, *OpenAPI Specification 3.1.0*: the API contract (`keyclerk/schema/api.openapi.json`).
  <https://spec.openapis.org/oas/v3.1.0>
- [PROMETHEUS] Prometheus, *Exposition formats*: the metrics. <https://prometheus.io/docs/instrumenting/exposition_formats/>
- [REGO] Open Policy Agent, *Policy Language (Rego)*: every rule the engine decides with.
  <https://www.openpolicyagent.org/docs/latest/policy-language/>
- [OPA-WASM] Open Policy Agent, *WebAssembly*: the policies compiled and evaluated in process.
  <https://www.openpolicyagent.org/docs/latest/wasm/>
- [WASM] W3C, *WebAssembly Core Specification*. <https://www.w3.org/TR/wasm-core-2/>
- [QR] ISO/IEC 18004:2015, *QR Code bar code symbology specification*: visit codes.
  <https://www.iso.org/standard/62021.html>
- [OSDP] Security Industry Association, *Open Supervised Device Protocol*: the door-controller connector.
  <https://www.securityindustry.org/industry-standards/open-supervised-device-protocol/>
- [RFC5424] R. Gerhards, *The Syslog Protocol*, and [RFC5425] F. Miao, Y. Ma, J. Salowey, *Transport Layer Security
  (TLS) Transport Mapping for Syslog*: the planned SIEM export. <https://www.rfc-editor.org/rfc/rfc5424>,
  <https://www.rfc-editor.org/rfc/rfc5425>

## Conventions and guidance KeyClerk follows
- [EUPL] European Union Public Licence, version 1.2: KeyClerk's licence.
  <https://interoperable-europe.ec.europa.eu/collection/eupl/eupl-text-eupl-12>
- [REUSE] Free Software Foundation Europe, *REUSE Specification*: every file carries its licence.
  <https://reuse.software/spec/>
- [SPDX] The Linux Foundation, *SPDX License List*: licence identifiers. <https://spdx.org/licenses/>
- [ADR] M. Nygard, *Documenting Architecture Decisions* (2011): the decision records in `docs/decisions`.
  <https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions>
- [SCORECARD] OpenSSF, *Scorecard*: the repository's supply-chain checks. <https://github.com/ossf/scorecard>
- [BESTPRACTICES] OpenSSF, *Best Practices Badge*. <https://www.bestpractices.dev/>
- [SLSA] SLSA, *Provenance, version 1.0*: what a release's attestation states. <https://slsa.dev/spec/v1.0/provenance>
- [TRUSTED-PUBLISHING] Python Packaging Authority, *Trusted Publishers*: releases to PyPI without a stored token.
  <https://docs.pypi.org/trusted-publishers/>
- [EDPB-02-2025] European Data Protection Board, *Guidelines 02/2025 on processing of personal data through
  blockchain technologies*: applied by analogy to an append-only log in decision 0028.
  <https://www.edpb.europa.eu/documents/guideline/guidelines-022025-on-processing-of-personal-data-through-blockchain_en>
- [SSF] OpenID Foundation, *Shared Signals Framework* and CAEP: the planned access-ended signals.
  <https://openid.net/wg/sharedsignals/>

## Software KeyClerk stands on

### At run time
- [PYTHON] The Python Software Foundation, *Python*. <https://www.python.org/>
- [KEYCLOAK] Keycloak: the identity broker KeyClerk governs, through its SCIM endpoint and admin API.
  <https://github.com/keycloak/keycloak>
- [OPA] Open Policy Agent: the policy engine whose Rego and WebAssembly compiler the policies are built with.
  <https://github.com/open-policy-agent/opa>
- [WASMTIME] Bytecode Alliance, *wasmtime-py*: the WebAssembly runtime the compiled policies run in.
  <https://github.com/bytecodealliance/wasmtime-py>
- [CRYPTOGRAPHY] Python Cryptographic Authority, *cryptography*: every key and signature.
  <https://github.com/pyca/cryptography>
- [PYYAML] *PyYAML*. <https://github.com/yaml/pyyaml>
- [JSONSCHEMA-PY] *jsonschema* for Python. <https://github.com/python-jsonschema/jsonschema>
- [SEGNO] *Segno*: QR codes. <https://github.com/heuer/segno>
- [SQLITE] *SQLite*: the signed change log's store. <https://sqlite.org/>

### To build, test and release it
- [PYTEST] *pytest*. <https://github.com/pytest-dev/pytest>
- [HYPOTHESIS] *Hypothesis*: property-based and state-machine tests. <https://github.com/HypothesisWorks/hypothesis>
- [LIBOSDP] *LibOSDP*: the OSDP stack the door-controller tests drive. <https://github.com/goToMain/libosdp>
- [RUFF] Astral, *Ruff*: the linter. <https://github.com/astral-sh/ruff>
- [UV] Astral, *uv*: the hash-locked requirement files. <https://github.com/astral-sh/uv>
- [REUSE-TOOL] Free Software Foundation Europe, *reuse*: the licence check. <https://github.com/fsfe/reuse-tool>
- [CLUSTERFUZZLITE] Google, *ClusterFuzzLite*: continuous fuzzing in CI. <https://github.com/google/clusterfuzzlite>
- [ATHERIS] Google, *Atheris*: the Python fuzzing engine. <https://github.com/google/atheris>
- [ATTEST] GitHub, *attest-build-provenance*: the release's signed provenance.
  <https://github.com/actions/attest-build-provenance>

## Named for context
- [RFC8785] A. Rundgren, B. Jordan, S. Erdtman, *JSON Canonicalization Scheme (JCS)*: a different canonical form,
  named to say KeyClerk does not use it. <https://www.rfc-editor.org/rfc/rfc8785>
- [WARPGATE] Warpgate: an access gateway an edge can drive with the leases it applies; the pull request template is
  adapted from its own. <https://github.com/warp-tech/warpgate>
- [SPIFFE] SPIFFE: workload identity, which a workload's account in KeyClerk can carry. <https://spiffe.io/>
- [TLAPLUS] L. Lamport, *TLA+*: the language of the planned specification the two-node edge profile is checked against.
  <https://lamport.azurewebsites.net/tla/tla.html>
- [OTEL] OpenTelemetry: where an organisation's device telemetry belongs, never in KeyClerk's records.
  <https://opentelemetry.io/>

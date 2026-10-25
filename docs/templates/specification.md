# <Title>

<One paragraph: what this specifies, between whom, and what it is for. Cite each outside standard or product at its
first mention, for example "signed with Ed25519 [RFC8032]".>

Status: version <x.y> of the formats named below, as <product> <version> ships them. <Where the conformance vectors
are.> Words like "must" are normative.

## 1. <First section>
<Normative text. Name an algorithm or format by its standard, with the citation tag, the first time it appears in a
paragraph. Inside code blocks no tags are needed; cite the standard in the paragraph that introduces the block.>

## <n>. Conformance
<Where the vectors are, what an implementation must reproduce, and that keys in them are test seeds.>

## References

### Normative
<What an implementation must follow to interoperate. One entry per standard, sorted by tag:>
- [RFC8032] S. Josefsson, I. Liusvaara, *Edwards-Curve Digital Signature Algorithm (EdDSA)*: Ed25519.
  <https://www.rfc-editor.org/rfc/rfc8032>

### Informative
<Context: products named, related standards this does not use, tools whose output formats the text refers to.>
- [KEYCLOAK] Keycloak, <what it is to this specification>. <https://www.keycloak.org/>

<!-- The rules (checked in CI by the repository's tools/check.py):
- every outside standard or product the text names is cited with [TAG] in the paragraph where it first appears;
- every cited tag has an entry here, every entry has an https link, and every entry is cited at least once;
- Normative and Informative are both present; an entry goes under Normative only if an implementation needs it.
Tags: RFCnnnn for RFCs, FIPSnnn-n and SPnnn-nnn for NIST, short capitals for others (TPM2, WASM, WEBAUTHN). -->

# What sets KeyClerk apart

Most identity governance suites keep their truth in a database their administrators control, assume they can always
reach the systems they govern, and grow by breadth: more connectors, more workflow, more screens. KeyClerk grows the
other way. It stays small and puts its weight on what can be proven. This page lists what it does that such suites
usually do not, and how each is meant to grow. Each line names the decision behind it; a claim moves here only with
code and tests.

The runtime stays compact, flexible, federable and distributable, self-healing and reconcilable, and fully auditable
(operator, 2026-10-24). Every expansion below is judged on those properties first, and on capable by policy, secure by
default.

## What it does

| Property | What it means | Decisions |
|---|---|---|
| Approvals you can verify | An approval is the approver's own sign-in at the broker, bound to the change by a nonce; high-risk changes also carry the proposer's own proof. Anyone can check it later without trusting KeyClerk's store. | 0006, 0015 |
| A signer that checks before it signs | The records key lives in its own process and signs a revision only when the engine's checks and the approval proofs allow it. Whoever takes over the desk can refuse or delay, never widen. | 0015 |
| History that replays | Records are signed revisions; any moment can be rebuilt and every answer recomputed from them. | 0005 |
| Governance that works offline | Edges receive signed bundles inside a ceiling their own officer signs, run on offline horizons, accept carried visit leases and phoned unlock codes, and prove their TPM and boot state. | 0014, 0016 |
| One policy for core and edge | The same Rego, compiled to Wasm, decides on the desk and in an edge agent in another language; conformance vectors prove they agree. | 0008, 0014, edge interface |
| Physical and logical access in one model | Places, zones, badges and visits sit beside grants, leases and edges. | 0009, 0010 |
| Crisis levels | Pre-approved surge packages switch on under a declared situation and lapse with it. | situation levels, 0011a |
| Secrets to a person, not to administrators | Credentials and break-glass halves are encrypted to keys a person's passkey derives, relayed once, and split between two custodians. | 0014 |
| Small | One image, no database; about 21,000 lines of its own code. | 0004 |

## How each grows

- **Verifiable approvals become an evidence pack.** Reviews, impact diffs and accepted SoD conflicts are signatures
  in the same scheme (vault decisions G1, G3, G4). Next, one export per audit period (records, proofs, witness
  signatures) and `keyclerk verify`, so an auditor checks it offline; later the format published for other tools.
- **The checking signer holds every key that grants.** The bundle key and the desk's unlock key move into it, and it
  checks each lease against the records and a sealed identity map from the reconciler (E3, G14). A witness on another
  machine countersigns revision heads, and edges echo the heads they saw (G10). A TPM or HSM backend keeps the signer's
  key out of any file.
- **Replay answers more questions.** The impact of a change is signed into its approval (G3); a diff between any two
  moments shows what changed in a person's access and who signed each step; a legal-hold export.
- **The edge interface becomes a specification.** Two independent implementations (the Python reference and an
  independent Go edge agent) and the conformance set; the HA profile (two nodes) against a TLA+ specification (G12, G13).
- **Policy as a library.** The Rego modules with their tests and vectors, packaged so a deployment's own policies get
  the same discipline and other components (a sign-in proxy for legacy systems) reuse the same decisions.
- **Physical and logical in one review.** Badge zones and logical access at a place in one review, each owner signing
  their part, a mismatch as a trigger (G9); later, a badge saying on site checked against an edge session saying on
  site.
- **Federated governance.** Connected organisations vouch for their people by signature; a lease here ends when the
  home organisation's leaver flow ends them.
- **Crisis levels tied to incidents.** A declared incident opens its surge package and its end closes it, with proof
  that everything lapsed (G11).

## Where suites stay ahead

Breadth: hundreds of connectors, flexible schemas and mappings, provisioning dependencies, mature administration
screens. KeyClerk does not compete there; it reconciles through a few connectors and leaves breadth to the systems it
governs.

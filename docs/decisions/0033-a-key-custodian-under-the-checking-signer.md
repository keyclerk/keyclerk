# 0033. A key custodian under the checking signer

- Status: accepted (2026-11-05), after an adversarial review, a prior-art review and the maintainer's decision round the
  same day
  (docs/reviews/2026-11-05-0033-prior-art.md). The maintainer asked for it after an adversarial review of porting the
  core to Go (docs/reviews/2026-11-05-go-core-adversarial review.md). Builds on 0015 (the checking signer, and "an HSM or PKCS#11 backend can sit behind the same socket
  later"), 0021 (every granting key in the signer), 0022 (the change log), 0030 point 1 (the records key rotated and
  recovered, an optional TPM or HSM backend) and 0031 (the core signer in HA mode, the commit witness). Built with
  roadmap step 8 in 0.29.0.
- Context: the checking signer (0015) holds the records key and signs a change only after the engine's checks, the
  approval proofs and the history guard allow it. Those checks are most of KeyClerk: the signer's refusal path calls
  the engine (records.guard, scope.guard_errors, reconcile.check_records, the working set, approvals, anchors), about
  20,000 of its 26,000 lines. So the process that judges and the process that holds the key are one, and a flaw
  anywhere in that Python trust base reaches the key. The review of a Go port found no speed problem (0.4 to 1.8 s a
  change at 26,000 people, the signer busy at most 8.4 % of the busiest hour), found the risks to be logic rather than
  memory safety, and found the independence of the Python desk and the Go edge agent, joined by conformance vectors, to
  be an asset. It recommended keeping the judge in Python and moving the key alone into a small Go process whose own
  checks are structural.

## What others do (the prior art, in short)
- **Logs put the key behind an interface that checks nothing.** Trillian (crypto/keys: a plain crypto.Signer), Tessera
  (an in-process note.Signer), Sunlight (a seed file in process) and Rekor (KMS, Tink, file or memory, all
  signature.Signer) sign what they are given; Go's sumdb note.Signer is Name, KeyHash and Sign. Key managers are the same:
  smallstep's KMS is a key handle with no policy on content, and Vault and OpenBao transit sign any input their path
  ACLs allow.
- **The fork guard sits in the application, after signing.** Sunlight's lock backend replaces the stored checkpoint by
  compare-and-swap after the tree head is signed, and stops the log on a mismatch; its README says the lock "ensures
  that logs won't encounter a fatal split even due to accidental operational mistakes such as running two Sunlight
  instances", and that "an attacker who can modify it can cause Sunlight to sign a split view". Trillian relies on master
  election, whose own documentation says more than one instance can believe it is master.
- **The one key holder that checks before it signs is the witness.** transparency-dev/witness keeps its state with its
  key and cosigns only a checkpoint whose old size equals the one it last cosigned and whose consistency proof holds.
  C2SP's checkpoint spec puts the rule on every signer: "A log or cosigner MUST NOT sign any checkpoint which is
  inconsistent with any checkpoint it previously signed". The custodian is that rule enforced where the key is.
- **Validator remote signers are the nearest analogue,** and their failures are the warning. CometBFT's privval persists
  its last height, round and step before the signature leaves and returns the stored signature for the same request;
  tmkms keeps a state file per chain but updates memory before the disk and treats a missing file as a first run at
  height 0; Horcrux's check and update under two locks let two requests for one position both pass (a double sign on
  Osmosis, 2025-03-06, 5 % slashed); keys live on two hosts after a failover slashed 11 validators at Lido on 2023-04-13
  and 40 on SSV Network on 2025-09-10. EIP-3076 moves a signer's state between machines as a watermark that an import
  can only raise, with both ends stopped.
- **Two certificate transparency logs were disqualified for what the custodian prevents:** Izenpe (2016-05-18) "presented
  two conflicting views of the Merkle Tree", from "reusing the key between a production instance and a testing
  instance"; Venafi (2017) after a cloud provider's outage.
- **A structural check does not catch the judge's bugs:** Let's Encrypt's linter shared Boulder's off-by-one in 2021
  (Bugzilla 1715455). The custodian is a floor under the history, not a second judge.
- **Hardware has limits that shape the design:** no TPM on sale implements Ed25519 (the TCG constants exist in go-tpm,
  no shipping part); every Go PKCS#11 library needs cgo, so a PKCS#11 build is not a static binary; TPM NV counters wear
  (reportedly about 100,000 writes, to be measured); Signal's secure value recovery warns that a counter on disk is reset
  by imaging the disk.

## Decision
1. **The custodian is a separate process, `keyclerk-custodian`, written in Go, and the only one that can read the
   records key.** The checking signer keeps every check it has today but no longer holds the key: it asks the custodian
   to sign. The key file belongs to the custodian's own operating-system user. A production key is never loaded by a
   development or test custodian, which refuses a key whose realm is not its own (the Izenpe lesson).
2. **It refuses, on its own state alone, anything that would break the log's structure,** whatever the signer asks:
   - a link only at exactly the next position, naming the last link's hash, in this realm, with a fence never lower
     than the last, and in the link format (kc-change-link-v1) within the per-change cap (0022);
   - one body per position: the same body again gets the same signature (Ed25519 is deterministic), another body at a
     signed position is refused;
   - a checkpoint, a C2SP note or a snapshot statement only over the size, root and head it computed itself from the
     links it signed, never lower than the last: consistency is computed, so no proof is needed;
   - in HA mode (0031), nothing at a position the commit witness's last countersigned checkpoint has already passed, the
     custodian checking the countersignature itself.
   C2SP's rule (never sign a checkpoint inconsistent with one signed before) is its conformance test. It judges no
   business rule; a compromised signer can still sign a valid but wrong change, which followers and the witness see,
   but can never fork or rewrite the history or sign two things at one position.
3. **Check, persist, sign, in one critical section.** Each request is checked, its new state written (a temporary file,
   fsync, rename, fsync of the directory), and only then signed and answered; memory never runs ahead of the disk, and
   a failed write stops the custodian rather than answer. Two requests for one position give one signature, and a test
   says so (the Horcrux race).
4. **A missing state is never a first run.** With a key and no state the custodian refuses to sign. Lost or corrupted
   state is recovered by an offline ceremony that only raises the floor: the newest of the commit witness's last
   countersigned checkpoint and the followers' heads, confirmed by two people (Q6), recorded as a signed marker in the
   log. State moves between machines only as an exported watermark (realm, size, head, fence, last checkpoint), with
   both ends stopped, an import that can only raise, and the exporter retiring itself (as EIP-3076).
5. **Its own rollback is detected and refused.** At start, and before signing after any restart, the custodian compares
   its state with the commit witness's last countersigned checkpoint (or the detection witness's outside HA) and refuses
   while it is behind. On a host with a TPM its state is bound to an NV monotonic counter, raised per checkpoint epoch
   and at recovery, not per link (wear; Q8); a counter and state that disagree stop it.
6. **Where the key lives.** A file of the custodian's own user is the baseline; with a TPM the file is sealed to the
   machine's boot state (PCRs), and the TPM holds the counter, never the key. Behind PKCS#11 (YubiHSM 2 and other HSMs
   with CKM_EDDSA) in a separate, dynamically linked build, the module's Ed25519 checked at start. Ed25519 stays: a curve
   a TPM can hold would change the log format and every verifier for a benefit the structural checks do not need.
7. **The protocol is the signer protocol's own,** over a local socket only (a Unix socket, or loopback where there is
   none): `sign_link`, `sign_checkpoint`, `sign_note`, `sign_snapshot`, `state`, each answered with a signature or a
   refusal that says why. Nothing in the desk changes.
8. **Small by rule:** the static build has the Go standard library, golang.org/x/sys and go-tpm; the PKCS#11 build adds
   one PKCS#11 module; together under 3,000 lines.
9. **Verification:** the log conformance vectors (tests/conformance/log.json, c2sp-go.json) extended with every refusal,
   run by the Python reference and the custodian; the concurrency test of point 3; the request parser fuzzed
   (ClusterFuzzLite); the whole Python suite run with the signer talking to the custodian; the failover model
   (docs/specs/SignerFailover.tla) and its explorer extended with the custodian as the authority on positions, and with
   a custodian restored from an older state.
10. **Kill criterion:** if the custodian needs any knowledge of the engine (scopes, grants, policy, approvals) to do its
    job, the boundary is wrong, and the work stops rather than grow.

## What does not change
- The Python checking signer stays the judge and the reference engine; the TLA+ specifications stay language-neutral;
  the Python desk and the Go edge agent stay independent, joined only by conformance vectors.
- The edge relay stays with the desk logic it relays.
- Porting the engine is not decided here. It is reopened only on evidence: if, after the streaming full check is
  built, the busiest hour passes about half of the signer's time at a real deployment's size, or the 500,000-identity
  benchmark misses its budget for a reason a profile pins on the language; and then one check at a time, a Go checker
  shadowing the Python one with differential verdicts.

## The maintainer's answers (decision round, 2026-11-05)
The ten questions went through the decision round (state: the vault's .claude/data/decide/keyclerk-0033-open.json). Three
were the maintainer's choice; seven followed a precedent or are cheap to reverse inward, and were defaulted with the
reason given.
- Q1 **Default** (maintainer): the custodian is the production default; the in-process key stays for development and
  tests only, and a development or test custodian refuses a production key. Against it: one more process on the
  smallest sites.
- Q2 **Where its code lives** (default): a Go module in this repository, cmd/keyclerk-custodian, released and exported
  with the engine and its vectors; cheap to move later.
- Q3 **Keys in phase A** (default): the records key alone; the bundle and unlock keys follow when they fit the budget.
- Q4 **Two signer nodes** (maintainer): each node runs its own custodian with the same key; the commit witness is the
  fence, desks adopt only countersigned links, and a custodian refuses to start or sign while its state is behind the
  witness. The residual is stated: a second signature at a position can exist, and is never adopted.
- Q5 **Phase B** (deferred): the witness and commit witness in Go are decided after phase A.
- Q6 **Lost state** (precedent, 0031 and 0032): an offline ceremony by the security officer and a root trust owner that
  raises the floor from the commit witness and the followers, recorded as a signed marker.
- Q7 **A rollback on a host without a TPM** (maintainer): the custodian refuses to sign until the two people recover it
  (Q6). Signing stops, access continues on the edges' horizons; a false alarm stops revocations too, because the
  custodian cannot let only reductions through without knowing the engine.
- Q8 **The counter's cadence** (default): per checkpoint epoch and at recovery, once the TPM's write limits are
  measured.
- Q9 **The PKCS#11 build** (precedent, 0015 and 0030 point 1): in phase A, as a separate dynamically linked build.
- Q10 **The fence** (precedent, 0031): in HA the commit witness's countersigned checkpoints; outside HA the custodian's own
  position; no lease, no election.

## Consequences
- One more process in a production deployment, small and static; development keeps one process.
- The records key's trust base shrinks from CPython and twelve packages to the Go standard library and at most two
  modules.
- Step 8's TPM and PKCS#11 work lands in the custodian, not in Python bindings.
- A second implementation of the log format exists, checked by vectors, as the edge agent is for bundles.
- A new failure mode: a custodian that refuses (behind the witness, a counter mismatch, lost state) stops signing until
  two people act. Access continues on the edges' horizons.

## Changelog
- 2026-11-05 Proposed after the review of porting the core to Go.
- 2026-11-05 Revised after the prior-art review: the witness as precedent, persist-then-sign in one critical section,
  no first run without state, a recovery ceremony and watermark export, rollback checked against the witness, no TPM-held
  Ed25519 key, a separate PKCS#11 build, the production key never in a test custodian; questions Q1 to Q5 rephrased and
  Q6 to Q10 added.
- 2026-11-05 The questions decided (Q1, Q4 and Q7 by the maintainer, the rest by precedent or default; Q5 deferred).
- 2026-11-05 Accepted by the maintainer.

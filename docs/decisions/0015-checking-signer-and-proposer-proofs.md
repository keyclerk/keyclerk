# 0015: A checking signer holds the records key, and a high-risk change carries its proposer's own signature

- Status: accepted (2026-10-23, choices D1 and D2), after an adversarial review of the whole design found that whoever
  took over the desk process could sign any revision
- Date: 2026-10-23
- Amends 0005 (the desk signs record revisions) and 0006 (approvals are the approver's own signature).

## Context
The desk process serves people, edges and unauthenticated endpoints, and until now it held the records key in memory.
Whoever took over that process could sign any revision: a membership nobody proposed, a delegation past every limit, an
approval list with names on it. The reconciler checks approvals against the broker (0006), but the proposer of a change
was vouched for by the desk alone, and the engine's own checks ran only inside the process that was compromised.

## Decision
1. **D1, the checking signer.** The records key lives in its own process (`python -m keyclerk.signer`), readable only by
   its own user, answering on a local socket (a Unix socket guarded by file permissions, or loopback TCP with a token).
   The desk runs with `--signer` and holds no records key. Before it signs a revision the signer checks it against its
   own copy of the last revision it signed:
   - the revision is exactly one higher, and the history is not rewritten (`records.guard`);
   - it adds no engine check error the last revision did not have;
   - with approval proofs configured, it adds no approval without a valid proof, and (D2) no high-risk record without
     its proposer's proof.

   A log line that vouches for a revision is signed only with that commit; other log lines are signed as they come. An
   existing store is handed over once with `--adopt`, which accepts only records signed with the signer's own key. An
   HSM or PKCS#11 backend can sit behind the same socket later; nothing in the desk changes for it.
2. **D2, proposer proofs by risk class.** A record is high risk when it is a membership of an elevated or privileged
   group (its effective class), a delegation, or anything a root holder proposes. The classes are policy
   (`approvals.proposer_proof`: `classes`, `delegations`, `root`, `off`); this is the default. Where approval proofs are
   required, a high-risk change waits for its proposer, who signs it the way an approver does: a fresh sign-in at the
   broker whose nonce is the proposal statement (`keyclerk-proposal`, so an approval never stands for a proposal or the
   other way round). The proof is kept in `proposal_proofs`, which only grows. Low-risk changes stay desk-vouched.
   Ending a record sooner needs no second signature: taking away is never the risky direction.

## What it does not cover
- A compromised desk can still refuse, delay or log noise, and show a person one change while asking the broker to sign
  another (the broker's sign-in page does not show the change; 0006 names the same limit).
- The signer checks transitions. Records made before proofs existed stay as they were; the reconciler keeps verifying
  approvals as before (0006), and the signer is where proposer proofs are checked.
- The signer trusts its own state directory. Losing it means adopting the store again, which an administrator does by hand.

## Consequences
- Taking over the desk no longer yields the records key, and no longer yields a signed revision that the engine's checks,
  the approvers or the proposer did not allow.
- Elevated and privileged changes take one more sign-in for the person proposing them.
- Deployment: one more process with its own user and state directory; the desk's `--signing-key` stays for development.

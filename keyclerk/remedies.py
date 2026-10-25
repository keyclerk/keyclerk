# SPDX-License-Identifier: EUPL-1.2
"""Why something did not happen, and what would make it happen: every refusal and every change that waits comes back
with next steps a person can act on (decision 0005).

Each engine or desk reason maps to a plain explanation (why), what completes the intent (do), and who can do it: the
people whose approval would count, the managers holding the power needed, or the root. Who is computed from the
records by the desk (keyclerk.desk), never guessed here; this module only knows which kind of person each reason
needs. A reason without a rule still gets a step: the root is the last resort.
"""
from __future__ import annotations

import re

# (pattern, why, do, who): who is "approvers", "managers", "root", "self" or None; {0}, {1} are the pattern's groups
ENGINE = [
    (r"(\S+) does not count: .*returns a favour",
     "{0} cannot be the second key: you approved a change of theirs recently, and keys are not traded.",
     "Ask another person with standing, or wait until the reciprocity window has passed.", "approvers"),
    (r"(\S+) does not count: .*the root is never a second key",
     "The root trust owner never counts as a second key: the most powerful account is never the check on itself.",
     "Ask the security officer or a named approver. The root can appoint a named approver with the security "
     "officer's key.", "approvers"),
    (r"(\S+) does not count: .*no standing",
     "{0} has no standing as a second key: only the security officer, a named approver, or someone who manages "
     "the group through another chain counts.",
     "Ask one of them to approve it under Approvals. If nobody fits, the root can appoint a named approver with the "
     "security officer's key.", "approvers"),
    (r"needs a second key from outside the actor's chain \((\w+) group\)",
     "The group is {0}: a second person, from outside the chain of delegations you act under, must agree.",
     "Ask one of them to approve it under Approvals. It waits for 7 days.", "approvers"),
    (r"a RESTRICTED badge needs a second key",
     "A RESTRICTED badge is signed out by two people: another front office person or the steward of the place must agree.",
     "Ask them to approve it under Approvals. It waits for 7 days.", "approvers"),
    (r"appointing a named approver needs the security officer's key",
     "A named approver is appointed by the root with the security officer's agreement.",
     "Ask the security officer to approve it under Approvals.", "approvers"),
    (r"needs the security officer's key",
     "Elevated or privileged delegations made by the root need the security officer's agreement.",
     "Ask the security officer to approve it under Approvals.", "approvers"),
    (r"including (\S+) needs the members power over \S+ too",
     "Nesting {0} brings its members into the group, so whoever manages {0} must agree.",
     "Ask one of them to approve it under Approvals.", "approvers"),
    (r"delegating privileged groups needs a second key",
     "Delegating privileged groups needs a second person from outside the chain.",
     "Ask one of them to approve it under Approvals.", "approvers"),
    (r"the actor added themselves", "Nobody adds themselves to a group.",
     "Ask another manager of the group to add you.", "managers"),
    (r"(\S+) is (\w+), above what \S+ allows",
     "{0} is classed {1}, above what your delegation covers.",
     "Ask someone whose delegation covers {1} groups to make this change, or the root.", "managers"),
    (r"(\S+) is classed below (\S+); an included group is classed at least as high",
     "{0} is classed lower than {1}, and a nested group must be classed at least as high as the group it joins.",
     "Nest a group of at least the same class, or ask the root to change a class.", "root"),
    (r"did not hold when it was made", "The delegation this was made under does not hold now.",
     "Propose it again under a delegation that holds, or ask a manager of the group.", "managers"),
    (r"widenings on \S+, above (\d+)", "The daily limit of {0} additions of access was reached.",
     "Try again tomorrow, or ask the root.", "root"),
    (r"powers wider than the parent's|max_risk above the parent's|max_membership_days above the parent's|"
     r"depth_left not below the parent's|outlives or predates its parent|group outside the parent's subtree",
     "A delegation can only narrow what you hold yourself.",
     "Delegate no more than your own delegation gives (see My desk): fewer powers, a lower class, a shorter time.", None),
    (r"longer than (\d+) days", "That is longer than the {0} days allowed.", "Choose at most {0} days.", None),
    (r"members are tenant persons; externals come through leases only",
     "People from outside the organisation get access through a lease, not a membership.",
     "Ask the root to arrange a lease for them.", "root"),
    (r"a privileged group neither includes nor is included", "Privileged groups have named members only.",
     "Add the people one by one instead of nesting a group.", None),
    (r"the include closes a cycle", "That would nest a group inside itself.", "Nest a different group.", None),
    (r"the include puts the actor into a group they manage", "This nesting would make you a member of a group you manage.",
     "Ask another manager of the group to make it.", "managers"),
    (r"delegated to oneself or to the root trust owner", "Nobody delegates to themselves or to the root.",
     "Choose another person.", None),
    (r"a deputy is a tenant person", "Only people of the organisation can be deputies.", "Choose another person.", None),
    (r"the delegate is already in the chain above", "That person already delegates to you.", "Choose another person.", None),
]

DESK = [
    (r"your own signature: this change is high risk",
     "This change is high risk, so it carries your own signature as well as the desk's.",
     "Open the change under Approvals and sign it: you sign in again with your passkey.", None),
    (r"you hold no delegation that gives the power '(\w+)' over (\S+) now",
     "You do not manage {1} with the power '{0}'.",
     "Ask one of them to make the change, or to delegate the power '{0}' over {1} to you.", "managers"),
    (r"that person is not in the records", "That person is not in the records yet.",
     "Ask the root to add them to the records first.", "root"),
    (r"that membership already holds", "That person is already a member.", "Nothing to do.", None),
    (r"the same change already waits", "The same change already waits for approval.",
     "Approve it, or withdraw it, under Approvals.", None),
    (r"days must be a whole number from 1 to (\d+)", "The length must be 1 to {0} days.", "Choose a length in that range.", None),
    (r"give a reason", "A reason is kept with the change.", "Write a reason of at least 3 characters.", None),
    (r"too many changes in a short time", "You made many changes in a short time.",
     "Wait a few minutes, then try again. The limit is per person.", None),
    (r"exists already", "A group with that id exists already.", "Pick another id.", None),
    (r"there is no (group|membership|delegation) (\S+)", "There is no {0} {1}.", "Check the id under Groups or Delegations.", None),
    (r"only the root, someone above in its chain, or the deputy", "Only the root, someone above in its chain, or the deputy may end it.",
     "Ask one of them.", "root"),
    (r"you proposed this change", "A second key is someone else's, never the proposer's.",
     "Ask one of them to approve it.", "approvers"),
    (r"you approved this change already", "Your key is in; it waits for another key.",
     "Ask one of them to approve it.", "approvers"),
    (r"does not count as a key this change needs", "Your approval is not one of the keys this change needs.",
     "Ask one of them to approve it.", "approvers"),
    (r"an approval is your own signature",
     "An approval is your own signature: you sign in again, with your passkey.",
     "Use Approve (sign in). No passkey yet? Set one up in your account first.", "self"),
    (r"not at the authentication level", "A password alone is not enough to approve.",
     "Approve again and use your passkey. No passkey yet? Set one up in your account first.", "self"),
    (r"not from a fresh sign-in", "Approvals need a fresh sign-in.", "Start the approval again from Changes.", "self"),
    (r"for another change or another person|someone else's", "The sign-in was for another change or another person.",
     "Start the approval again from Changes, signed in as yourself.", "self"),
    (r"waited too long and has expired", "The change waited more than 7 days and expired.", "Propose it again.", None),
    (r"changes already wait for approval", "Too many changes wait for approval across the realm.",
     "Ask approvers to settle waiting changes first, then try again.", None),
    (r"no such change waits for approval", "That change no longer waits: it was applied, withdrawn or expired.",
     "See the change log under Approvals.", None),
    (r"only who proposed it, or the root, may withdraw", "Only who proposed it, or the root, may withdraw it.",
     "Ask them.", "root"),
]


def plain(reason: str) -> str:
    """An engine reason without the record id it starts with (M-x-0001: ...)."""
    return re.sub(r"^[A-Z]{1,3}-[\w-]+: ", "", str(reason))


def match(reason: str, table=None) -> tuple[str, str, str | None]:
    """(why, do, who-kind) for one reason; a reason no rule knows sends the person to the root."""
    text = plain(reason)
    for pattern, why, do, who in (table if table is not None else ENGINE + DESK):
        m = re.search(pattern, text)
        if m:
            g = m.groups()
            return why.format(*g), do.format(*g), who
    return text[0:1].upper() + text[1:], "If this should be possible, ask the root.", "root"

# 0011: Personas, workloads and agents

- Status: accepted for building (2026-10-23). The question it answers: should one person in the HR records have
  several digital personas, for example a sysadmin with a normal account and an admin account, or is that an outdated
  idea? The demo must also show two workload identities and three agents: two directed by a workload, one a personal
  assistant directed by an employee.
- Date: 2026-10-23
- The position on a separate admin persona stands until a better argument overturns it; the line is a setting
  (`identity.privileged_needs_admin`, default true), so a deployment that disagrees changes one value.

## Context
A person record already holds several anchors (one person, several accounts) and a kind: tenant, external or agent.
What is missing: why a person has a second account and what it may be used for; workloads as identities of their own;
and who directs an agent, which decides how far the agent may reach.

## The question: a separate admin account, or one account with elevation?
Position: **keep a separate admin persona for privileged work, but not the old way.** The old way is a second account
with standing rights, a password, and a mailbox, used from the same laptop. That is worse than one account.
The new way:
- the admin persona holds **no standing privilege**: its privileged memberships are given for hours, with a second key
  (0010 section 2);
- it signs in **only** with its own hardware key, from a privileged-access device, never from the daily browser;
- it has no mailbox, no browsing, no chat: nothing that reads untrusted content.

Why not only elevation on the daily account: elevation limits *when* a right exists, not *where the tokens live*. The
daily session reads mail and the web, and a token stolen from that browser is the most common way in. A separate
persona keeps the privileged session's credentials, cookies and tokens away from that surface; elevation on one account
cannot. This is what current guidance for privileged access still asks for (tiered access with separate privileged
accounts on privileged devices).

The strongest case against: two accounts are friction, and people work around friction. So the line is drawn by class:
- **privileged** groups: only an admin persona may be a member (default; a setting);
- **elevated** groups: the daily account with step-up and a membership in hours is enough;
- **low**: the daily account.

## Decision
1. **Personas.** A person lists their accounts with a purpose: `daily` or `admin` (a deployment may add purposes). An
   admin persona belongs to the same person: separation of duties, reviews, standing and leaving all count per person,
   never per account. Rego decides that a privileged membership needs an admin persona.
2. **Workloads.** A new kind `workload`: a service identity (a SPIFFE ID, a client), with an **owner** (a person who
   answers for it). It never signs in interactively, never approves, never delegates. It may hold entitlements like
   anyone, within its owner's envelope.
3. **Agents.** Kind `agent`, with a **director**: the workload or the person that directs it, and an owner. An agent
   acts on behalf of its director: what it may do is the intersection of what it was given and what its director holds
   at that moment (on-behalf-of, as token exchange's actor claim). When the director loses a right, the agent does too;
   when the director leaves, the agent stops. An agent never approves, never delegates, never directs another agent.
4. **The persona graph** shows them: a person with both personas, a workload with its owner, an agent with its
   director, and what each reaches.

## Consequences
- Records: `persons[].personas` (anchor and purpose), kind `workload`, `owner` and `director` on workloads and agents.
- A new compiled policy decides personas and agents (identity.rego), like every KeyClerk rule.
- The demo tenant gets a sysadmin with a daily and an admin persona, two workloads, two agents directed by a workload and
  a personal assistant agent directed by an employee.

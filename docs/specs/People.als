-- SPDX-License-Identifier: EUPL-1.2
-- Decision 0032: who may relate to whom. The design's rules (points 2 to 25) are one predicate, Design; each
-- invariant is checked under it, and each broken variant (the Design with one rule left out, from the adversarial review)
-- must yield a counterexample. Run: java -jar org.alloytools.alloy.dist.jar exec -c '*' docs/specs/People.als
-- (tools/check_people_model.py reads the receipt and says which held and which broke as expected).

abstract sig Kind {}
one sig Employee, Contractor, Partner, Visitor extends Kind {}
abstract sig State {}
one sig Active, Suspended, Ended extends State {}
abstract sig Plane {}
one sig Daily, Admin extends Plane {}
sig Right {}
sig Home {}
sig Subject {}

sig Org { orgHome: one Home }

sig Person {
  home: one Home,
  rights: set Right,
  deputyOf: set Person              -- the people who appointed this person as their deputy
}
sig Tombstone in Person {}          -- a past person kept only so their signatures verify (point 4)
sig ForCause in Person {}           -- ended for cause (point 12)

sig Engagement {
  person: one Person,
  org: one Org,
  kind: one Kind,
  sponsor: lone Person,
  state: one State
}

sig Persona {
  owner: one Person,
  plane: one Plane,
  subject: one Subject,             -- the home's pairwise subject (point 2)
  under: set Engagement
}
sig ActivePersona in Persona {}

sig Workload { wOwner: one Person, wRights: set Right }
sig Agent { director: one (Person + Workload), aOwner: one Person, aRights: set Right }

abstract sig Class {}
one sig BreakGlass, SiteAgent, Unmanaged extends Class {}
sig Account { persona: lone Persona, cls: lone Class, accountable: lone Person }

sig Claim { claimSubject: one Person, checker: one Person }
sig Grant { eng: one Engagement, onPersona: one Persona, approver: one Person, restsOn: set Claim }

fun activeEng[p: Person]: set Engagement { { e: Engagement | e.person = p and e.state = Active } }
fun sponsoredBy: Person -> Person { { a, b: Person | some e: Engagement | e.person = a and e.sponsor = b } }

-- The rules ---------------------------------------------------------------------------------------------------------

pred Pairwise {                     -- point 2: a subject identifies personae of one home only
  all disj p, q: Persona | p.subject = q.subject => p.owner.home = q.owner.home
}
pred OnlyThroughEngagement {        -- point 4: no person without an engagement, apart from tombstones
  all p: Person - Tombstone | some e: Engagement | e.person = p
  no e: Engagement | e.person in Tombstone and e.state = Active
}
pred PersonaRules {                 -- points 12 and 15
  all x: Persona | some x.under and x.under.person = x.owner
  all x: Persona | x.plane = Admin => one x.under
  all x: ActivePersona | some (x.under & activeEng[x.owner]) and x.owner not in ForCause
}
pred ForCauseSuspendsAll {          -- point 12
  all p: ForCause, e: Engagement | e.person = p => e.state != Active
}
pred SponsorRules {                 -- point 9
  all e: Engagement | e.kind = Employee <=> no e.sponsor
  all e: Engagement | some e.sponsor => {
    e.sponsor != e.person
    e.sponsor.home = e.person.home
    some s: activeEng[e.sponsor] | s.kind = Employee
  }
}
pred RoleSeparation {               -- points 25 and N10, N11
  all g: Grant {
    g.approver != g.eng.person
    g.approver not in g.eng.sponsor
    g.approver not in g.restsOn.checker
    g.eng.person not in g.approver.deputyOf
    some activeEng[g.approver]
  }
  all g: Grant, c: g.restsOn | c.checker != c.claimSubject and c.checker not in g.eng.sponsor
}
pred GrantRules {                   -- points 11 and 30
  all g: Grant | g.onPersona.owner = g.eng.person and g.eng in g.onPersona.under
  all g: Grant | g.restsOn.claimSubject in g.eng.person
}
pred AgentWithinPeople {            -- point 6: the intersection over director, director's owner and own owner
  all a: Agent | a.aRights in a.aOwner.rights
  all a: Agent | a.director in Person => a.aRights in a.director.rights
  all a: Agent | a.director in Workload => a.aRights in a.director.wRights & a.director.wOwner.rights
}
pred AccountsOwned {                -- point 7
  all a: Account | no a.persona => (some a.cls and some a.accountable and some activeEng[a.accountable])
  all a: Account | some a.persona => no a.cls
}

pred Design {
  Pairwise and OnlyThroughEngagement and PersonaRules and ForCauseSuspendsAll and SponsorRules
  and RoleSeparation and GrantRules and AgentWithinPeople and AccountsOwned
}

-- The invariants ----------------------------------------------------------------------------------------------------

pred NoCrossHomeId { all disj p, q: Persona | p.owner.home != q.owner.home => p.subject != q.subject }       -- N1
pred NoPersonWithoutEngagement { all p: Person - Tombstone | some e: Engagement | e.person = p }             -- N2
pred EveryAccountOwned { all a: Account | some a.persona or (some a.accountable and some activeEng[a.accountable]) } -- N2
pred AgentNeverBeyondItsPeople { all a: Agent | a.aRights in a.aOwner.rights                                   -- N8
                                 and (a.director in Workload => a.aRights in a.director.wOwner.rights) }
pred NoSelfApproval { all g: Grant | g.approver != g.eng.person and g.eng.person not in g.approver.deputyOf } -- N10
pred DistinctRoles { all g: Grant | g.approver not in g.eng.sponsor + g.restsOn.checker }                      -- N11
pred SponsorsGrounded {            -- N11: every sponsor's authority rests on an active engagement of their own that
  all e: Engagement | some e.sponsor =>  -- nobody sponsors (an employee's), so a sponsor leaving leaves no chain behind
    some f: activeEng[e.sponsor] | no f.sponsor and f.kind = Employee
}
pred ForCauseHoldsNothing { no x: ActivePersona | x.owner in ForCause }                                       -- N14
pred ApproverActive { all g: Grant | some activeEng[g.approver] }                                            -- N2

-- The design is not vacuous: an instance with a sponsored contractor, a grant and an agent exists.
run Populated { Design and some e: Engagement | e.kind = Contractor and some g: Grant | g.eng = e
                and some Agent and some ActivePersona } for 4 but exactly 2 Home

check Holds_N1 { Design => NoCrossHomeId } for 5
check Holds_N2 { Design => NoPersonWithoutEngagement and EveryAccountOwned and ApproverActive } for 5
check Holds_N8 { Design => AgentNeverBeyondItsPeople } for 5
check Holds_N10 { Design => NoSelfApproval } for 5
check Holds_N11 { Design => DistinctRoles and SponsorsGrounded } for 5
check Holds_N14 { Design => ForCauseHoldsNothing } for 5

-- Broken variants: the design with one rule left out must break its invariant (a counterexample is expected).
check Breaks_L8_agentBoundedByDirectorOnly { (Pairwise and OnlyThroughEngagement and PersonaRules and ForCauseSuspendsAll
  and SponsorRules and RoleSeparation and GrantRules and AccountsOwned
  and (all a: Agent | a.director in Person => a.aRights in a.director.rights)
  and (all a: Agent | a.director in Workload => a.aRights in a.director.wRights)) => AgentNeverBeyondItsPeople } for 5
check Breaks_F1_noRoleSeparation { (Pairwise and OnlyThroughEngagement and PersonaRules and ForCauseSuspendsAll
  and SponsorRules and GrantRules and AgentWithinPeople and AccountsOwned) => DistinctRoles } for 5
check Breaks_L3_sponsorAnyPerson { (Pairwise and OnlyThroughEngagement and PersonaRules and ForCauseSuspendsAll
  and RoleSeparation and GrantRules and AgentWithinPeople and AccountsOwned
  and (all e: Engagement | some e.sponsor => e.sponsor != e.person)) => SponsorsGrounded } for 5
check Breaks_L2_forCauseOneEngagementOnly { (Pairwise and OnlyThroughEngagement and SponsorRules and RoleSeparation
  and GrantRules and AgentWithinPeople and AccountsOwned
  and (all x: Persona | some x.under and x.under.person = x.owner)
  and (all x: ActivePersona | some (x.under & activeEng[x.owner]))) => ForCauseHoldsNothing } for 5
check Breaks_L7_unownedAccounts { (Pairwise and OnlyThroughEngagement and PersonaRules and ForCauseSuspendsAll
  and SponsorRules and RoleSeparation and GrantRules and AgentWithinPeople) => EveryAccountOwned } for 5
check Breaks_L9_deputyApproves { (Pairwise and OnlyThroughEngagement and PersonaRules and ForCauseSuspendsAll
  and SponsorRules and GrantRules and AgentWithinPeople and AccountsOwned
  and (all g: Grant | g.approver != g.eng.person)) => NoSelfApproval } for 5
check Breaks_P4_sharedUpstreamSubject { (OnlyThroughEngagement and PersonaRules and ForCauseSuspendsAll and SponsorRules
  and RoleSeparation and GrantRules and AgentWithinPeople and AccountsOwned) => NoCrossHomeId } for 5 but exactly 2 Home

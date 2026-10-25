// SPDX-License-Identifier: EUPL-1.2
// KeyClerk front end: a thin client of the KeyClerk API (/api/v1, contract at /api/v1/openapi.json).
// It holds no rules: what is shown and what may be done comes from the API, and the engine decides every change.
// Every API call goes through call() and the CALLS table below, which tests hold equal to the contract.
// Everything shown is built with DOM methods and text nodes: data never becomes HTML.
"use strict";

const CALLS = {
  me: ["GET", "/me"],
  people: ["GET", "/people"],
  person: ["GET", "/people/{anchor}"],
  graph: ["GET", "/people/{anchor}/graph"],
  tree: ["GET", "/delegations/tree"],
  visits: ["GET", "/visits"],
  visit: ["GET", "/visits/{visit_id}"],
  visitqr: ["GET", "/visits/{visit_id}/qr/{party}"],
  scan: ["GET", "/scan/{token}"],
  groups: ["GET", "/groups"],
  group: ["GET", "/groups/{group_id}"],
  delegations: ["GET", "/delegations"],
  changes: ["GET", "/changes"],
  propose: ["POST", "/changes"],
  preview: ["POST", "/changes/preview"],
  approve: ["POST", "/changes/{change_id}/approve"],
  phonelink: ["GET", "/changes/{change_id}/phone-link"],
  approvalsignin: ["POST", "/changes/{change_id}/approval-sign-in"],
  statement: ["GET", "/changes/{change_id}/statement"],
  withdraw: ["POST", "/changes/{change_id}/withdraw"],
  broker: ["GET", "/broker"],
  mykeys: ["GET", "/me/keys"],
  relay: ["GET", "/relay"],
  relaytake: ["POST", "/relay/{relay_id}/take"],
  relayconfirm: ["POST", "/relay/{relay_id}/confirm"],
  edges: ["GET", "/edges"],
  setceiling: ["POST", "/edges/{edge_id}/ceiling"],
  unlock: ["POST", "/edges/{edge_id}/unlock"],
  closeincident: ["POST", "/edges/{edge_id}/incidents/{incident_id}/close"],
  myvisits: ["GET", "/me/visit-leases"],
  carried: ["POST", "/me/visit-leases/{lease_id}/carried"],
  contract: ["GET", "/openapi.json"],
};

let ME = null;

async function call(name, params, body, query) {
  const [method, template] = CALLS[name];
  const qs = query ? "?" + new URLSearchParams(query).toString() : "";
  const path = template.replace(/\{(\w+)\}/g, (_, k) => encodeURIComponent(params[k])) + qs;
  const headers = { "Accept": "application/json" };
  if (method === "POST") {
    headers["Content-Type"] = "application/json";
    headers["X-KeyClerk-CSRF"] = ME && ME.csrf ? ME.csrf : "";
  }
  const res = await fetch("/api/v1" + path, { method, headers, credentials: "same-origin",
    body: method === "POST" ? JSON.stringify(body || {}) : undefined });
  const data = await res.json().catch(() => ({ error: { code: "invalid", message: "not JSON" } }));
  if (!res.ok) {
    const err = new Error((data.error && data.error.message) || res.statusText);
    err.status = res.status;
    err.code = data.error && data.error.code;
    err.next = (data.error && data.error.next) || stepsFor(res.status, err.code);
    throw err;
  }
  return data;
}

// --- building blocks --------------------------------------------------------------------------------------------

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const present = kids => kids.flat(Infinity).filter(k => k !== null && k !== undefined && k !== false);
// Every element filled with parts, some of them optional: replaceChildren alone would write a left-out part as "null"
const fill = (el, ...kids) => el.replaceChildren(...present(kids));
const pill = (text, cls, title) => h("span", { class: "pill " + (cls || ""), title }, text);
const RISK_WORDS = { low: "Low", elevated: "Elevated", privileged: "Privileged" };
// A class is not an outcome: outlined, one to three bars, Privileged filled; never the ok/warn/bad colours
const riskTag = (r, title) => h("span", { class: "tag risk-" + (r || "unknown"), title },
  h("span", { class: "bars", "aria-hidden": "true" }, h("i", {}), h("i", {}), h("i", {})), RISK_WORDS[r] || r || "unknown");
// One status vocabulary (desk-upgrade.md): a word and a glyph, never colour alone; "pending" is never shown as a word.
// A change that is pending waits for a key; a grant that is pending starts later: status() is for changes, grantStatus()
// for memberships, delegations and graph links.
const STATUS = {
  applied: ["Done", "ok"], pending: ["Waiting for a key", "warn"], refused: ["Refused", "bad"], withdrawn: ["Withdrawn", ""],
  expired: ["Expired unsigned", ""], recovered: ["Recovered", "plum"], unreadable: ["Unreadable", "bad"], error: ["Not done", "bad"],
  active: ["In force", "ok"], ok: ["In force", "ok"], starts: ["Starts later", ""], grace: ["Ending, grace period", "warn"],
  standby: ["On standby", "warn"], ended: ["Ended", ""], dead: ["Ended: a link above ended", ""], revoked: ["Revoked for cause", "bad"],
  void: ["Void", "bad"], lapsed: ["Lapsed", "warn"], invalid: ["Not valid", "bad"] };
const status = s => { const [word, tone] = STATUS[s] || [String(s), ""]; return pill(word, "st " + (tone || "neutral")); };
const grantStatus = s => status(s === "pending" ? "starts" : s);
const link = (href, text, cls) => h("a", { href, class: cls }, text);
const groupLink = g => link("#/group/" + encodeURIComponent(g), g);
const who = (anchor, name) => name ? h("span", { class: "person", title: anchor }, name) : h("code", {}, anchor);
const personLink = (anchor, name) => link("#/person/" + encodeURIComponent(anchor), name || anchor);
const idTag = id => h("span", { class: "id" }, id);
const empty = text => h("p", { class: "empty" }, text);
const ALL_POWERS = ["delegate", "includes", "members", "rules", "subgroups"];
const POWER_WORDS = { members: "add people", includes: "nest groups", subgroups: "make subgroups", delegate: "delegate", rules: "rules" };
function powers(list) {
  if (ALL_POWERS.every(p => list.includes(p))) return pill("all powers", "plum", list.join(", "));
  return list.map(p => pill(POWER_WORDS[p] || p, "", p));
}

// Dates people read: "1 Mar 2027", and how far away it is.
const DAY = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric" });
const STAMP = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
const REL = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const asDate = t => t ? new Date(t) : null;
const day = t => t ? DAY.format(asDate(t)) : "";
const stamp = t => t ? STAMP.format(asDate(t)) : "";
function rel(t) {
  if (!t) return "";
  const s = (asDate(t) - Date.now()) / 1000, a = Math.abs(s);
  const [n, u] = a < 90 ? [s, "second"] : a < 5400 ? [s / 60, "minute"] : a < 129600 ? [s / 3600, "hour"]
    : a < 5184000 ? [s / 86400, "day"] : a < 47304000 ? [s / 2592000, "month"] : [s / 31536000, "year"];
  return REL.format(Math.round(n), u);
}
const when = t => t ? h("span", {}, day(t)) : "";
// A moment as visible text (never only in a tooltip, which touch and keyboard users cannot reach), the relative time beside it
const moment = t => t ? h("span", { class: "moment" }, stamp(t), h("span", { class: "muted small" }, " (" + rel(t) + ")")) : "";

// A table that becomes labelled cards on a phone.
function table(head, rows, caption) {
  return h("div", { class: "wrap" }, h("table", {},
    caption ? h("caption", { class: "vh" }, caption) : null,
    h("thead", {}, h("tr", { class: "head" }, head.map(x => h("th", { scope: "col" }, x)))),
    h("tbody", {}, rows.map(r => h("tr", {}, r.map((c, i) => h("td", { "data-label": head[i] || null }, c)))))));
}

// One layout for every page head (operator, 2026-10-23: button placement): crumbs; the title with the page's own
// actions at its right (headActions); the lead; anything else below.
const headActions = (...kids) => h("div", { class: "headactions" }, kids);
function pageHead(title, lead, ...extra) {
  const is = (x, c) => x && x.classList && x.classList.contains(c);
  return h("div", { class: "pagehead" }, extra.filter(x => is(x, "crumbs")),
    h("div", { class: "titlerow" }, h("h1", {}, title), extra.filter(x => is(x, "headactions"))),
    lead ? h("p", { class: "lead" }, lead) : null,
    extra.filter(x => !is(x, "crumbs") && !is(x, "headactions")));
}
const section = (title, ...kids) => h("section", { class: "section" }, h("h2", {}, title), kids);

// Views return what to show; route() shows it only if no newer navigation started meanwhile (a slow page never
// overwrites the one the person asked for after it).
let ROUTE_ID = 0;
let SHOWN_HASH = null;
const setMain = (...kids) => ({ render: kids });
function show(kids) {
  const main = document.getElementById("main");
  const had = document.activeElement;
  const first = SHOWN_HASH === null;                       // the first page: Tab starts at the skip link
  const moved = !first && SHOWN_HASH !== (location.hash || "#/");
  main.removeAttribute("aria-busy");
  fill(main, ...present(kids));
  SHOWN_HASH = location.hash || "#/";
  const h1 = main.querySelector("h1");
  const plainTitle = h1 ? (() => { const c = h1.cloneNode(true); c.querySelectorAll(".pill, .tag").forEach(x => x.remove());
    return c.textContent.replace(/\s+/g, " ").trim(); })() : "KeyClerk";
  document.title = plainTitle + " - KeyClerk";
  // a new page, or the control that had focus is gone: focus the heading, so a screen reader starts at the top
  if (h1 && !first && (moved || !document.contains(had))) {
    h1.setAttribute("tabindex", "-1");
    h1.focus({ preventScroll: !moved });
  }
}

// What to do when the desk never got to decide: the session, the page, the load (the desk explains its own refusals).
function stepsFor(status, code) {
  const s = (why, doit) => [{ why, do: doit, who: [] }];
  if (status === 401) return s("Your sign-in has ended: it lasts 15 minutes, or you were signed out at your organisation's sign-in.",
    "Sign in again, then repeat what you did.");
  if (code === "csrf") return s("This page is older than your current sign-in.", "Reload the page, then repeat what you did.");
  if (status === 429) return s("Too many requests from you in a short time.", "Wait a minute, then try again.");
  if (status === 503) return s("The desk is busy.", "Try again in a few seconds.");
  if (status === 403) return s("This is not yours to see or do.", "Ask someone who manages it, or the root.");
  if (status >= 500) return s("Something went wrong on the desk; nothing was changed by it.", "Try again; if it keeps failing, tell the operator.");
  return [];
}

function people(list, max) {
  if (!list || !list.length) return null;
  const shown = list.slice(0, max || 8), rest = list.length - shown.length;
  return h("span", { class: "who" }, shown.map(w => pill(w.name || w.anchor, "plum", w.anchor)),
    rest > 0 ? h("span", { class: "muted small" }, "and " + rest + " more") : null);
}

function nextSteps(steps, shown) {
  if (!steps || !steps.length) return null;
  const said = new Set((shown || []).map(x => plain(x).toLowerCase()));      // a reason listed under Why is not repeated
  const fresh = w => w && !said.has(String(w).toLowerCase());
  return h("div", { class: "next" }, h("h4", {}, "What you can do"),
    h("ol", {}, steps.map(st => h("li", {}, h("span", { class: "do" }, st.do), fresh(st.why) ? h("div", { class: "why small muted" }, st.why) : null,
      st.who && st.who.length ? h("div", { class: "who" }, h("span", { class: "muted small" }, "Ask: "), people(st.who)) : null))));
}

// One panel for every outcome: a preview, the result of a change, a page that could not be shown. In this order: what
// happened, what you can do, why (the engine's words), and the rule ids last, for the security officer.
const OUTCOME_HEAD = {
  applied: ["Done", "It reaches the sign-in service within a minute."],
  pending: ["Waiting for a key", "Someone else's key completes it; they see it under Approvals."],
  refused: ["Refused", "Nothing was changed."], error: ["Not done", "Nothing was changed."], withdrawn: ["Withdrawn", ""], info: ["", ""] };
const PREVIEW_HEAD = {
  applied: ["Can be done right away", "Nothing is changed until you confirm."],
  pending: ["Would wait for a key", "Someone else's key would complete it."],
  refused: ["Would be refused", "Nothing is changed."] };
// a change that waits only for its proposer's own signature (decision 0015): no one else's key is missing
const SIGN_OWN = /^your own signature: this change is high risk/;
const onlyOwnSignature = r => r.outcome === "pending" && (r.reasons || []).length > 0 && r.reasons.every(x => SIGN_OWN.test(x));
function outcome(r, opts) {
  const o = opts || {};
  const kind = r.outcome || "info";
  const [word, sub] = onlyOwnSignature(r)
    ? (o.preview ? ["Would wait for your signature", "You sign it at the broker after you propose it."]
      : ["Waiting for your signature", "Open it under Approvals and sign it."])
    : (o.preview ? PREVIEW_HEAD : OUTCOME_HEAD)[kind] || ["", ""];
  const reasons = (r.reasons || []).filter(Boolean);
  const heading = h("h3", { tabindex: "-1" }, h("span", { class: "glyph", "aria-hidden": "true" }),
    o.title || [word, r.summary ? (word ? ": " : "") + r.summary : ""]);
  const bad = kind === "refused" || kind === "error";
  const el = h("div", { class: "outcome " + kind, role: bad ? "alert" : "status" }, heading,
    o.lead || (r.message ? h("p", {}, r.message) : sub ? h("p", { class: "small" }, sub,
      !o.preview && kind === "pending" && r.change_id ? [" ", h("a", { href: "#/change/" + r.change_id }, "Open the change")] : null) : null),
    nextSteps(r.next, kind !== "applied" ? reasons : []),
    reasons.length && kind !== "applied" ? h("div", { class: "whylist" }, h("h4", {}, "Why"),
      h("ul", {}, reasons.map(x => h("li", {}, plain(x))))) : null,
    reasons.some(x => plain(x) !== String(x)) ? h("details", { class: "small" }, h("summary", {}, "Details for the security officer"),
      h("ul", { class: "mono" }, reasons.map(x => h("li", {}, String(x))))) : null,
    o.actions || null);
  if (o.focus) setTimeout(() => heading.focus(), 0);
  return el;
}

const plain = r => String(r).replace(/^[A-Z]{1,3}-[\w-]+: /, "");

function banner(result) {
  const b = document.getElementById("banner");
  if (!result) { b.hidden = true; return; }
  const visitOnly = result.records && Object.keys(result.records).length
    && Object.keys(result.records).every(k => k.startsWith("visit"));
  const bad = result.outcome === "refused" || result.outcome === "error";
  b.className = "banner " + result.outcome;
  fill(b, h("div", { class: "body" }, outcome(result, { focus: bad,
    lead: visitOnly && result.outcome === "applied" ? h("p", { class: "small" }, "Recorded.") : null })),   // a visit step
    h("button", { class: "close", "aria-label": "Dismiss", on: { click: () => banner(null) } }, "Dismiss"));
  b.hidden = false;
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function act(name, params, body) {
  for (const d of document.querySelectorAll("dialog[open]")) { d.close(); d.remove(); }
  try {
    const r = await call(name, params, body);
    banner(r);
  } catch (e) {
    banner({ outcome: e.code === "refused" ? "refused" : "error", summary: "", reasons: [e.message], next: e.next });
  }
  await refreshMe();
  route();
}

// --- the frame --------------------------------------------------------------------------------------------------

async function refreshMe() {
  ME = await call("me");
  document.getElementById("realm").textContent = ME.realm + " · revision " + ME.revision;
  // Daily work first; the sign-in service and the API page under More (desk-upgrade.md, shell). A count is part of the
  // link's name: "Approvals, 2 waiting for your key".
  const tabs = [["#/", "Home"], ["#/changes", "Approvals", ME.waiting_for_me, "waiting for your key"], ["#/groups", "Groups"],
    ME.viewer || ME.root || (ME.manages || []).length ? ["#/people", "People"] : null, ["#/delegations", "Delegations"],
    ["#/visits", "Visits", ME.guests_waiting, "guests waiting for you"]].filter(Boolean);
  const more = [["#/keys", "Your hardware key"], ["#/secrets", "Secrets for you"], ["#/edges", "Edges"],
    ["#/broker", "Sign-in service"], ["#/api", "API"]];
  const item = ([href, text, n, what]) => h("a", { href }, text, n ? [h("span", { class: "count", "aria-hidden": "true" }, n),
    h("span", { class: "vh" }, ", " + n + " " + what)] : null);
  const moreMenu = h("details", { class: "more" }, h("summary", {}, "More"), h("div", { class: "menu" }, more.map(item)));
  moreMenu.addEventListener("click", ev => { if (ev.target.closest("a")) moreMenu.open = false; });
  moreMenu.addEventListener("keydown", ev => { if (ev.key === "Escape" && moreMenu.open) { moreMenu.open = false; moreMenu.querySelector("summary").focus(); } });
  const menuBtn = h("button", { type: "button", class: "menubtn", "aria-haspopup": "dialog" }, "Menu");
  menuBtn.addEventListener("click", () => {
    const close = h("button", { type: "button", class: "ghost sm" }, "Close");
    const dlg = h("dialog", { class: "navmenu", "aria-label": "Sections" }, h("div", { class: "taskhead" }, h("b", {}, "KeyClerk"), close),
      h("nav", { "aria-label": "Sections" }, [...tabs, ...more].map(item)));
    const done = () => { dlg.close(); dlg.remove(); menuBtn.focus(); };
    close.addEventListener("click", done);
    dlg.addEventListener("click", ev => { if (ev.target.closest("a")) done(); });
    dlg.addEventListener("cancel", ev => { ev.preventDefault(); done(); });
    document.body.appendChild(dlg);
    dlg.showModal();
    const here = dlg.querySelector("a[aria-current]") || dlg.querySelector("a");
    if (here) here.focus();
    refreshNav();
  });
  fill(document.getElementById("nav"), ...tabs.map(item), moreMenu);
  const old = document.querySelector("header .menubtn");
  if (old) old.remove();
  document.getElementById("whoami").insertAdjacentElement("beforebegin", menuBtn);
  refreshNav();
  const name = ME.person || ME.name || "signed in";
  fill(document.getElementById("whoami"), ...present([
    h("span", { class: "avatar", "aria-hidden": "true" }, name.slice(0, 1)),
    h("span", { class: "name" }, name),
    ME.root ? h("span", { class: "role" }, "root") : ME.viewer ? h("span", { class: "role" }, "viewer") : null,
    h("a", { href: "/logout" }, "Sign out")]));
}

// --- my desk ----------------------------------------------------------------------------------------------------

async function viewDesk() {
  const changes = await call("changes");
  const mine = changes.pending.filter(c => c.can_approve);
  const role = ME.root ? "You hold the root trust role: you manage every group and delegate from the top."
    : ME.delegations.length ? "What you may do comes from the delegations you hold, each a chain back to the root."
      : "You hold no delegation: you see your own access, and approve changes where your key counts.";
  // What needs you first (desk-upgrade.md, home): what waits for your key, what you proposed, what ends soon.
  const proposed = changes.pending.filter(c => ME.anchor && c.actor === ME.anchor && !c.expired);
  const soon = new Date(Date.now() + 14 * 86400000).toISOString();
  const ending = ME.delegations.filter(d => d.end && d.end < soon && d.status === "active");
  const need = (n, label, href, sample) => n ? h("div", { class: "need" }, h("a", { href, class: "needlink" }, label + " (" + n + ")"),
    sample ? h("span", { class: "muted small" }, sample) : null) : null;
  const needs = [
    need(mine.length, "Waiting for your key", "#/changes", mine[0] && mine[0].summary + (mine[0].actor_name ? ", by " + mine[0].actor_name : "")),
    need(proposed.length, "Your proposals waiting", "#/changes/mine", proposed[0] && proposed[0].summary),
    need(ending.length, "Your delegations ending within 14 days", "#/delegations", ending[0] && ending[0].group + " on " + day(ending[0].end)),
  ].filter(Boolean);
  return setMain(
    pageHead("Hello " + (ME.person || ME.name || ""), role),
    section("Needs you", needs.length ? h("div", { class: "card needs" }, needs) : empty("Nothing needs you now.")),
    h("div", { class: "cols" },
      section("Groups you manage (" + ME.manages.length + ")", ME.manages.length ? h("div", { class: "card tree" }, ME.manages.map(m =>
        h("div", { class: "row" }, groupLink(m.group), h("span", { class: "right" }, powers(m.powers)))))
        : empty("You manage no group. Someone who manages one can delegate to you.")),
      section("Your rights, and where they come from (" + ME.entitlements.length + ")", ME.entitlements.length ? h("div", { class: "card tree" }, ME.entitlements.map(e =>
        h("div", { class: "row" }, h("code", {}, e.entitlement),
          h("span", { class: "right small muted" }, "through", h("span", { class: "inline-list" }, e.via.map(groupLink))))))
        : empty("No rights come to you through groups."))),
    ME.delegations.length ? section("Delegations you hold (" + ME.delegations.length + ")", delegationList(ME.delegations)) : null);
}

// --- delegations ------------------------------------------------------------------------------------------------

function delegationList(list) {
  return h("div", { class: "list" }, list.map(d => h("div", { class: "card item" },
    h("div", { class: "main" },
      h("h3", {}, who(d.delegate, d.delegate_name), h("span", { class: "muted" }, "manages"), groupLink(d.group),
        grantStatus(d.status)),
      h("div", { class: "meta" },
        h("span", {}, powers(d.powers)), h("span", {}, "up to ", riskTag(d.max_risk)),
        h("span", {}, "until ", when(d.end), " (" + rel(d.end) + ")"),
        d.grace_until ? h("span", { class: "warn" }, "grace until ", when(d.grace_until)) : null,
        h("span", {}, "given by ", who(d.by, d.by_name))),
      h("div", { class: "meta" }, h("span", { class: "chain", title: "the chain back to the root" }, d.chain.join("  <  ")))),
    d.can_end ? h("div", { class: "side" }, endDelegation(d)) : null)));
}

function endDelegation(d) {
  const n = d.impact.delegations.length, m = d.impact.memberships.length;
  const b = h("button", { type: "button", class: "quiet sm" }, "End...");
  b.addEventListener("click", () => {
    const mode = h("select", {}, h("option", { value: "retire" }, "retire (orderly, with a grace period)"),
      h("option", { value: "revoke" }, "revoke (for cause: voids what was done since)"));
    const reason = h("input", { maxlength: 300, placeholder: "kept in the records" });
    const impact = n || m ? h("p", { class: "small warn" }, n + " delegation" + (n === 1 ? "" : "s") + " below it and " + m + " membership"
      + (m === 1 ? "" : "s") + " made under it end too.") : null;
    taskDialog("End " + (d.delegate_name || d.delegate) + "'s delegation over " + d.group + "?", h("div", {}, impact,
      reviewed([field("How", mode), field("Why", reason, "required; kept in the records", true)],
        () => reason.value.trim().length < 3 ? { error: "Say why (at least 3 characters)", field: reason }
          : { action: "end_delegation", delegation_id: d.delegation_id, mode: mode.value, reason: reason.value.trim() })), b);
  });
  return b;
}

async function viewDelegations() {
  const list = await call("delegations");
  return setMain(pageHead("Delegations", "Each delegation narrows the one above it: powers, part of the tree, class, how long memberships "
    + "may last, how often it may be passed on, and time. Retiring is orderly; revoking is for cause and voids what was done since."),
  list.length ? h("p", {}, link("#/tree", "Show as a tree", "button sm")) : null,
  list.length ? delegationList(list) : empty("No delegation you may see."));
}

// --- groups -----------------------------------------------------------------------------------------------------

async function viewGroups() {
  const groups = await call("groups");
  return setMain(pageHead("Groups", "The tree of groups you manage or belong to. A group's class is fixed when it is made; nesting it in "
    + "a group of a higher class raises it."),
  h("div", { class: "card tree" }, groups.map(g => h("div", { class: "row d" + Math.min(g.depth, 6) + (g.members || g.my_powers.length ? "" : " dim") },
    link("#/group/" + encodeURIComponent(g.group_id), g.group_id, "name"),
    riskTag(g.effective_risk, g.effective_risk !== g.max_risk ? "made " + g.max_risk + ", raised by nesting" : null),
    g.description ? h("span", { class: "muted small" }, g.description) : null,
    h("span", { class: "right" }, g.members ? h("span", { class: "muted small" }, g.members + " member" + (g.members === 1 ? "" : "s")) : null,
      g.my_powers.length ? powers(g.my_powers) : null)))));
}

// "office-staff -> site-heverlee -> M-1 -> under D-2 < root" becomes "through site-heverlee" (or "directly").
function how(path, gid) {
  const groups = path.filter((x, i) => i > 0 && !/^[A-Z]-|^under /.test(x));
  const ids = path.filter(x => /^[A-Z]-|^under /.test(x)).join(" ");
  return h("span", { class: "how", title: path.join("  >  ") },
    groups.length ? ["through ", groups.map((g, i) => [i ? " and " : "", groupLink(g)])] : "directly", " ", h("span", { class: "id" }, ids));
}

async function viewGroup(gid) {
  const [g, ppl, groups] = await Promise.all([call("group", { group_id: gid }),
    (ME.manages || []).length || ME.root || ME.viewer ? call("people") : Promise.resolve([]), call("groups")]);
  const crumbs = h("div", { class: "crumbs" }, link("#/groups", "Groups"),
    [...g.ancestors].reverse().map(a => [h("span", { class: "sep" }, "/"), groupLink(a)]), h("span", { class: "sep" }, "/"), h("span", {}, g.group_id));
  const parts = [pageHead(h("span", {}, g.group_id), g.description, crumbs,
    h("div", { class: "facts" },
      h("span", {}, h("b", {}, "class"), riskTag(g.effective_risk)),
      h("span", {}, h("b", {}, "members"), g.effective_members.length),
      h("span", {}, h("b", {}, "carries"), g.carries.length ? g.carries.map(c => pill(c, "", "a right members get")) : "nothing"),
      g.children.length ? h("span", {}, h("b", {}, "subgroups"), g.children.map((c, i) => [i ? ", " : "", groupLink(c)])) : null,
      g.included_by.length ? h("span", {}, h("b", {}, "nested in"), g.included_by.map((c, i) => [i ? ", " : "", groupLink(c)])) : null,
      g.my_powers.length ? h("span", {}, h("b", {}, "you may"), powers(g.my_powers)) : null))];
  if (g.my_powers.length) parts[0].querySelector(".titlerow").appendChild(headActions(actionPanel(g, ppl.filter(p => p.kind === "tenant"), groups)));
  parts.push(section("Members (" + g.effective_members.length + ")",
    h("p", { class: "muted small" }, "Everyone who is in this group, directly or through a nested group: this is what the sign-in service holds."),
    g.effective_members.length ? table(["person", "how", "in the sign-in service"], g.effective_members.map(m =>
      [personLink(m.anchor, m.name), m.paths.map(p => h("div", {}, how(p, g.group_id))),
        m.in_broker === null ? h("span", { class: "muted" }, "unknown") : m.in_broker ? pill("yes", "ok") : pill("within a minute", "warn")]))
      : empty("Nobody is in this group yet.")));
  parts.push(section("Memberships made here",
    g.memberships.length ? table(["member", "added by", "from", "until", "state", ""], g.memberships.map(m =>
      [m.kind === "group" ? h("span", {}, "the group ", groupLink(m.member))
        : m.kind === "rule" ? h("span", { title: "everyone the rule on this attribute matches" }, "people whose ", h("code", {}, m.member), " matches a rule")
          : who(m.member, m.member_name),
        h("span", { title: "under " + m.chain.join(" < ") }, who(m.by, m.by_name)), when(m.start),
        h("span", {}, when(m.end), h("div", { class: "tiny muted" }, rel(m.end))), grantStatus(m.status),
        m.can_end ? endMembership(m) : null])) : empty("No membership was made here.")));
  parts.push(section("Who manages it", table(["person", "through", "over", "powers", "state"], g.managers.map(m =>
    [who(m.anchor, m.name), m.delegation_id === "root" ? "the root" : idTag(m.delegation_id),
      m.over === "everything" ? "everything" : groupLink(m.over), powers(m.powers), grantStatus(m.status)]))));
  if (g.effective_members.some(m => m.in_broker === false)) {
    const here = location.hash;                                   // refresh while the reconciler catches up
    const busy = () => document.querySelector("dialog[open]") || (document.activeElement && document.activeElement.matches("input, select, textarea"));
    const again = () => { if (location.hash !== here) return; if (busy() || !document.getElementById("banner").hidden) setTimeout(again, 5000); else route(); };
    setTimeout(again, 10000);
  }
  return setMain(...parts);
}

function endMembership(m) {
  const b = h("button", { type: "button", class: "quiet sm" }, "End...");
  b.addEventListener("click", () => {
    const reason = h("input", { maxlength: 300, placeholder: "kept in the records" });
    taskDialog("End " + (m.member_name || m.member) + "'s membership?",
      reviewed([field("Why", reason, "required; kept in the records", true)],
        () => reason.value.trim().length < 3 ? { error: "Say why (at least 3 characters)", field: reason }
          : { action: "end_membership", membership_id: m.membership_id, reason: reason.value.trim() }), b);
  });
  return b;
}

// One task at a time, in a dialog, and reviewed before it is made: choose, check (the engine's answer comes first),
// confirm. Esc or Close returns focus to the button that opened it (desk-upgrade.md, slice 4).
function taskDialog(title, content, opener) {
  const close = h("button", { type: "button", class: "ghost sm close", "aria-label": "Close" }, "Close");
  const dlg = h("dialog", { class: "task", "aria-labelledby": "task-title" },
    h("div", { class: "taskhead" }, h("h2", { id: "task-title" }, title), close), content);
  const done = () => { dlg.close(); dlg.remove(); if (opener && document.contains(opener)) opener.focus(); };
  close.addEventListener("click", done);
  dlg.addEventListener("cancel", ev => { ev.preventDefault(); done(); });
  document.body.appendChild(dlg);
  dlg.showModal();
  const first = dlg.querySelector("input, select, textarea, button:not(.close)");
  if (first) first.focus();
  return done;
}

function actionPanel(g, tenants, groups) {
  const can = p => g.my_powers.includes(p);
  const tasks = [
    can("members") ? ["Add a person", "Add a person to " + g.group_id, () => addMemberForm(g, tenants)] : null,
    can("includes") ? ["Nest a group", "Nest a group in " + g.group_id, () => includeForm(g, groups)] : null,
    can("subgroups") ? ["New subgroup", "A new group under " + g.group_id, () => subgroupForm(g)] : null,
    can("delegate") ? ["Delegate", "Delegate over " + g.group_id, () => delegateForm(g, tenants)] : null,
  ].filter(Boolean);
  return h("div", { class: "verbs" }, tasks.map(([label, title, make], i) => {
    const b = h("button", { type: "button", class: i ? "secondary" : null }, label);
    b.addEventListener("click", () => taskDialog(title, make(), b));
    return b;
  }));
}

// The form, then the review of what would happen, then the confirmation.
// A form's own check before the engine's: toBody returns the request, or { error, field } for what is missing. The
// error summary takes focus and links to the field (GOV.UK error summary); the field says the same.
function formError(form, out, err) {
  for (const x of form.querySelectorAll("[aria-invalid]")) x.removeAttribute("aria-invalid");
  for (const x of form.querySelectorAll(".fielderror")) x.remove();
  if (!err) return;
  const target = err.field && (err.field.matches("input, select, textarea") ? err.field : err.field.querySelector("input, select, textarea"));
  if (target) {
    target.setAttribute("aria-invalid", "true");
    if (!target.id) target.id = "f" + Math.random().toString(36).slice(2, 9);
    const msg = h("span", { class: "fielderror", id: target.id + "-err" }, "Error: " + err.error);
    target.setAttribute("aria-describedby", [target.getAttribute("aria-describedby"), msg.id].filter(Boolean).join(" "));
    target.insertAdjacentElement("afterend", msg);
  }
  const head = h("h3", { tabindex: "-1" }, "There is a problem");
  fill(out, h("div", { class: "errorsummary", role: "alert" }, head,
    h("ul", {}, h("li", {}, target ? h("a", { href: "#" + target.id, on: { click: ev => { ev.preventDefault(); target.focus(); } } }, err.error)
      : err.error))));
  head.focus();
  if (!document.title.startsWith("Error: ")) document.title = "Error: " + document.title;
}

function reviewed(fields, toBody, explain) {
  const out = h("div", {});
  const form = h("form", { novalidate: true, on: { submit: async ev => {
    ev.preventDefault();
    const body = toBody();
    if (!body || body.error) { formError(form, out, body || { error: "Fill in what is asked." }); return; }
    formError(form, out, null);
    document.title = document.title.replace(/^Error: /, "");
    fill(out, h("p", { class: "muted small" }, "Asking the engine..."));
    try {
      const p = await call("preview", {}, body);
      fill(out, outcome(p, { preview: true, focus: true,
        actions: p.outcome === "refused" ? null : h("div", { class: "actions" },
          h("button", { type: "button", on: { click: () => act("propose", {}, body) } },
            p.outcome === "applied" ? (p.summary ? p.summary.charAt(0).toUpperCase() + p.summary.slice(1) : "Confirm")
              : onlyOwnSignature(p) ? "Propose, then sign it" : "Propose: ask for a key"),
          h("button", { type: "button", class: "ghost", on: { click: () => fill(out) } }, "Change something")) }));
    } catch (e) {
      fill(out, outcome({ outcome: "refused", reasons: [e.message], next: e.next }, { preview: true, focus: true,
        title: "This cannot be done" }));
    }
  } } }, explain ? h("p", { class: "muted small" }, explain) : null, h("div", { class: "fields" }, fields),
    h("div", { class: "actions" }, h("button", { type: "submit" }, "Review")));
  return h("div", {}, form, out);
}

let FIELD_N = 0;
function field(label, input, hint, wide) {
  const control = input.matches && input.matches("input, select, textarea") ? input : input.querySelector && input.querySelector("input, select, textarea");
  const hintEl = typeof hint === "string" ? h("span", { class: "hint" }, hint) : hint || null;
  if (control && hintEl) {
    hintEl.id = hintEl.id || "hint" + (++FIELD_N);
    control.setAttribute("aria-describedby", hintEl.id);
  }
  return h("label", { class: "field" + (wide ? " wide" : "") }, label, input, hintEl);
}

// A person picker (WAI-ARIA APG combobox, list autocomplete): type to filter, arrows to move, Enter to choose.
// The element carries .value (the chosen anchor) like the select it replaces.
function personSelect(list, exclude) {
  const people = [...list].filter(p => p.anchor !== exclude).sort((a, b) => a.person.localeCompare(b.person));
  const id = "pp" + (++FIELD_N);
  const input = h("input", { type: "text", role: "combobox", "aria-autocomplete": "list", "aria-expanded": "false",
    "aria-controls": id + "-list", autocomplete: "off", placeholder: "type a name" });
  const listbox = h("ul", { role: "listbox", id: id + "-list", class: "options", hidden: true });
  const wrap = h("span", { class: "combo" }, input, listbox);
  let chosen = "", shown = [], active = -1;
  Object.defineProperty(wrap, "value", { get: () => chosen });
  const render = () => {
    const q = input.value.trim().toLowerCase();
    shown = people.filter(p => !q || p.person.toLowerCase().includes(q) || p.anchor.toLowerCase().includes(q)).slice(0, 12);
    active = Math.min(active, shown.length - 1);
    fill(listbox, shown.length ? shown.map((p, i) => h("li", { role: "option", id: id + "-o" + i, "aria-selected": i === active ? "true" : "false",
      class: i === active ? "on" : null, on: { mousedown: ev => { ev.preventDefault(); pick(i); } } }, p.person,
      h("span", { class: "muted small" }, " " + p.anchor))) : h("li", { class: "muted small" }, "nobody by that name"));
    listbox.hidden = false;
    input.setAttribute("aria-expanded", "true");
    if (active >= 0) input.setAttribute("aria-activedescendant", id + "-o" + active); else input.removeAttribute("aria-activedescendant");
  };
  const hide = () => { listbox.hidden = true; input.setAttribute("aria-expanded", "false"); input.removeAttribute("aria-activedescendant"); };
  const pick = i => { const p = shown[i]; if (!p) return; chosen = p.anchor; input.value = p.person; hide(); };
  input.addEventListener("input", () => { chosen = ""; active = 0; render(); });
  input.addEventListener("click", render);                       // not on focus: an open list must not cover the form
  input.addEventListener("blur", () => setTimeout(hide, 100));
  input.addEventListener("keydown", ev => {
    if (ev.key === "ArrowDown") { ev.preventDefault(); if (listbox.hidden) { active = 0; render(); return; }
      active = Math.min(active + 1, shown.length - 1); render(); }
    else if (ev.key === "ArrowUp") { ev.preventDefault(); active = Math.max(active - 1, 0); render(); }
    else if (ev.key === "Enter" && !listbox.hidden && active >= 0) { ev.preventDefault(); pick(active); }
    else if (ev.key === "Escape" && !listbox.hidden) { ev.preventDefault(); ev.stopPropagation(); hide(); }
  });
  return wrap;
}

function daysInput(value) {
  return h("input", { type: "number", min: 1, max: 3650, value, inputmode: "numeric" });
}

// "For how many days", with the end date it gives shown as you type.
function daysHint(input, text) {
  const out = h("span", { class: "hint", "aria-live": "polite" });
  const show = () => {
    const n = Number(input.value);
    const end = n >= 1 ? new Date(Date.now() + n * 86400000) : null;
    fill(out, end ? "ends " + end.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "",
      text ? (end ? "; " : "") + text : "");
  };
  input.addEventListener("input", show);
  show();
  return out;
}

function addMemberForm(g, tenants) {
  const sel = personSelect(tenants, ME.anchor), days = daysInput(30);
  return reviewed([field("Person", sel), field("For how many days", days, daysHint(days, "it ends by itself; your delegation sets the maximum"))],
    () => !sel.value ? { error: "Choose a person from the list", field: sel }
      : { action: "add_member", group: g.group_id, anchor: sel.value, days: Number(days.value) },
    "Add someone to " + g.group_id + ". They get what the group carries.");
}

function includeForm(g, groups) {
  const sel = h("select", { required: true }, h("option", { value: "" }, "choose a group"),
    groups.filter(x => x.group_id !== g.group_id).map(x => h("option", { value: x.group_id }, x.group_id + " (" + x.effective_risk + ")")));
  const days = daysInput(30);
  return reviewed([field("Group to nest", sel), field("For how many days", days, daysHint(days))],
    () => !sel.value ? { error: "Choose a group to nest", field: sel }
      : { action: "include_group", group: g.group_id, include: sel.value, days: Number(days.value) },
    "Everyone in the nested group becomes a member of " + g.group_id + ". Its manager may have to agree.");
}

function subgroupForm(g) {
  const id = h("input", { required: true, pattern: "[a-z0-9][a-z0-9-]{1,62}", placeholder: "for example helpdesk", autocomplete: "off" });
  const risk = h("select", {}, ["low", "elevated", "privileged"].map(r => h("option", { value: r }, r)));
  const desc = h("input", { placeholder: "what it is for", maxlength: 300 });
  return reviewed([field("Name", id, "lower case letters, digits and dashes"), field("Class", risk, "fixed once it is made"),
    field("What it is for", desc, null, true)],
  () => !/^[a-z0-9][a-z0-9-]{1,62}$/.test(id.value) ? { error: "Give a name of lower case letters, digits and dashes (2 to 63)", field: id }
    : Object.assign({ action: "create_group", parent: g.group_id, group_id: id.value, max_risk: risk.value },
    desc.value ? { description: desc.value } : {}),
  "A new group under " + g.group_id + ".");
}

function delegateForm(g, tenants) {
  const sel = personSelect(tenants, ME.anchor);
  const boxes = g.my_powers.map(p => h("input", { type: "checkbox", value: p, checked: p === "members" }));
  const risk = h("select", {}, ["low", "elevated", "privileged"].map(r => h("option", { value: r }, r)));
  const days = daysInput(90);
  return reviewed([field("Deputy", sel), field("Up to class", risk), field("For how many days", days, daysHint(days)),
    field("Powers they get", h("span", { class: "checks" }, boxes.map(b => h("label", {}, b, POWER_WORDS[b.value] || b.value))),
      "never more than you hold yourself", true)],
  () => !sel.value ? { error: "Choose a deputy from the list", field: sel }
    : !boxes.some(b => b.checked) ? { error: "Give at least one power", field: boxes[0] }
    : { action: "delegate", group: g.group_id, delegate: sel.value,
    powers: boxes.filter(b => b.checked).map(b => b.value), max_risk: risk.value, days: Number(days.value) },
  "Hand on part of what you hold over " + g.group_id + " and the groups below it.");
}

// --- changes ----------------------------------------------------------------------------------------------------

function pendingList(list) {
  return h("div", { class: "list" }, list.map(c => h("div", { class: "card item" },
    h("div", { class: "main" },
      h("h3", {}, link("#/change/" + encodeURIComponent(c.change_id), c.summary), " ", c.expired ? status("expired") : status("pending")),
      h("div", { class: "meta" }, h("span", {}, "proposed by ", who(c.actor, c.actor_name)), moment(c.at),
        idTag(c.change_id)),
      h("div", { class: "small" }, (c.needs && c.needs.length ? c.needs : c.reasons.map(plain)).map(n => h("div", {}, n))),
      c.approvals && c.approvals.length ? h("div", { class: "meta" }, "Keys given: ", c.approvals.join(", ")) : null,
      c.waiting_for && c.waiting_for.length ? h("div", { class: "who" }, h("span", { class: "muted small" }, "Who can add the key: "), people(c.waiting_for, 6))
        : !c.expired ? h("div", { class: "small warn" }, "Ask the root: they can find who adds this key.") : null),
    h("div", { class: "side" },
      c.can_approve ? link("#/change/" + encodeURIComponent(c.change_id), "Review and approve", "button") : null,
      !c.can_approve ? link("#/change/" + encodeURIComponent(c.change_id), "Open", "button ghost") : null,
      c.can_withdraw ? h("button", { class: "ghost", on: { click: () => withdraw(c) } }, "Withdraw") : null))));
}

// A question before an action that cannot be undone (desk-upgrade.md, dialog): native <dialog>, Cancel focused first.
function confirmDialog(title, lines, verb) {
  return new Promise(resolve => {
    const no = h("button", { type: "button", class: "ghost" }, "Cancel");
    const yes = h("button", { type: "button", class: "danger" }, verb);
    const dlg = h("dialog", { class: "confirm", "aria-labelledby": "confirm-title" },
      h("h2", { id: "confirm-title" }, title), h("ul", {}, lines.map(x => h("li", {}, x))), h("div", { class: "actions" }, no, yes));
    const done = v => { dlg.close(); dlg.remove(); resolve(v); };
    no.addEventListener("click", () => done(false));
    yes.addEventListener("click", () => done(true));
    dlg.addEventListener("cancel", ev => { ev.preventDefault(); done(false); });       // Esc
    document.body.appendChild(dlg);
    dlg.showModal();
    no.focus();
  });
}

async function withdraw(c) {
  if (await confirmDialog("Withdraw this change?", [c.summary, "The keys given so far are dropped.",
    "To make it again, propose it again."], "Withdraw")) act("withdraw", { change_id: c.change_id });
}

// One waiting change, in full, before anyone signs it (decision 0006: the broker's sign-in page does not show it).
const LINE_WORDS = { membership: "joins", delegation: "is delegated", "new group": "new group", "named approver": "named approver", end: "ends" };
async function viewChange(cid) {
  const all = await call("changes");
  const c = all.pending.find(x => x.change_id === cid);
  const crumbs = h("div", { class: "crumbs" }, link("#/changes", "Approvals"), " / ", cid);
  if (!c) {
    const done = all.log.find(e => e.change_id === cid);
    return setMain(pageHead("This change no longer waits", done ? "It was " + (STATUS[done.outcome] || [done.outcome])[0].toLowerCase() + "."
      : "It was settled, withdrawn, or it is not yours to see.", crumbs), link("#/changes", "Back to Approvals", "button"));
  }
  const st = (c.can_approve || c.can_sign) && ME.approval_sign_in ? await call("statement", { change_id: cid }).catch(() => null) : null;
  // a high-risk change carries its proposer's own signature too (decision 0015): the same fresh sign-in, for your own change
  const signBox = c.can_sign ? h("section", { class: "section approvebox card" },
    h("h2", {}, "Sign your change"),
    h("p", {}, "This change is high risk, so it carries your own signature as well as the desk's. You sign in again with your "
      + "passkey; the sign-in page will not show the change, so check it here first."),
    st ? h("div", { class: "statement" }, h("span", { class: "muted small" }, "You sign: "), h("code", {}, st.nonce.slice(0, 12) + "...")) : null,
    h("div", { class: "actions" }, h("button", { on: { click: () => approve(cid) } }, "Sign and sign in"))) : null;
  const rows = (c.what || []).map(l => [
    h("span", {}, LINE_WORDS[l.kind] || l.kind),
    l.member ? who(l.member, l.member_name) : h("span", { class: "muted" }, l.detail || ""),
    l.group ? h("span", {}, groupLink(l.group), " ", l.risk ? riskTag(l.risk) : null) : "",
    l.start || l.end ? h("span", {}, l.start ? day(l.start) : "...", " to ", l.end ? day(l.end) : "...") : "",
    l.under ? h("span", { class: "small" }, l.under) : "",
    l.member && l.detail ? h("span", { class: "small muted" }, l.detail) : ""]);
  const approveBox = c.can_approve ? h("section", { class: "section approvebox card" },
    h("h2", {}, "Approve"),
    ME.approval_sign_in ? h("p", {}, "Approving is your own signature. You sign in again with your passkey; the sign-in page will not "
      + "show this change, so check it here first.") : h("p", {}, "Your key completes or advances this change."),
    st ? h("div", { class: "statement" }, h("span", { class: "muted small" }, "You sign: "), h("code", {}, st.nonce.slice(0, 12) + "..."),
      h("details", { class: "small" }, h("summary", {}, "Show in full"), h("p", {}, "Change ", h("code", {}, st.change_id),
        ", by ", h("code", {}, st.by), ", over records ", (st.records || []).map((r, i) => [i ? ", " : "", h("code", {}, r)])),
        h("p", {}, "Nonce ", h("code", {}, st.nonce)))) : null,
    h("div", { class: "actions" },
      h("button", { on: { click: () => approve(cid) } }, ME.approval_sign_in ? "Approve and sign in" : "Approve"),
      ME.approval_sign_in ? h("button", { class: "secondary", on: { click: () => approveOnPhone(cid) } }, "Approve on my phone") : null),
    passkeyHint()) : null;
  return setMain(pageHead(h("span", {}, c.summary, " ", c.expired ? status("expired") : status("pending")),
    h("span", {}, "Proposed by ", who(c.actor, c.actor_name), ", ", stamp(c.at), "."), crumbs,
    c.can_withdraw ? headActions(h("button", { type: "button", class: "ghost", on: { click: () => withdraw(c) } }, "Withdraw")) : null),
    section("What it changes", rows.length ? table(["", "who", "group and class", "from - until", "under", ""], rows, "What it changes")
      : empty("The desk could not describe it record by record.")),
    section("Why it waits", h("ul", {}, (c.needs && c.needs.length ? c.needs : c.reasons.map(plain)).map(n => h("li", {}, n)))),
    section("Keys", h("p", {}, c.approvals.length ? ["Given by ", (c.approval_names || []).map((n, i) => [i ? ", " : "", n || c.approvals[i]]), "."]
      : "No key given yet."), c.waiting_for && c.waiting_for.length ? h("div", { class: "who" }, h("span", { class: "muted small" },
      "Who can add the next key: "), people(c.waiting_for, 8)) : null),
    signBox, approveBox);
}

// Where approvals need proofs, approving is a fresh sign-in at the broker that signs this change (decision 0006).
async function approve(cid) {
  if (!ME.approval_sign_in) return act("approve", { change_id: cid });
  try {                                   // a POST with the CSRF token starts it; the broker's sign-in signs the change
    const r = await call("approvalsignin", { change_id: cid });
    if (/^https?:\/\//.test(r.redirect)) location.assign(r.redirect);
  } catch (e) {
    banner({ outcome: "error", summary: "", reasons: [e.message], next: e.next });
  }
}

// The same signed approval, started on a phone: a short-lived link for this approver, shown as a QR code.
async function approveOnPhone(cid) {
  const b = document.getElementById("banner");
  try {
    const l = await call("phonelink", { change_id: cid });
    b.className = "banner info";
    fill(b, h("div", { class: "body" }, h("div", { class: "title" }, "Approve on your phone"),
      h("div", {}, "Scan the code, check the change it shows, and sign in there with your passkey. The link works until ",
        stamp(l.expires_at), "."),
      h("div", { class: "phone" }, l.qr.startsWith("/approve-qr/") ? h("img", { src: l.qr, alt: "QR code of the approval link", width: 200, height: 200 }) : null,
        h("code", { class: "small" }, l.url))),
    h("button", { class: "close", "aria-label": "Dismiss", on: { click: () => banner(null) } }, "Dismiss"));
    b.hidden = false;
    window.scrollTo({ top: 0, behavior: "smooth" });
  } catch (e) {
    banner({ outcome: "error", summary: "", reasons: [e.message], next: e.next });
  }
}

// Approving asks for a passkey where the realm binds one to approvals: say where to register one.
function passkeyHint() {
  if (!ME.approval_sign_in) return null;
  const ok = /^https?:\/\/[^\s"<>]+\/account\//.test(ME.account_url || "");
  return h("p", { class: "muted small" }, "Approving is your own signature: you sign in again, with your passkey. ",
    ok ? h("a", { href: ME.account_url, rel: "noopener noreferrer" }, "Set up a passkey in your account") : null, ok ? "." : null);
}

async function viewChanges(done) {
  if (["applied", "pending", "refused"].includes(done)) {
    banner({ outcome: done, summary: "Your approval", reasons: [] });
    history.replaceState(null, "", "#/changes");
    done = undefined;
  }
  const tab = ["mine", "others", "history"].includes(done) ? done : "key";
  const c = await call("changes");
  const isMine = x => ME.anchor && x.actor === ME.anchor;
  const groups = { key: c.pending.filter(x => x.can_approve), mine: c.pending.filter(isMine),
    others: c.pending.filter(x => !x.can_approve && !isMine(x)) };
  const tabs = h("nav", { class: "subtabs", "aria-label": "Approvals" }, [["key", "Waiting for your key", groups.key.length],
    ["mine", "Your proposals", groups.mine.length], ["others", "Other changes waiting", groups.others.length], ["history", "History"]]
    .map(([k, label, n]) => h("a", { href: "#/changes/" + (k === "key" ? "" : k), class: k === tab ? "on" : null,
      "aria-current": k === tab ? "page" : null }, label, n ? h("span", { class: "count" }, n) : null)));
  const EMPTY = { key: "Nothing waits for your key.", mine: "Nothing you proposed is waiting.", others: "Nothing else waits." };
  return setMain(pageHead("Approvals", "Changes waiting for a key, and everything that happened, with the engine's answer."), tabs,
    tab !== "history" ? h("section", { class: "section" }, h("div", { class: "sectionhead" }, h("h2", { class: "vh" }, "Waiting"), passkeyHint()),
      groups[tab].length ? pendingList(groups[tab]) : empty(EMPTY[tab])) :
    historyView(c.log));
}

// The log, filtered and 50 rows at a time (desk-upgrade.md, log): an investigation starts narrow.
function historyView(log) {
  const box = h("div", {});
  const FILTERS = [["all", "All", () => true], ["mine", "Mine", e => ME.anchor && (e.actor === ME.anchor || e.approved_by === ME.anchor)],
    ["refused", "Refused", e => e.outcome === "refused"], ["waiting", "Waiting", e => e.outcome === "pending"]];
  let which = "all", limit = 50;
  const draw = () => {
    const rows = log.filter(FILTERS.find(f => f[0] === which)[2]);
    fill(box, h("div", { class: "filters", role: "group", "aria-label": "Show" }, FILTERS.map(([k, label]) =>
      h("button", { type: "button", class: "sm " + (k === which ? "" : "ghost"), "aria-pressed": k === which ? "true" : "false",
        on: { click: () => { which = k; limit = 50; draw(); } } }, label))),
    rows.length ? historyTable(rows.slice(0, limit)) : empty("Nothing to show."),
    rows.length > limit ? h("p", {}, h("button", { type: "button", class: "ghost", on: { click: () => { limit += 50; draw(); } } },
      "Show 50 more (" + (rows.length - limit) + " left)")) : null);
  };
  draw();
  return section("What happened", box);
}

function historyTable(rows) {
  return table(["when", "change", "by", "answer", ""], rows.map(e => [
      h("span", {}, stamp(e.at), h("div", { class: "tiny muted" }, rel(e.at))),
      h("span", {}, e.summary || e.action, e.reasons && e.reasons.length && e.outcome !== "applied"
        ? h("div", { class: "tiny muted" }, plain(e.reasons[0])) : null),
      e.actor ? who(e.actor, e.actor_name) : h("span", { class: "muted" }, "the desk"),
      h("span", {}, status(e.outcome), e.approved_by ? h("div", { class: "tiny muted" }, "key: ", who(e.approved_by, e.approver_name)) : null),
      h("span", { class: "id", title: "change log line " + e.seq }, "rev " + e.revision)]), "What happened");
}

// --- hardware keys, relayed secrets, edges (decision 0014) ------------------------------------------------------
// The person key comes from the passkey through PRF (personkey.js); only its public half leaves the browser.

async function viewKeys() {
  const [keys, visits] = await Promise.all([call("mykeys"), call("myvisits")]);
  const carry = async (v, btn) => {
    btn.setAttribute("aria-disabled", "true");
    try {
      const sealed = await call("carried", { lease_id: v.lease_id });
      const a = h("a", { href: "data:application/json;charset=utf-8," + encodeURIComponent(JSON.stringify(sealed)),
        download: "carried-" + v.lease_id + ".json", class: "button sm" }, "Save the carried lease");
      btn.replaceWith(a);
      a.focus();
    } catch (e) {
      banner({ outcome: "error", reasons: [e.message],
        next: e.status === 403 ? [{ why: "A carried lease is issued within 10 minutes of a fresh sign-in.", do: "Sign in again, then carry it.", who: [] }] : [] });
    }
  };
  const active = keys.filter(k => k.active);
  const ssh = h("textarea", { rows: 2, placeholder: "ssh-ed25519 AAAA... (the public key your hardware key holds, optional)" });
  const out = h("div", {});
  const go = h("button", { type: "button" }, "Register with my hardware key");
  go.addEventListener("click", async () => {
    fill(out, h("p", { class: "muted small", role: "status" }, "Touch your key and give its PIN when your browser asks..."));
    try {
      const reg = await PK.register(ME.person || ME.name || "me");
      if (!reg.user_verification) throw new Error("the key did not verify you (no PIN or biometric): not registered");
      const body = { action: "enrol_person_key", public_key: reg.public_key, credential_id: reg.credential_id,
        user_verification: true, attestation: reg.attestation };
      if (ssh.value.trim()) body.ssh_key = ssh.value.trim();
      fill(out);
      act("propose", {}, body);
    } catch (e) {
      fill(out, outcome({ outcome: "error", reasons: [e.message || String(e)] }, { title: "Not registered", focus: true }));
    }
  });
  return setMain(pageHead("Your hardware key", "Lease secrets for legacy systems reach you encrypted to a key only your hardware key "
    + "can derive (WebAuthn PRF). The desk relays them and cannot read them; a key without PRF cannot receive them."),
    section("Registered", active.length ? table(["key", "since", "SSH key"], active.map(k => [h("code", {}, k.key_id), day(k.at),
      k.ssh_key ? h("code", { class: "small" }, k.ssh_key.slice(0, 40) + "...") : h("span", { class: "muted" }, "none")]), "Registered keys")
      : empty("No hardware key registered yet.")),
    visits.length ? section("Your visit leases on edges", h("p", { class: "muted small" }, "Carry one to an edge that is cut off: save it, "
      + "take it to the site, and the edge checks it and your hardware key. ", link("/login?fresh=1", "Sign in again first", "button ghost sm")),
      table(["lease", "edge", "targets", "until", ""], visits.map(v => {
        const b = h("button", { type: "button", class: "sm" }, "Carry it");
        b.addEventListener("click", () => carry(v, b));
        return [h("code", {}, v.lease_id), v.edge, v.targets.join(", "), moment(v.until), b];
      }), "Visit leases")) : null,
    active.length ? h("p", { class: "muted small" }, "One key per person: to replace it, ask the root or the security officer to end this one first.")
      : section("Register", h("div", { class: "card panel" },
        field("SSH public key", ssh, "for visit leases on edges; your hardware key holds it", true), h("div", { class: "actions" }, go), out,
        h("p", { class: "muted small" }, "Registering waits for a second key from the security officer or a named approver."))));
}

async function viewSecrets() {
  const [items, keys] = await Promise.all([call("relay"), call("mykeys")]);
  const key = keys.find(k => k.active);
  const show = h("div", {});
  const take = async (it, btn) => {
    btn.setAttribute("aria-disabled", "true");
    try {
      const got = await call("relaytake", { relay_id: it.relay_id });
      fill(show, h("p", { class: "muted small", role: "status" }, "Touch your key to open it..."));
      const k = keys.find(x => x.key_id === got.key_id) || key;          // the key it was sent to, not just the current one
      const plain = await PK.openWithKey(k.credential_id, k.public_key, got.envelope);
      await call("relayconfirm", { relay_id: it.relay_id });             // only now may the desk forget it
      const text = new TextDecoder().decode(plain);
      const box = h("input", { type: "text", readonly: true, value: text, class: "secret", "aria-label": "the secret" });
      fill(show, h("div", { class: "outcome applied", role: "status" }, h("h3", { tabindex: "-1" }, got.envelope.context),
        h("p", { class: "small" }, "Shown once: the desk no longer holds it. Use it now; it is rotated after its first use."), box));
      box.focus(); box.select();
      route();
    } catch (e) {
      const fresh = e.status === 403;
      fill(show, outcome({ outcome: "error", reasons: [e.message || String(e)],
        next: fresh ? [{ why: "A secret is handed over within 10 minutes of a fresh sign-in at the sign-in service.", do: "Sign in again, then take it.", who: [] }] : [] },
        { title: "Not opened", focus: true }));
    }
  };
  return setMain(pageHead("Secrets for you", "Lease credentials and break-glass halves sent to your hardware key. Each is handed over "
    + "once, within 10 minutes of a fresh sign-in, and opened here with your key."),
    !key ? h("p", {}, link("#/keys", "Register your hardware key first", "button")) : h("p", {}, link("/login?fresh=1", "Sign in again first", "button ghost sm")),
    show,
    items.length ? table(["what", "from edge", "waiting since", "until", ""], items.map(it => {
      const b = h("button", { type: "button", class: "sm" }, "Take and open");
      b.addEventListener("click", () => take(it, b));
      return [it.purpose, it.edge, moment(it.created), day(it.expires), key ? b : ""];
    }), "Secrets waiting") : empty("Nothing waits for you."));
}

async function viewEdges() {
  const list = await call("edges");
  const ceilingForm = e => {
    const txt = h("textarea", { rows: 4, placeholder: '{"ceiling": {"bytes": ..., "signature": ..., "key": ..., "key_id": ...}} sealed with python -m keyclerk.edge_cli seal' });
    const b = h("button", { type: "button", class: "sm" }, "Set this ceiling");
    b.addEventListener("click", () => {
      let body;
      try { body = JSON.parse(txt.value); } catch (x) { banner({ outcome: "error", reasons: ["That is not JSON."] }); return; }
      act("setceiling", { edge_id: e.edge_id }, body);
    });
    return h("details", { class: "small" }, h("summary", {}, "Set a new ceiling (the officer)"), field("Signed ceiling", txt, null, true), b);
  };
  return setMain(pageHead("Edges", "Site appliances that enforce leases on a bastion while they may be cut off. Each pulls signed "
    + "bundles; its officer's signed ceiling bounds what they may hold."),
    list.length ? h("div", { class: "list" }, list.map(e => h("div", { class: "card item" }, h("div", { class: "main" },
      h("h3", {}, e.name || e.edge_id, " ", e.ended ? status("ended") : pill(e.profile + (e.attested ? ", attested " + e.attested : ", not attested yet"),
        e.attested === "assured" ? "ok" : "")),
      h("div", { class: "meta" }, h("span", {}, "officer ", e.officer_name || e.officer), h("span", {}, "bundle " + e.serial),
        h("span", {}, e.last_pull ? ["last pull ", moment(e.last_pull)] : "never pulled"),
        h("span", {}, e.ceiling_serial ? "ceiling " + e.ceiling_serial : h("b", { class: "warn" }, "no ceiling: it gets no leases")),
        h("span", {}, "evidence up to " + e.evidence_seq)),
      h("div", { class: "small" }, "Targets: ", e.targets.join(", ")),
      e.incidents.length ? h("div", { class: "small" }, h("b", {}, "Incidents: "), e.incidents.slice(-5).reverse().map(i =>
        h("div", {}, status(i.kind === "drift" ? "lapsed" : "revoked"), " ", i.kind.replace(/_/g, " "), i.system ? " on " + i.system : "", " ", moment(i.received)))) : null,
      e.dropped.length ? h("div", { class: "small muted" }, e.dropped.length + " lease(s) outside the ceiling were left out of the last bundle.") : null,
      ME.anchor === e.officer ? ceilingForm(e) : null,
      e.visit_leases.length ? h("div", { class: "small" }, h("b", {}, "Visit leases: "), e.visit_leases.map(v => {
        const end = h("button", { type: "button", class: "ghost sm" }, "End");
        end.addEventListener("click", async () => {
          if (await confirmDialog("End visit lease " + v.lease_id + "?", [(v.person_name || v.person) + " on " + v.targets.join(", "),
            "The edge drops it at its next bundle; a cut-off edge keeps it until its window ends."], "End it"))
            act("propose", {}, { action: "end_edge_record", id: v.lease_id, reason: "ended at the desk" });
        });
        return h("div", {}, v.person_name || v.person, " on ", v.targets.join(", "), " until ", day(v.until), " ", e.may_close ? end : null);
      })) : null,
      e.may_close ? visitForm(e) : null,
      e.unlock_approver ? unlockForm(e) : null,
      e.may_close && e.incidents.some(i => !i.closed) ? h("details", { class: "small" }, h("summary", {}, "Close incidents"),
        e.incidents.filter(i => !i.closed).map(i => {
          const b = h("button", { type: "button", class: "ghost sm" }, "Close");
          b.addEventListener("click", () => act("closeincident", { edge_id: e.edge_id, incident_id: i.incident_id }, { note: "closed at the desk" }));
          return h("div", {}, i.kind.replace(/_/g, " "), " ", moment(i.received), " ", b);
        })) : null)))) : empty("No edge you may see."),
    ME.root || list.some(e => e.may_close) ? section("Enrol or rotate an edge", preparedForm()) : null);
}

function visitForm(e) {
  const person = h("input", { placeholder: "idp:...", autocomplete: "off" });
  const ssh = h("input", { placeholder: "ssh-ed25519 AAAA... (their registered key)" });
  const hours = daysInput(24);
  const targets = h("input", { value: e.targets[0] || "" });
  return h("details", { class: "small" }, h("summary", {}, "Grant a visit lease"),
    reviewed([field("Person", person, "their anchor"), field("SSH key", ssh, "the one registered with their hardware key", true),
      field("Targets", targets, "comma separated"), field("Hours", hours, "at most edge.rego's window and the ceiling")],
    () => !person.value ? { error: "Name the person", field: person } : !ssh.value ? { error: "Give their SSH key", field: ssh }
      : { action: "grant_visit_lease", edge: e.edge_id, person: person.value.trim(), ssh_key: ssh.value.trim(),
        targets: targets.value.split(",").map(s => s.trim()).filter(Boolean), hours: Number(hours.value) },
    "Waits for a second key from the security officer or a named approver."));
}

function unlockForm(e) {
  const f = { person: h("input", { placeholder: "idp:..." }), target: h("input", { value: e.targets[0] || "" }),
    key_fingerprint: h("input", { placeholder: "SHA256:... as the edge shows it" }), nonce: h("input", { placeholder: "as the edge shows it" }),
    minutes: h("input", { type: "number", min: 1, max: 60, value: 30 }) };
  const out = h("div", {});
  const b = h("button", { type: "button" }, "Read the unlock code");
  b.addEventListener("click", async () => {
    try {
      const r = await call("unlock", { edge_id: e.edge_id }, { person: f.person.value.trim(), target: f.target.value.trim(),
        key_fingerprint: f.key_fingerprint.value.trim(), nonce: f.nonce.value.trim(), minutes: Number(f.minutes.value) });
      fill(out, h("div", { class: "outcome applied", role: "status" }, h("h3", { tabindex: "-1" }, h("code", { class: "secret" }, r.code)),
        h("p", { class: "small" }, "Call the person back on their registered number and read it out. It unlocks that key on this edge for "
          + r.minutes + " minutes.")));
    } catch (x) {
      fill(out, outcome({ outcome: "refused", reasons: [x.message] }, { title: "No code", focus: true }));
    }
  });
  return h("details", { class: "small" }, h("summary", {}, "Phoned unlock"),
    h("p", { class: "muted small" }, "You are a second person: never read a code for yourself. Copy what the edge shows."),
    field("Person", f.person), field("Target", f.target), field("Key fingerprint", f.key_fingerprint, null, true),
    field("Nonce", f.nonce), field("Minutes", f.minutes), b, out);
}

function preparedForm() {
  const txt = h("textarea", { rows: 6, placeholder: '{"action": "enrol_edge", ...} or {"action": "rotate_edge", ...}, prepared with python -m keyclerk.edge_cli' });
  return h("div", { class: "card panel" }, h("p", { class: "muted small" }, "Enrolling and rotating need the edge's and the officer's signatures, "
    + "so they are prepared with the command-line tool (docs/keyclerk-edge-interface.md) and pasted here."),
  reviewed([field("Prepared change", txt, null, true)], () => {
    try { const b = JSON.parse(txt.value); return ["enrol_edge", "rotate_edge"].includes(b.action) ? b : { error: "enrol_edge or rotate_edge only", field: txt }; }
    catch (x) { return { error: "That is not JSON", field: txt }; }
  }));
}

// --- people -----------------------------------------------------------------------------------------------------

async function viewPeople() {
  const ppl = await call("people");
  return setMain(pageHead("People", "Everyone in the records. Open a graph to see how a person is connected, now or at another moment."),
    table(["person", "kind", "anchor", ""], [...ppl]
    .sort((a, b) => a.person.localeCompare(b.person)).map(p =>
      [personLink(p.anchor, p.person), pill(p.kind, p.kind === "tenant" ? "" : "key"), h("code", {}, p.anchor),
        link(graphHref(p.anchor), "graph", "button sm ghost")])));
}

async function viewPerson(anchor) {
  const p = await call("person", { anchor });
  return setMain(pageHead(h("span", {}, p.person, " ", pill(p.kind)), null, h("p", { class: "muted" }, h("code", {}, p.anchor),
    " ", link(graphHref(p.anchor), "Show as a graph", "button sm"))),
    h("div", { class: "cols" },
      section("Groups, and how", p.groups.length ? table(["group", "how"], p.groups.map(g => [groupLink(g.group),
        g.paths.map(x => h("div", {}, how(x, g.group)))])) : empty("In no group.")),
      section("Rights", p.entitlements.length ? table(["right", "through"], p.entitlements.map(e =>
        [h("code", {}, e.entitlement), e.via.map((g, i) => [i ? ", " : "", groupLink(g)])])) : empty("No rights through groups."))),
    p.delegations.length ? section("Delegations held", delegationList(p.delegations)) : null);
}

// --- person graph (decision 0009) -------------------------------------------------------------------------------
// One person at a moment: their accounts by identity source, groups, delegations, places and the people around them,
// as far as the desk's view policy lets you see. The library (Cytoscape.js, MIT, vendored) loads only on this page.

let CY_LOADING = null;
function loadGraphLibrary() {
  if (window.cytoscape) return Promise.resolve();
  if (!CY_LOADING) CY_LOADING = new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "/vendor/cytoscape.min.js";
    s.onload = resolve;
    s.onerror = () => { CY_LOADING = null; reject(new Error("The graph library did not load; the table below shows the same.")); };
    document.head.appendChild(s);
  });
  return CY_LOADING;
}

const graphHref = (anchor, at) => "#/graph/" + encodeURIComponent(anchor) + (at ? "?at=" + encodeURIComponent(at) : "");
const tok = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const EDGE_WORDS = { account: "signs in as", member: "is in", added: "added to", approved: "approved for", manages: "manages",
  delegated: "delegated to", approver: "appointed approver", steward: "steward of", deputy: "deputy of",
  front_office: "front office of", lease: "may visit", sponsor: "sponsors", within: "is in", owns: "owns", directs: "directs" };
const NODE_WORDS = { subject: "this person", account: "account", person: "person", group: "group", scope: "part of the tree", place: "place" };

function localInput(iso) {             // an ISO moment as the value of a datetime-local input, in local time
  const d = new Date(iso), p = n => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

function windowText(e) {
  if (!e.from && !e.to) return "";
  return [e.from ? day(e.from) : "...", e.to ? day(e.to) : "..."].join(" to ");
}

// Back and forward in time: the moment shown, the previous and next change, and any moment you pick.
function timeBar(at, marks, isNow, go) {
  const prev = marks.before[marks.before.length - 1], next = marks.after[0];
  const moment = h("input", { type: "datetime-local", value: localInput(at), "aria-label": "Moment to show" });
  return h("div", { class: "timebar card" },
    h("div", { class: "when" }, h("b", {}, isNow ? "Now" : stamp(at)), h("span", { class: "muted small" }, isNow ? stamp(at) : rel(at))),
    h("div", { class: "steps" },
      h("button", { class: "sm", disabled: !prev, title: prev ? stamp(prev) : "nothing changed before", on: { click: () => go(prev) } }, "Previous change"),
      h("button", { class: "sm now", "aria-pressed": isNow ? "true" : "false", on: { click: () => go(null) } }, "Now"),
      h("button", { class: "sm", disabled: !next, title: next ? stamp(next) : "nothing changes after", on: { click: () => go(next) } }, "Next change"),
      moment, h("button", { class: "sm", on: { click: () => moment.value && go(new Date(moment.value).toISOString()) } }, "Show")));
}

async function viewGraph(arg) {
  const [anchor, at] = (arg || "").split("?at=");
  const g = await call("graph", { anchor: anchor }, null, at ? { at } : null);
  const subject = g.nodes.find(n => n.kind === "subject");
  const sources = [...new Set(g.nodes.filter(n => n.kind === "account").map(n => n.source.name))];
  const label = id => (g.nodes.find(n => n.id === id) || {}).label || id;
  const timebar = timeBar(g.at, g.marks, !at, t => { location.hash = graphHref(anchor, t); });
  const panel = h("div", { class: "graphpanel card" }, h("p", { class: "muted small" }, "Select something in the graph to see how it is connected."));
  const box = h("div", { class: "graphbox", id: "graphbox", role: "img",
    "aria-label": `Graph of ${subject ? subject.label : anchor}: ${g.nodes.length} items, ${g.edges.length} connections. The table below lists the same.` });
  const legend = h("div", { class: "legend small" },
    [["subject", "this person"], ["account", "account (where it signs in, named on it)"], ["person", "someone connected"],
      ["group", "group (class named under it)"], ["place", "place"]].map(([k, t]) => h("span", {}, h("i", { class: "dot " + k }), t)),
    h("span", {}, h("i", { class: "line dashed" }), "starts later"), h("span", {}, h("i", { class: "line faded" }), "ended"),
    h("span", {}, h("i", { class: "line soon" }), "ends within 14 days"));
  const subjectId = subject ? subject.id : null;
  const rows = g.edges.filter(e => e.kind !== "within").map(e => {
    const other = e.target === subjectId ? e.source : e.target;
    return [h("button", { type: "button", class: "ghost sm", "aria-label": "Show " + label(other) + " in the graph",
      on: { click: () => box.select && box.select(other) } }, "Show"), label(e.source), EDGE_WORDS[e.kind] || e.kind, label(e.target),
    e.label && e.label !== EDGE_WORDS[e.kind] ? h("span", { class: "small" }, e.label) : "",
    (e.via || []).length ? h("span", { class: "small" }, e.via.join("; ")) : "", windowText(e), e.status ? grantStatus(e.status) : ""];
  });
  const crumbs = h("div", { class: "crumbs" }, link("#/people", "People"), " / ",
    personLink(anchor, subject ? subject.label : anchor), " / graph");
  const tidy = h("button", { type: "button", class: "ghost sm" }, "Tidy up");
  const after = () => drawGraph(g, box, panel, anchor, tidy).catch(err => fill(box, h("p", { class: "empty" }, err.message)));
  return {
    render: [pageHead(h("span", {}, subject ? subject.label : anchor, " ", (subject && subject.roles || []).map(r => pill(r, "plum"))),
      "How this person's accounts, groups, delegations and places connect, at the moment you pick. You see what you may know.", crumbs),
    timebar,
    sources.length ? h("p", { class: "small" }, "Signs in through: ", sources.map((s, i) => [i ? ", " : "",
      h("i", { class: "swatch src-" + (i % 4), "aria-hidden": "true" }), h("b", {}, s)])) : null,   // the colour each source's accounts get in the graph
    h("div", { class: "graphwrap" }, box, panel), h("div", { class: "legendrow" }, legend, tidy),
    section("As a table", h("p", { class: "muted small" }, "Show selects the item in the graph and describes it beside the graph."),
      rows.length ? table(["", "who or what", "relation", "to", "detail", "via", "when", "state"], rows, "Connections") : empty("Nothing connected at this moment.")),
    g.realm_sources ? section("Where the realm's people sign in", table(["source", "kind", "people", "accounts"],
      g.realm_sources.map(s => [h("b", {}, s.name), pill(s.kind, s.kind === "unknown" ? "warn" : ""), s.persons, s.accounts]))) : null],
    after,
  };
}

// Where each item of a person graph goes (desk-upgrade.md, graph). Rules, so the same graph always looks the same:
// - the person in the middle; columns by distance from them, one step per column;
// - their own accounts, and the workloads and agents they own or direct, to the left; what they belong to, manage or
//   reach (groups, places, the tree) to the right, and whatever hangs off those one column further out;
// - in the first column: accounts daily before admin (left), groups privileged before elevated before low and then people
//   (right), items sharing a
//   box of the tree next to each other, then by name; further out each item sits at the height of what it connects
//   to (shorter lines, fewer crossings), never closer than one row to the next.
// Dragging still works; "Tidy up" puts everything back.
const RISK_ORDER = { privileged: 0, elevated: 1, low: 2 };
const KIND_ORDER = { account: 0, person: 1, group: 2, scope: 3, place: 4 };          // left: accounts, then what they run
const KIND_ORDER_RIGHT = { group: 0, scope: 1, place: 2, person: 3 };              // right: what they belong to, then people
const PURPOSE_ORDER = { daily: 0, admin: 1 };
function graphLayout(g) {
  const pos = graphPositions(g);
  return pos ? { name: "preset", positions: n => pos[n.id()] || { x: 0, y: 0 }, fit: true, padding: 30, animate: false }
    : { name: "concentric", fit: true, padding: 30, animate: false };
}
function graphPositions(g) {
  const boxes = new Set(g.nodes.filter(n => n.parent).map(n => n.parent));
  const items = g.nodes.filter(n => !boxes.has(n.id));
  const subject = items.find(n => n.kind === "subject");
  if (!subject) return null;
  const near = new Map(items.map(n => [n.id, []]));
  for (const e of g.edges) {
    if (!near.has(e.source) || !near.has(e.target) || e.source === e.target) continue;
    near.get(e.source).push([e.target, e.kind]);
    near.get(e.target).push([e.source, e.kind]);
  }
  const step = new Map([[subject.id, 0]]), side = new Map([[subject.id, 0]]), queue = [subject.id];
  while (queue.length) {
    const id = queue.shift();
    for (const [other, kind] of near.get(id)) {
      if (step.has(other)) continue;
      step.set(other, step.get(id) + 1);
      side.set(other, id === subject.id ? (["account", "owns", "directs"].includes(kind) ? -1 : 1) : side.get(id));
      queue.push(other);
    }
  }
  for (const n of items)              // a person beside the groups they act on would draw lines through them: one column out
    if (n.kind === "person" && step.get(n.id) === 1 && side.get(n.id) === 1
        && near.get(n.id).some(([o]) => o !== subject.id && step.get(o) === 1 && side.get(o) === 1)) step.set(n.id, 2);
  const far = Math.max(1, ...step.values()) + 1;
  for (const n of items) if (!step.has(n.id)) { step.set(n.id, far); side.set(n.id, 1); }   // not connected: far right
  const byId = Object.fromEntries(items.map(n => [n.id, n]));
  const columns = new Map();
  for (const n of items) {
    const c = side.get(n.id) * step.get(n.id);
    if (!columns.has(c)) columns.set(c, []);
    columns.get(c).push(n);
  }
  const ROW = 74, COL = 250, pos = {};
  pos[subject.id] = { x: 0, y: 0 };
  const name = n => String(n.label || n.id);
  const kindRank = n => ((side.get(n.id) < 0 ? KIND_ORDER : KIND_ORDER_RIGHT)[n.kind] ?? 9);
  const firstOrder = (a, b) => kindRank(a) - kindRank(b)
    || (PURPOSE_ORDER[a.purpose] ?? 2) - (PURPOSE_ORDER[b.purpose] ?? 2)
    || (RISK_ORDER[a.risk] ?? 3) - (RISK_ORDER[b.risk] ?? 3)
    || String(a.parent || "").localeCompare(String(b.parent || "")) || name(a).localeCompare(name(b));
  const order = [...columns.keys()].filter(c => c !== 0).sort((a, b) => Math.abs(a) - Math.abs(b) || a - b);
  for (const c of order) {
    const col = columns.get(c);
    let want;
    if (Math.abs(c) === 1) {
      col.sort(firstOrder);
      want = col.map((n, i) => (i - (col.length - 1) / 2) * ROW);
    } else {                          // the height of what it connects to in the column nearer the middle
      const inner = c - Math.sign(c);
      const at = n => {
        const ys = near.get(n.id).filter(([o]) => side.get(o) * step.get(o) === inner && pos[o]).map(([o]) => pos[o].y);
        return ys.length ? ys.reduce((s, y) => s + y, 0) / ys.length : 0;
      };
      col.sort((a, b) => at(a) - at(b) || String(a.parent || "").localeCompare(String(b.parent || "")) || name(a).localeCompare(name(b)));
      want = col.map(at);
      for (let i = 1; i < want.length; i++) want[i] = Math.max(want[i], want[i - 1] + ROW);   // never closer than a row
      const shift = (col.map(at).reduce((s, y) => s + y, 0) - want.reduce((s, y) => s + y, 0)) / col.length;
      want = want.map(y => y + shift);                                                        // keep the column centred
    }
    col.forEach((n, i) => { pos[n.id] = { x: c * COL, y: want[i] }; });
  }
  return pos;
}

async function drawGraph(g, box, panel, anchor, tidy) {
  await loadGraphLibrary();
  // account colours per sign-in source: never the status colours (ok, warn, bad); the same order as the .src-N swatches
  const palette = [tok("--plum"), tok("--key"), tok("--ink-2"), tok("--edge")];
  const srcIds = [...new Set(g.nodes.filter(n => n.kind === "account").map(n => n.source.id))];
  const soon = new Date(new Date(g.at).getTime() + 14 * 86400000).toISOString();
  const edgeState = e => e.status === "pending" ? "pending" : ["ended", "dead", "lapsed", "revoked", "void"].includes(e.status)
    ? "ended" : e.to && e.to < soon ? "soon" : "on";
  const pos = graphPositions(g) || {};
  const skips = e => pos[e.source] && pos[e.target] && Math.abs(pos[e.source].x - pos[e.target].x) > 260 ? "yes" : "no";
  // how far a line that skips a column bends sideways so that it passes above or below what stands in that column
  const bend = e => {
    if (skips(e) === "no") return 0;
    const s = pos[e.source], t = pos[e.target], mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
    const between = Object.values(pos).filter(q => q !== s && q !== t && Math.min(s.x, t.x) < q.x && q.x < Math.max(s.x, t.x));
    if (!between.length) return 0;
    const top = Math.min(...between.map(q => q.y)), bottom = Math.max(...between.map(q => q.y));
    const want = my - top < bottom - my ? top - 45 : bottom + 45;            // just outside the nearer end of the column
    const len = Math.hypot(t.x - s.x, t.y - s.y) || 1, nx = -(t.y - s.y) / len, ny = (t.x - s.x) / len;
    return Math.round((mx - mx) * nx + (want - my) * ny) * 2;            // a bezier reaches half its control distance
  };
  const els = [
    ...g.nodes.map(n => ({ data: { id: n.id, label: n.kind === "account" ? n.source.name + (n.purpose && n.purpose !== "unspecified" ? " (" + n.purpose + ")" : "") + "\n" + n.label.split(":").pop()
      : n.label + (n.person_kind === "workload" || n.person_kind === "agent" ? "\n" + n.person_kind : "")
        + (n.kind === "group" && n.risk ? "\n" + n.risk[0].toUpperCase() + n.risk.slice(1) : ""), kind: n.kind,   // class in words too
      parent: n.parent || undefined, risk: n.risk || "", pkind: n.person_kind || "", color: n.kind === "account" ? palette[srcIds.indexOf(n.source.id) % palette.length] : "" } })),
    ...g.edges.map(e => ({ data: { id: e.id, source: e.source, target: e.target, kind: e.kind, skips: skips(e), bend: bend(e),
      label: e.kind === "within" || e.kind === "account" ? "" : (EDGE_WORDS[e.kind] || e.kind)
        + (edgeState(e) === "soon" ? ", ends soon" : ""),     // in words, not colour alone
      state: edgeState(e) } })),
  ];
  const ink = tok("--ink"), muted = tok("--muted"), line = tok("--edge"), card = tok("--card"), soft = tok("--soft");
  const cy = window.cytoscape({
    container: box, elements: els, minZoom: 0.2, maxZoom: 3,
    style: [
      { selector: "node", style: { label: "data(label)", "font-size": 11, color: ink, "text-wrap": "wrap", "text-max-width": 120,
        "text-valign": "bottom", "text-margin-y": 5, "background-color": soft, "border-width": 1, "border-color": line, width: 26, height: 26 } },
      { selector: "node[kind = 'subject']", style: { "background-color": tok("--plum"), width: 58, height: 58, "font-size": 13, "font-weight": 700,
        "text-valign": "center", "text-margin-y": 0, color: tok("--on-accent"), "text-max-width": 52 } },
      { selector: "node[kind = 'account']", style: { shape: "round-rectangle", "background-color": "data(color)", width: 18, height: 18 } },
      { selector: "node[kind = 'person']", style: { "background-color": card, "border-color": muted } },
      { selector: "node[pkind = 'workload']", style: { shape: "round-octagon", "border-color": tok("--key"), "border-width": 2 } },
      { selector: "node[pkind = 'agent']", style: { shape: "diamond", "border-color": tok("--plum"), "border-width": 2 } },
      { selector: "node[kind = 'group']", style: { shape: "round-rectangle", width: 34, height: 22, "border-width": 3, "background-color": card } },
      { selector: "node[risk = 'low']", style: { "border-color": tok("--ok") } },
      { selector: "node[risk = 'elevated']", style: { "border-color": tok("--warn") } },
      { selector: "node[risk = 'privileged']", style: { "border-color": tok("--bad") } },
      { selector: "node[kind = 'place']", style: { shape: "hexagon", "background-color": tok("--key-soft"), "border-color": tok("--key"), width: 30, height: 26 } },
      { selector: ":parent", style: { "background-color": soft, "background-opacity": 0.5, "border-color": line, "border-style": "dashed",
        "text-valign": "top", "text-halign": "center", "font-size": 10, color: muted, padding: 14, shape: "round-rectangle" } },
      { selector: "edge", style: { width: 1.5, "line-color": line, "target-arrow-color": line, "target-arrow-shape": "triangle",
        "curve-style": "bezier", "arrow-scale": 0.8, label: "data(label)", "font-size": 9, color: muted, "text-rotation": "autorotate",
        "text-background-color": tok("--card"), "text-background-opacity": 0.9, "text-background-padding": 2,
        "source-distance-from-node": 4, "target-distance-from-node": 4 } },
      { selector: "edge[skips = 'yes']", style: { "curve-style": "unbundled-bezier", "control-point-distances": "data(bend)",
        "control-point-weights": 0.5 } },          // a line that skips a column bends around it, not through it
      { selector: "edge[state = 'pending']", style: { "line-style": "dashed" } },
      { selector: "edge[state = 'ended']", style: { opacity: 0.35, "line-style": "dotted" } },
      { selector: "edge[state = 'soon']", style: { "line-color": tok("--warn"), "target-arrow-color": tok("--warn"), width: 2 } },
      { selector: "edge[kind = 'within']", style: { "line-style": "dotted", "target-arrow-shape": "none" } },
      { selector: ":selected", style: { "border-color": tok("--focus"), "border-width": 3, "line-color": tok("--focus"), "target-arrow-color": tok("--focus") } },
    ],
    layout: graphLayout(g),
  });
  // a small graph is not blown up; on a narrow screen it is not shrunk past readable labels either: it starts on the
  // person, and the rest is a drag or a pinch away
  const settle = () => {
    if (cy.zoom() > 1.2) { cy.zoom(1.2); cy.center(); }
    else if (cy.zoom() < 0.75 && box.clientWidth < 600) { cy.zoom(0.75); cy.center(cy.$("node[kind = 'subject']")); }
  };
  settle();
  if (tidy) tidy.onclick = () => { cy.layout(graphLayout(g)).run(); settle(); };
  const byId = Object.fromEntries(g.nodes.map(n => [n.id, n]));
  const describe = n => {
    const touching = g.edges.filter(e => e.source === n.id || e.target === n.id);
    fill(panel, 
      h("h3", {}, n.label), h("p", { class: "small muted" }, NODE_WORDS[n.kind] || n.kind,
        n.kind === "account" ? " at " + n.source.name : "", n.risk ? ", class " + n.risk : ""),
      n.kind === "subject" && n.last_seen === null ? h("p", { class: "small muted" }, "Last seen: not recorded yet.") : null,
      touching.length ? h("ul", { class: "small" }, touching.map(e => h("li", {},
        (byId[e.source] || {}).label, " ", h("b", {}, EDGE_WORDS[e.kind] || e.kind), " ", (byId[e.target] || {}).label,
        e.label && e.label !== EDGE_WORDS[e.kind] ? " (" + e.label + ")" : "", windowText(e) ? ", " + windowText(e) : "",
        (e.via || []).length ? h("div", { class: "tiny muted" }, "via " + e.via.join("; ")) : null))) : null,
      n.kind === "person" ? link(graphHref(n.anchor), "Open their graph", "button sm") : null,
      n.kind === "group" ? link("#/group/" + encodeURIComponent(n.label), "Open the group", "button sm") : null);
  };
  cy.on("tap", "node", ev => describe(byId[ev.target.id()]));
  box.select = id => {                                   // from the table: select it, show it, describe it, and say so
    const node = cy.getElementById(id);
    if (!node || !node.length || !byId[id]) return;
    cy.$(":selected").unselect();
    node.select();
    cy.animate({ center: { eles: node } }, { duration: 200 });
    describe(byId[id]);
    panel.setAttribute("tabindex", "-1");
    panel.focus({ preventScroll: false });
  };
  cy.on("tap", ev => { if (ev.target === cy) fill(panel, h("p", { class: "muted small" }, "Select something in the graph to see how it is connected.")); });
  const s = cy.getElementById("subject");
  if (s.nonempty()) s.select();
}

// --- delegation tree (decision 0009) ----------------------------------------------------------------------------
// What was handed on, to whom, how deep and until when, at the moment you pick. A viewer and the root see the whole
// tree; a deputy sees what they hold, what they handed on below it and the chain above it (the desk's tree policy).

const treeHref = at => "#/tree" + (at ? "?at=" + encodeURIComponent(at) : "");
const TREE_STATES = { active: "in force", pending: "starts later", grace: "retired, the grace period runs", ended: "ended",
  revoked: "revoked for cause", dead: "a link above it broke" };
const treeStatus = grantStatus;

async function viewTree(arg) {
  const at = (arg || "").split("?at=")[1];
  const g = await call("tree", {}, null, at ? { at } : null);
  const timebar = timeBar(g.at, g.marks, !at, t => { location.hash = treeHref(t); });
  const crumbs = h("div", { class: "crumbs" }, link("#/delegations", "Delegations"), " / tree");
  const head = pageHead("Delegation tree", g.whole
    ? "Every delegation in the tenant at the moment you pick: who handed what on to whom, how deep, until when."
    : "The delegations you hold, what you handed on below them and the chain above them, at the moment you pick.", crumbs);
  if (!g.nodes.length) return { render: [head, timebar, empty("You hold no delegation, so there is no tree to show.")] };
  const byId = Object.fromEntries(g.nodes.map(n => [n.id, n]));
  const tops = g.nodes.filter(n => !n.parent || !byId[n.parent]);
  const rows = [];
  const walk = (n, depth) => { if (n.kind === "delegation") rows.push(n); g.nodes.filter(k => k.parent === n.id).forEach(k => walk(k, depth + 1)); };
  tops.forEach(n => walk(n, n.kind === "root" ? 0 : 1));
  const panel = h("div", { class: "graphpanel card" }, h("p", { class: "muted small" }, "Select a delegation to see what it allows."));
  const box = h("div", { class: "graphbox", id: "graphbox", role: "img",
    "aria-label": `Delegation tree: ${rows.length} delegations. The table below lists the same.` });
  const legend = h("div", { class: "legend small" },
    [["ok", "in force"], ["warn", "grace period, or ends within 14 days"], ["pend", "starts later"], ["gone", "ended, revoked or broken above"]]
      .map(([k, t]) => h("span", {}, h("i", { class: "box " + k }), t)));
  return {
    render: [head, timebar,
      g.held.length && !g.whole ? h("p", { class: "small" }, "You hold: ", g.held.map((d, i) => [i ? ", " : "", h("b", {}, byId[d].group)])) : null,
      h("div", { class: "graphwrap" }, box, panel), legend,
      section("As a list", rows.length ? delegationTreeList(g, tops, box) : empty("Nothing delegated at this moment."))],
    after: () => drawTree(g, tops, box, panel).catch(err => fill(box, h("p", { class: "empty" }, err.message))),
  };
}

// The delegation tree as a tree for the keyboard and screen readers (WAI-ARIA tree view): Up and Down move, Right opens
// or goes in, Left closes or goes up, Home and End jump, Enter shows the delegation beside the diagram.
function delegationTreeList(g, tops, box) {
  const kids = id => g.nodes.filter(k => k.parent === id);
  const item = (n, level) => {
    const children = kids(n.id);
    const label = n.kind === "root" ? h("span", {}, h("b", {}, "Root"), " held by ", n.label)
      : h("span", {}, h("b", {}, n.label), " manages ", n.group, " ", riskTag(n.max_risk), " ", treeStatus(n.status),
        h("span", { class: "muted small" }, " " + (n.depth_left ? "may pass on " + n.depth_left + " more level" + (n.depth_left === 1 ? "" : "s")
          : "may not pass on") + (n.to ? ", until " + day(n.to) : "") + ", " + n.in_use + " membership" + (n.in_use === 1 ? "" : "s") + " rely on it"));
    const li = h("li", { role: "treeitem", "aria-level": String(level), tabindex: "-1", "data-id": n.id,
      "aria-expanded": children.length ? "true" : null }, label,
      children.length ? h("ul", { role: "group" }, children.map(k => item(k, level + 1))) : null);
    return li;
  };
  const tree = h("ul", { role: "tree", class: "treelist", "aria-label": "Delegations" }, tops.map(n => item(n, 1)));
  const visible = () => [...tree.querySelectorAll('[role="treeitem"]')].filter(li => !li.closest('[aria-expanded="false"] > ul'));
  const focus = li => { for (const x of tree.querySelectorAll('[role="treeitem"]')) x.tabIndex = -1; li.tabIndex = 0; li.focus(); };
  const first = tree.querySelector('[role="treeitem"]');
  if (first) first.tabIndex = 0;
  tree.addEventListener("keydown", ev => {
    const li = ev.target.closest('[role="treeitem"]');
    if (!li) return;
    const list = visible(), i = list.indexOf(li);
    const open = li.getAttribute("aria-expanded");
    let go = null;
    if (ev.key === "ArrowDown") go = list[i + 1];
    else if (ev.key === "ArrowUp") go = list[i - 1];
    else if (ev.key === "Home") go = list[0];
    else if (ev.key === "End") go = list[list.length - 1];
    else if (ev.key === "ArrowRight") { if (open === "false") li.setAttribute("aria-expanded", "true"); else if (open === "true") go = li.querySelector('[role="treeitem"]'); }
    else if (ev.key === "ArrowLeft") { if (open === "true") li.setAttribute("aria-expanded", "false"); else go = li.parentElement.closest('[role="treeitem"]'); }
    else if (ev.key === "Enter" || ev.key === " ") { if (box.select) box.select(li.dataset.id); }
    else return;
    ev.preventDefault();
    if (go) focus(go);
  });
  tree.addEventListener("click", ev => { const li = ev.target.closest('[role="treeitem"]'); if (li && !ev.target.closest("a")) { focus(li); if (box.select) box.select(li.dataset.id); } });
  return tree;
}

async function drawTree(g, tops, box, panel) {
  await loadGraphLibrary();
  const soon = new Date(new Date(g.at).getTime() + 14 * 86400000).toISOString();
  const tone = n => n.kind === "root" ? "root" : n.status === "active" ? (n.to && n.to < soon ? "warn" : "ok")
    : n.status === "grace" ? "warn" : n.status === "pending" ? "pend" : "gone";
  const els = [
    ...g.nodes.map(n => ({ data: { id: n.id, tone: tone(n),
      label: n.kind === "root" ? "root\n" + n.label : n.label + "\n" + n.group + (n.to ? "\nuntil " + day(n.to) : "")
        + (tone(n) === "warn" ? (n.status === "grace" ? ", grace period" : ", ends soon") : "") } })),   // words, not colour alone
    ...g.edges.map(e => ({ data: { id: e.id, source: e.source, target: e.target } })),
  ];
  const line = tok("--edge");
  const cy = window.cytoscape({
    container: box, elements: els, minZoom: 0.2, maxZoom: 1.2,    // a small tree is not blown up to fill the box
    style: [
      { selector: "node", style: { shape: "round-rectangle", label: "data(label)", "text-wrap": "wrap", "text-valign": "center",
        "text-halign": "center", "font-size": 11, color: tok("--ink"), width: 130, height: 54, "background-color": tok("--card"),
        "border-width": 2, "border-color": tok("--ok") } },
      { selector: "node[tone = 'root']", style: { "background-color": tok("--plum"), "border-color": tok("--plum"),
        color: tok("--on-accent"), "font-weight": 700, height: 44 } },
      { selector: "node[tone = 'warn']", style: { "border-color": tok("--warn"), "border-width": 3 } },
      { selector: "node[tone = 'pend']", style: { "border-style": "dashed", "border-color": tok("--key") } },
      { selector: "node[tone = 'gone']", style: { opacity: 0.45, "border-style": "dotted", "border-color": tok("--muted") } },
      { selector: "edge", style: { width: 1.5, "line-color": line, "target-arrow-color": line, "target-arrow-shape": "triangle",
        "curve-style": "taxi", "taxi-direction": "downward", "arrow-scale": 0.8 } },
      { selector: ":selected", style: { "border-color": tok("--focus"), "border-width": 3 } },
    ],
    layout: { name: "breadthfirst", directed: true, roots: tops.map(n => n.id), spacingFactor: 1.1, padding: 24, animate: false },
  });
  const byId = Object.fromEntries(g.nodes.map(n => [n.id, n]));
  const hint = () => fill(panel, h("p", { class: "muted small" }, "Select a delegation to see what it allows."));
  const describe = n => {
    if (n.kind === "root") {
      fill(panel, h("h3", {}, "Root"), h("p", { class: "small" }, "Held by ",
        n.anchor ? personLink(n.anchor, n.label) : n.label, " at this moment. Every delegation is a chain back to here."));
      return;
    }
    fill(panel, 
      h("h3", {}, n.label, " ", h("span", { class: "muted small" }, n.id)),
      h("p", { class: "small" }, treeStatus(n.status), " ", TREE_STATES[n.status] || "", n.grace_until ? ", until " + day(n.grace_until) : ""),
      h("ul", { class: "small" },
        h("li", {}, "Manages ", link("#/group/" + encodeURIComponent(n.group), n.group), " and below, up to class ",
          riskTag(n.max_risk)),
        h("li", {}, "Powers: ", powers(n.powers)),
        n.max_membership_days ? h("li", {}, "Memberships up to " + n.max_membership_days + " days") : null,
        h("li", {}, "Level " + n.depth + " below the root; " + (n.depth_left
          ? "may pass on " + n.depth_left + " more level" + (n.depth_left === 1 ? "" : "s") : "may not pass on")),
        h("li", {}, "Handed on by " + n.by + ", " + windowText(n)),
        h("li", {}, n.in_use + " membership" + (n.in_use === 1 ? "" : "s") + " made under it in force")),
      link(graphHref(n.anchor), "Open their graph", "button sm"));
  };
  cy.on("tap", "node", ev => describe(byId[ev.target.id()]));
  box.select = id => {
    const node = cy.getElementById(id);
    if (!node || !node.length || !byId[id]) return;
    cy.$(":selected").unselect();
    node.select();
    cy.animate({ center: { eles: node } }, { duration: 200 });
    describe(byId[id]);
  };
  cy.on("tap", ev => { if (ev.target === cy) hint(); });
}

// --- visits (decision 0009) -------------------------------------------------------------------------------------
// Who comes, when, with which vehicle and kit, and what happened on the day. The desk's visit policy decides who may
// record what, what the gate says and which timer steps are due; this page shows it and offers what you may do.

const visitHref = (id, at) => "#/visit/" + encodeURIComponent(id) + (at ? "?at=" + encodeURIComponent(at) : "");
const WHEN = { upcoming: ["upcoming", ""], open: ["open now", "ok"], closed: ["closed", ""] };
const PRESENTED = { qr: "the QR code from registration", "visitor-badge": "a visitor badge",
  "restricted-badge": "a RESTRICTED badge", none: "nothing yet" };
const ACTION_WORDS = { record_entry: "Record entry", acknowledge_arrival: "Acknowledge arrival", confirm_guest: "Confirm: with me",
  record_departure: "Record departure" };
const EVENT_WORDS = { opens: "Visit opens", start: "Meeting starts", end: "Meeting ends", closes: "Visit closes",
  arrived: "Arrived", entered: "Entered", expected: "Expected", "attendee-added": "Added to the visit",
  "registered-on-site": "Registered at the front office", acknowledged: "Arrival acknowledged", confirmed: "Confirmed with the host",
  reminded: "Host reminded", suspended: "Suspended and flagged", left: "Left", "qr-issued": "QR code issued", "badge-returned": "Badge returned",
  "remind-due": "Reminder due",
  "suspend-due": "Suspension due" };

async function viewVisits() {
  const list = await call("visits");
  const rows = list.map(v => [pill(...WHEN[v.when]), link(visitHref(v.visit_id), v.purpose || v.visit_id),
    h("span", { class: "small" }, stamp(v.start), " to ", stamp(v.end)), v.place_name, v.host_name || v.host,
    v.parties + (v.unregistered ? ` (${v.unregistered} unregistered)` : ""), v.vehicles.join(", "),
    h("span", {}, v.suspended ? pill(v.suspended + " suspended", "bad") : null,
      v.waiting_for_me ? pill(v.waiting_for_me + " waiting for you", "warn") : null)]);
  return setMain(pageHead("Visits", "Visits you host or organise, visits to a place whose front office or steward you are, and "
    + "your own. A visit is the only thing that lets someone on site."),
  section("Register a visit", h("details", { class: "card" }, h("summary", {}, "Open the form"), registerVisitForm())),
  section("Visits", rows.length ? table(["", "purpose", "when", "place", "host", "people", "vehicle", ""], rows)
    : empty("No visit you may see.")));
}

function registerVisitForm() {
  const place = h("input", { required: true, placeholder: "place:heverlee", autocomplete: "off" });
  const purpose = h("input", { required: true, maxlength: 300, placeholder: "what the visit is for" });
  const start = h("input", { type: "datetime-local", required: true }), end = h("input", { type: "datetime-local", required: true });
  const guests = h("textarea", { rows: 4, placeholder: "one per line: an anchor (registered, e.g. ext:3a71-carla) or a name (invited, not registered yet)" });
  const companions = h("input", { type: "number", min: 0, max: 20, value: 0 });
  const delegation = h("input", { maxlength: 80, placeholder: "e.g. the supplier's name" });
  const escorts = h("input", { maxlength: 400, placeholder: "anchors of staff who accompany them, comma separated", autocomplete: "off" });
  const plate = h("input", { maxlength: 20, placeholder: "plate (kept only as a digest)", autocomplete: "off" });
  const make = h("input", { maxlength: 40, placeholder: "make" }), model = h("input", { maxlength: 40, placeholder: "model" });
  const colour = h("input", { maxlength: 30, placeholder: "colour" });
  const iso = el => el.value ? new Date(el.value).toISOString() : null;
  return reviewed([
    field("Place", place, "the site, by its id"), field("Purpose", purpose, null, true),
    field("Meeting starts", start), field("Meeting ends", end, "the visit opens and closes around it by policy"),
    field("Guests", guests, "each person on their own line; they arrive when and how they like", true),
    field("Unregistered companions", companions, "a count; they can only get an escorted visitor badge"),
    field("Delegation", delegation, "optional: the group they come as"),
    field("Escorts", escorts, "optional", true),
    field("A vehicle announced", h("span", { class: "inline-fields" }, plate, make, model, colour), "optional; driven by the first guest", true)],
  () => {
    if (!place.value) return { error: "Choose the place", field: place };
    if (!start.value) return { error: "Give the start", field: start };
    if (!end.value) return { error: "Give the end", field: end };
    const lines = guests.value.split("\n").map(s => s.trim()).filter(Boolean);
    const attendees = lines.map(s => /^[A-Za-z0-9]+:[^\s]+$/.test(s) ? { anchor: s } : { name: s });
    for (let i = 0; i < Number(companions.value); i++) attendees.push({ unregistered: true, label: "companion " + (i + 1) });
    if (!attendees.length) return { error: "Add at least one guest", field: guests };
    const body = { action: "register_visit", place: place.value.trim(), purpose: purpose.value, start: iso(start), end: iso(end),
      attendees, host: ME.anchor, organiser: ME.anchor };
    const esc = escorts.value.split(",").map(s => s.trim()).filter(Boolean);
    if (esc.length) body.escorts = esc;
    if (delegation.value) body.delegation = { name: delegation.value };
    if (plate.value) body.vehicles = [{ plate: plate.value, make: make.value, model: model.value, colour: colour.value,
      driver: attendees[0] && attendees[0].anchor ? 1 : undefined }];
    return body;
  }, "You become the host and organiser. Registered guests get a QR code; invited people register before they come or at the front office.");
}

// A day strip: the window with its margins, the meeting, now, and what happened, drawn as SVG (no inline style, so
// the page keeps its strict content policy).
function svg(tag, attrs, ...kids) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, v);
  for (const k of kids.flat()) if (k) el.append(typeof k === "string" ? document.createTextNode(k) : k);
  return el;
}

function dayStrip(v) {
  const t0 = new Date(v.opens).getTime(), t1 = new Date(v.closes).getTime(), W = 1000;
  const x = t => Math.max(0, Math.min(W, ((new Date(t).getTime() - t0) / (t1 - t0)) * W));
  const now = new Date(v.at).getTime();
  const marks = v.timeline.filter(e => !["opens", "closes", "start", "end"].includes(e.kind));
  return svg("svg", { viewBox: `0 -18 ${W} 78`, class: "daystrip", role: "img",
    "aria-label": `Visit window ${stamp(v.opens)} to ${stamp(v.closes)}; meeting ${stamp(v.start)} to ${stamp(v.end)}` },
  svg("rect", { x: 0, y: 10, width: W, height: 18, rx: 4, class: "margin" }),
  svg("rect", { x: x(v.start), y: 10, width: Math.max(2, x(v.end) - x(v.start)), height: 18, rx: 3, class: "meeting" }),
  svg("text", { x: 2, y: 4, class: "lbl" }, stamp(v.opens)),
  svg("text", { x: W - 2, y: 4, class: "lbl end" }, stamp(v.closes)),
  svg("text", { x: (x(v.start) + x(v.end)) / 2, y: 23, class: "lbl mid" }, "meeting"),
  marks.map(e => svg("g", { class: "tick " + e.kind }, svg("line", { x1: x(e.at), x2: x(e.at), y1: 6, y2: 34 }),
    /^suspend/.test(e.kind) ? svg("rect", { x: x(e.at) - 4, y: 36, width: 8, height: 8 })      // suspension: a square
      : svg("circle", { cx: x(e.at), cy: 40, r: 4 }),                                          // reminder: a ring (CSS); else a dot
    svg("title", {}, `${new Date(e.at).toLocaleTimeString()} ${EVENT_WORDS[e.kind] || e.kind}`))),
  now >= t0 && now <= t1 ? svg("line", { x1: x(v.at), x2: x(v.at), y1: 0, y2: 50, class: "now" }) : null);
}

function gateText(g) {
  if (g.allow) return h("span", {}, pill("passes", "ok"), g.escort ? " escorted" : "");
  if (g.never) return h("span", {}, pill("never", "bad"), " ", g.reasons.join("; "));
  return h("span", {}, pill(g.front_office ? "front office" : "stopped", g.front_office ? "warn" : "bad"), " ", g.reasons.join("; "));
}

function entryForm(v, p) {
  const presented = h("select", {}, Object.entries(PRESENTED).map(([k, t]) => h("option", { value: k, selected: k === (p.last_presented || (p.registered ? "qr" : "none")) }, t)));
  const vehicle = h("input", { type: "checkbox" });
  const zone = h("select", {}, h("option", { value: "" }, "the site"), v.zones.map(z => h("option", { value: z }, z)));
  const checkpoint = h("input", { maxlength: 80, placeholder: "main gate", value: "main gate" });
  const token = h("input", { maxlength: 400, placeholder: "scan or paste the QR code", autocomplete: "off", spellcheck: "false" });
  return h("form", { class: "inline-form", on: { submit: ev => { ev.preventDefault();
    const body = { action: "record_entry", visit_id: v.visit_id, party: p.party, presented: presented.value, vehicle: vehicle.checked,
      checkpoint: checkpoint.value || undefined };
    if (zone.value) body.zone = zone.value;
    if (presented.value === "qr" && token.value) body.token = token.value.trim().replace(/^.*#\/scan\//, "");
    act("propose", {}, body); } } },
  h("label", {}, "Showed ", presented), p.role === "driver" ? h("label", {}, vehicle, " with the vehicle") : null,
  p.registered ? h("label", {}, "Code ", token) : null,
  v.zones.length ? h("label", {}, "Into ", zone) : null, h("label", {}, "At ", checkpoint),
  h("button", { type: "submit", class: "sm" }, "Record entry"));
}

const STATE_PILL = { registered: ["registered", "ok"], invited: ["invited, not registered", "warn"],
  "registered-on-site": ["registered at the front office", "ok"], unregistered: ["unregistered", "warn"] };
function partyCard(v, p) {
  const states = [p.arrived ? pill("arrived " + new Date(p.arrived).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), "ok") : pill("not arrived", ""),
    p.acknowledged ? pill("acknowledged", "ok") : null, p.confirmed ? pill("with the host", "ok") : null,
    p.suspended ? pill("suspended", "bad") : null, p.departed ? pill("left", "") : null];
  const simple = p.actions.filter(a => a !== "record_entry" && a !== "issue_badge");
  return h("div", { class: "card item" + (p.suspended ? " attention" : "") },
    h("div", { class: "main" },
      h("h3", {}, p.registered ? personLink(p.anchor, p.name) : p.name, " ", pill(...(STATE_PILL[p.state] || [p.state, ""]))),
      h("div", { class: "pills" }, states),
      h("p", { class: "small muted" }, [p.organisation, p.expected ? "expected " + new Date(p.expected).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : null,
        p.came ? "came " + p.came : null, p.escort ? "escort: " + p.escort : null,
        p.kit.length ? "brings " + p.kit.map(k => k.count + " x " + k.name).join(", ") : null].filter(Boolean).join(" · ")),
      h("p", { class: "small" }, "At the gate now: ", gateText(p.gate))),
    h("div", { class: "actions" },
      simple.map(a => h("button", { class: "sm" + (a === "confirm_guest" ? "" : " ghost"),
        on: { click: () => act("propose", {}, { action: a, visit_id: v.visit_id, party: p.party }) } }, ACTION_WORDS[a])),
      p.qr ? h("button", { class: "sm ghost", on: { click: ev => showQr(v, p, ev.target) } }, "Show QR code") : null,
      p.actions.includes("register_on_site") ? onSiteForm(v, p) : null,
      p.actions.includes("issue_badge") ? badgeForm(v, p) : null,
      p.actions.includes("record_entry") ? entryForm(v, p) : null));
}

function onSiteForm(v, p) {
  const anchor = h("input", { maxlength: 256, placeholder: "their account after self-registering", autocomplete: "off", required: true });
  return h("form", { class: "inline-form", on: { submit: ev => { ev.preventDefault();
    act("propose", {}, { action: "register_on_site", visit_id: v.visit_id, party: p.party, anchor: anchor.value.trim() }); } } },
  h("label", {}, "Registered as ", anchor), h("button", { type: "submit", class: "sm ghost" }, "Link (identity checked)"));
}

function addAttendeeForm(v) {
  const who = h("input", { maxlength: 256, placeholder: "an anchor, or a name", autocomplete: "off", required: true });
  return h("form", { class: "inline-form", on: { submit: ev => { ev.preventDefault();
    const s = who.value.trim();
    act("propose", {}, { action: "add_attendee", visit_id: v.visit_id, attendee: /^[A-Za-z0-9]+:[^\s]+$/.test(s) ? { anchor: s } : { name: s } }); } } },
  h("label", {}, "Someone not on the list: ", who), h("button", { type: "submit", class: "sm ghost" }, "Add"));
}

function badgeForm(v, p) {
  const kind = h("select", {}, h("option", { value: "visitor" }, "visitor badge (escorted)"),
    p.registered ? h("option", { value: "restricted" }, "RESTRICTED badge (a second person signs)") : null);
  const number = h("input", { maxlength: 40, placeholder: "badge number", required: true, autocomplete: "off" });
  return h("form", { class: "inline-form", on: { submit: ev => { ev.preventDefault();
    act("propose", {}, { action: "issue_badge", visit_id: v.visit_id, party: p.party, kind: kind.value, badge: number.value }); } } },
  h("label", {}, "Badge ", kind), h("label", {}, "No. ", number), h("button", { type: "submit", class: "sm ghost" }, "Hand out"));
}

async function showQr(v, p, button) {
  try {
    const q = await call("visitqr", { visit_id: v.visit_id, party: p.party });
    button.replaceWith(h("div", { class: "qrbox" },
      h("img", { src: q.image, alt: "QR code for " + p.name + " on this visit", width: 200, height: 200 }),
      h("div", { class: "small" }, h("b", {}, "Show this at the gate."), " Valid until ", stamp(q.until),
        ". Anyone can scan it to see whether the guest may walk unescorted; it tells them nothing else."),
      h("button", { class: "sm ghost", on: { click: () => act("propose", {}, { action: "issue_qr", visit_id: v.visit_id, party: p.party }) } },
        "Lost it? Issue a new code (this one stops working)")));
  } catch (e) {
    banner({ outcome: "error", summary: "", reasons: [e.message], next: e.next });
  }
}

// --- the phone scan (no sign-in) ------------------------------------------------------------------------------
// Anyone with a phone scans a guest's code: yes or no, and until when, checked online now. Nothing else. A signed-in
// front office sees a button to record the entry at their checkpoint with the same code.

async function viewScan(token) {
  const r = await call("scan", { token });
  const answer = r.unescorted
    ? h("div", { class: "scan yes", role: "status" }, h("div", { class: "big" }, "Yes"),
      h("div", {}, "may walk unescorted until ", h("b", {}, new Date(r.until).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))))
    : h("div", { class: "scan no", role: "status" }, h("div", { class: "big" }, "No"),
      h("div", {}, "must be escorted, or go to the front office"));
  return setMain(answer,
    h("p", { class: "muted small center" }, "Checked online at ", new Date(r.at).toLocaleTimeString(), ". This answer tells nothing else about the guest."),
    ME && ME.person ? h("div", { class: "card" }, h("p", { class: "small" }, "Front office: record this guest's entry with the code."),
      h("form", { class: "inline-form", on: { submit: ev => { ev.preventDefault();
        act("propose", {}, { action: "record_entry", token, presented: "qr", checkpoint: ev.target.elements.cp.value || undefined }); } } },
      h("label", {}, "At ", h("input", { name: "cp", maxlength: 80, value: "main gate" })),
      h("button", { type: "submit", class: "sm" }, "Record entry"))) : null);
}

async function viewVisit(arg) {
  const [id, at] = (arg || "").split("?at=");
  const v = await call("visit", { visit_id: id }, null, at ? { at } : null);
  const times = [...new Set(v.timeline.filter(e => !e.kind.endsWith("-due")).map(e => e.at))].sort();
  const marks = { before: times.filter(t => t < v.at).slice(-20), after: times.filter(t => t > v.at).slice(0, 20) };
  const timebar = timeBar(v.at, marks, !at, t => { location.hash = visitHref(id, t); });
  const crumbs = h("div", { class: "crumbs" }, link("#/visits", "Visits"), " / ", v.visit_id);
  const nameOf = pid => (v.parties.find(p => p.party === pid) || {}).name || pid;
  const line = v.timeline.map(e => h("li", { class: "ev " + e.kind + (new Date(e.at) > new Date(v.at) ? " ahead" : "") },
    h("span", { class: "t" }, new Date(e.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })),
    h("span", { class: "what" }, h("b", {}, EVENT_WORDS[e.kind] || e.kind), e.party ? " " + nameOf(e.party) : "",
      e.presented ? `, showed ${PRESENTED[e.presented] || e.presented}` : "", e.vehicle ? ", with the vehicle" : "",
      e.zone ? ", into " + e.zone : "", e.checkpoint ? " at " + e.checkpoint : "",
      e.by_name ? h("span", { class: "muted" }, " (" + e.by_name + ")") : "",
      e.notify && e.notify.length ? h("div", { class: "tiny muted" }, "notified: " + e.notify.length + " people") : null,
      e.kind.endsWith("-due") || ["reminded", "suspended"].includes(e.kind) ? h("div", { class: "tiny muted" }, e.text) : null)));
  return setMain(
    pageHead(h("span", {}, v.purpose || v.visit_id, " ", pill(...WHEN[v.when])),
      `${v.place_name}, hosted by ${v.host_name || v.host}${v.organiser !== v.host ? ", organised by " + (v.organiser_name || v.organiser) : ""}. `
      + `Meeting ${stamp(v.start)} to ${stamp(v.end)}; on site from ${stamp(v.opens)} until ${stamp(v.closes)}.`, crumbs),
    timebar,
    h("div", { class: "card" }, dayStrip(v)),
    section("Who comes", h("p", { class: "small muted" }, [v.delegation ? "Delegation " + v.delegation : null,
      `${v.arrived} of ${v.parties} arrived`, v.escorts.length ? "escorts: " + v.escorts.join(", ") : null].filter(Boolean).join(" · ")),
    h("div", { class: "list" }, v.parties.map(p => partyCard(v, p))), v.may_add ? h("div", { class: "card" }, addAttendeeForm(v)) : null),
    h("div", { class: "cols" },
      section("Vehicle", v.vehicles_detail.length ? h("div", { class: "card" }, v.vehicles_detail.map(k =>
        h("p", {}, h("b", {}, [k.colour, k.make, k.model].filter(Boolean).join(" ") || "a vehicle"), ", plate ending ",
          h("code", {}, k.plate_tail), k.driver ? ", driven by " + k.driver : ""))) : empty("No vehicle announced.")),
      section("Kit", v.kit.length ? h("div", { class: "card" }, h("ul", {}, v.kit.map(i => h("li", {}, `${i.count} x ${i.name}`,
        i.note ? ` (${i.note})` : "", i.with ? h("span", { class: "muted" }, ", " + i.with) : null)))) : empty("No kit declared."))),
    v.badges.length ? section("Badges", table(["holder", "badge", "handed out by", "second key", "valid", "returned", ""],
      v.badges.map(b => [b.holder, h("span", {}, pill(b.kind === "restricted" ? "RESTRICTED" : "visitor", b.kind === "restricted" ? "bad" : ""),
        " ...", h("code", {}, b.tail)), b.issued_by || "", b.second.join(", "), `${stamp(b.from)} to ${stamp(b.to)}`,
      b.returned ? stamp(b.returned) : "", b.may_return ? h("button", { class: "sm ghost",
        on: { click: () => act("propose", {}, { action: "return_badge", badge_id: b.badge_id }) } }, "Mark returned") : ""]))) : null,
    section("Timeline", h("ol", { class: "card timeline" }, line)));
}

// --- broker -----------------------------------------------------------------------------------------------------

async function viewBroker() {
  const b = await call("broker");
  return setMain(pageHead("Sign-in service", "What the reconciler did with the records in the sign-in service (Keycloak)."),
    h("div", { class: "cards" }, [["records revision", b.revision], ["memberships held there", b.observed],
      ["change log", b.log_intact ? "intact" : "BROKEN"]].map(([k, n], i) =>
      h("div", { class: "card stat" + (i === 2 && !b.log_intact ? " attention" : "") }, h("b", {}, n), h("span", {}, k)))),
    section("Reconciler runs", brokerRuns(b.runs)),
    section("Added by hand in the sign-in service",
      h("p", { class: "muted small" }, "Memberships nobody asked for here were found and removed; the service's admin events say who added them."),
      (b.manual_changes || []).length ? table(["seen", "group", "member", "added by", "via"], b.manual_changes.map(m =>
        [moment(m.at), h("code", {}, m.group), who(m.member, m.member_name), m.by, h("code", {}, m.client)]))
        : empty("None seen.")));
}

// Runs that say the same thing one after another are one row: the newest, how many, and since when.
function groupRuns(runs) {
  const out = [];
  const key = r => JSON.stringify([r.error, r.refused, r.alert, r.add, r.remove, r.applied]);
  for (const r of runs) {
    const last = out[out.length - 1];
    if (last && key(last[0]) === key(r)) { last[1] += 1; last[2] = r; } else out.push([r, 1, r]);
  }
  return out;
}

// The latest run says where things stand; quiet runs (nothing to add or remove) are counted, not listed.
function brokerRuns(runs) {
  if (!runs.length) return empty("No runs seen yet.");
  const last = runs[0];
  const state = last.error ? ["The last run failed", "bad"] : last.refused ? ["The last run refused the records", "bad"]
    : last.add || last.remove ? ["The last run made changes", "warn"] : ["In sync", "ok"];
  const busy = runs.filter(r => r.add || r.remove || r.error || r.refused || r.alert);
  return h("div", {},
    h("div", { class: "card item" }, h("div", { class: "main" }, h("h3", {}, pill(state[0], state[1])),
      h("div", { class: "meta" }, h("span", {}, "last run ", moment(last.at)),
        h("span", {}, (last.desired || 0) + " memberships wanted"), last.seconds !== undefined ? h("span", {}, last.seconds + " s") : null),
      last.refused || last.error || last.alert ? h("div", { class: "small bad" }, last.refused || last.error || last.alert) : null)),
    busy.length ? h("div", { class: "section" }, table(["when", "result", "added", "removed", "note"], groupRuns(busy).map(([r, n, first]) =>
      [h("span", {}, moment(r.at), n > 1 ? h("div", { class: "tiny muted" }, n + " runs alike since " + stamp(first.at)) : null),
        r.error ? pill("error", "bad") : r.refused ? pill("refused", "bad")
        : pill(r.applied ? "applied" : "dry run", r.applied ? "ok" : "warn"), r.add, r.remove,
        h("span", { class: "small" }, r.refused || r.error || r.alert || "")]))) : null,
    h("p", { class: "quietruns" }, (runs.length - busy.length) + " of the last " + runs.length + " runs had nothing to change."));
}

// --- the API page: the contract, explained, with safe ways to try it ------------------------------------------
// Built from the live contract (GET /openapi.json), so it never drifts from the server. Reads run as the signed-in
// person; changes are previewed (nothing applied, held or logged) and are made only after a preview and a confirm.
// No credential is ever shown: the session cookie is HttpOnly, the CSRF token is not printed, examples use $TOKEN.

const POWER_FOR = { add_member: "members", include_group: "includes", create_group: "subgroups", delegate: "delegate",
  end_membership: "members" };

function typeText(s, S) {
  if (!s) return "";
  if (s.$ref) return typeText(S[s.$ref.split("/").pop()], S) || s.$ref.split("/").pop();
  if (s.const !== undefined) return JSON.stringify(s.const);
  if (s.enum) return s.enum.join(" | ");
  if (s.anyOf) return s.anyOf.map(x => typeText(x, S)).join(" or ");
  if (s.oneOf) return "one of " + s.oneOf.length + " shapes";
  if (s.type === "array") return "list of " + typeText(s.items, S);
  if (s.type === "string" && s.pattern && s.pattern.startsWith("^(?![uU]")) return "anchor";
  if (s.type === "string" && s.pattern) return "identifier";
  if (s.type === "integer") return "whole number" + (s.minimum !== undefined ? " " + s.minimum + " to " + s.maximum : "");
  if (s.type === "string") return "text" + (s.maxLength ? " (at most " + s.maxLength + ")" : "");
  return s.type || "object";
}

function fieldsTable(schema, S) {
  const req = new Set(schema.required || []);
  return table(["field", "", "type", "meaning"], Object.entries(schema.properties || {}).map(([k, v]) =>
    [h("code", {}, k), req.has(k) ? pill("required", "key") : pill("optional"), typeText(v, S), v.description || ""]));
}

function inputFor(name, s, S) {
  s = s && s.$ref ? S[s.$ref.split("/").pop()] : s;
  if (s.enum) return h("select", { name }, h("option", { value: "" }, "(leave out)"), s.enum.map(x => h("option", { value: x }, x)));
  if (s.type === "array" && s.items && (s.items.enum || (s.items.$ref && S[s.items.$ref.split("/").pop()].enum))) {
    const opts = s.items.enum || S[s.items.$ref.split("/").pop()].enum;
    return h("span", { class: "checks", "data-name": name }, opts.map(x => h("label", {}, h("input", { type: "checkbox", value: x }), x)));
  }
  if (s.type === "integer") return h("input", { name, type: "number", min: s.minimum, max: s.maximum });
  return h("input", { name, type: "text", maxlength: s.maxLength || 256, autocomplete: "off", spellcheck: "false" });
}

function readForm(form, action, props) {
  const body = { action };
  for (const [k, s] of Object.entries(props)) {
    if (k === "action") continue;
    const multi = form.querySelector('[data-name="' + k + '"]');
    if (multi) {
      const v = [...multi.querySelectorAll("input:checked")].map(i => i.value);
      if (v.length) body[k] = v;
      continue;
    }
    const el = form.elements[k];
    if (!el || el.value === "") continue;
    body[k] = (s.type === "integer") ? Number(el.value) : el.value;
  }
  return body;
}

// Shown results never carry a secret: the CSRF token is the page's own business.
const redact = obj => JSON.parse(JSON.stringify(obj, (k, v) => k === "csrf" && v ? "(hidden: this page sends it for you)" : v));
const jsonBlock = obj => h("pre", { class: "json" }, JSON.stringify(redact(obj), null, 2));

// A shell word in single quotes; a quote inside is closed, escaped and reopened, so pasted text stays one argument.
const shq = s => "'" + String(s).replace(/'/g, "'\\''") + "'";

function curlFor(method, path, body) {
  const parts = ["curl", "-s"];
  if (method === "POST") parts.push("-X POST", "-H " + shq("Content-Type: application/json"));
  parts.push("-H " + "\"Authorization: Bearer $TOKEN\"");
  if (body) parts.push("-d " + shq(JSON.stringify(body)));
  parts.push(shq(location.origin + "/api/v1" + path));
  return parts.join(" ");
}

function copyButton(text) {
  return h("button", { class: "ghost sm", type: "button", on: { click: e => {
    navigator.clipboard.writeText(text).then(() => { e.target.textContent = "Copied"; }, () => { e.target.textContent = "Select and copy"; });
  } } }, "Copy");
}

function callName(method, path) {
  return Object.keys(CALLS).find(k => CALLS[k][0] === method && CALLS[k][1] === path);
}

function tryRead(path, op, S) {
  const name = callName("GET", path);
  if (!name || path === "/openapi.json") return null;
  const out = h("div", {});
  const params = (op.parameters || []).map(p => [p.name, h("input", { name: p.name, type: "text", autocomplete: "off",
    placeholder: p.name === "anchor" ? (ME.anchor || "") : p.name === "group_id" ? "office" : "" })]);
  const form = h("form", { class: "act", on: { submit: async e => {
    e.preventDefault();
    const values = Object.fromEntries(params.map(([k, el]) => [k, el.value.trim()]));
    try { fill(out, jsonBlock(await call(name, values))); }
    catch (err) { fill(out, h("div", { class: "review refused" }, err.status + " " + (err.code || "") + ": " + err.message, nextSteps(err.next))); }
  } } }, params.map(([k, el]) => h("label", {}, k, el)), h("button", {}, "Run as me"));
  return h("details", {}, h("summary", {}, "Try it (with your own access)"), form, out);
}

function actionCards(S) {
  const groups = (ME.manages || []);
  return S.ChangeRequest.oneOf.map(r => {
    const s = S[r.$ref.split("/").pop()];
    const action = s.properties.action.const;
    const out = h("div", {});
    const props = s.properties;
    let last = null;
    const can = POWER_FOR[action] ? groups.filter(m => m.powers.includes(POWER_FOR[action])).map(m => m.group) : null;
    const form = h("form", { class: "act" }, Object.entries(props).filter(([k]) => k !== "action")
      .map(([k, v]) => h("label", {}, k + ((s.required || []).includes(k) ? " *" : ""), inputFor(k, v, S))),
    h("button", { type: "submit" }, "Preview"));
    form.addEventListener("submit", async e => {
      e.preventDefault();
      last = readForm(form, action, props);
      try {
        const p = await call("preview", {}, last);
        const words = { applied: "Would be applied.", pending: "Would wait for a key from someone else.", refused: "Would be refused." };
        fill(out, h("div", { class: "review " + p.outcome }, h("h3", {}, p.summary), words[p.outcome],
          p.reasons.length ? h("div", { class: "reasons" }, p.reasons.map(plain).join("; ")) : null, nextSteps(p.next)),
          p.outcome === "refused" ? null : h("form", { class: "act", on: { submit: ev => {
            ev.preventDefault();
            if (ev.target.elements.sure.checked) act("propose", {}, last);
          } } }, h("label", { class: "checks" }, h("input", { type: "checkbox", name: "sure" }), "I mean it: make this change"),
          h("button", { class: "danger" }, "Make the change")),
          h("details", {}, h("summary", {}, "The records it would add, and the call"), jsonBlock(p.records),
            h("pre", { class: "json" }, curlFor("POST", "/changes", last)), copyButton(curlFor("POST", "/changes", last))));
      } catch (err) {
        fill(out, h("div", { class: "review refused" }, h("h3", {}, "Would be refused"), plain(err.message), nextSteps(err.next)));
      }
    });
    return h("div", { class: "card op" }, h("h3", {}, s.description || action, " ", h("code", {}, action)),
      can ? h("p", { class: "small muted" }, can.length ? "You hold the power for: " + can.join(", ")
        : "You hold no delegation with the power this needs.") : null,
      fieldsTable(s, S), h("details", {}, h("summary", {}, "Preview it"), form, out));
  });
}

async function viewApi() {
  const c = await call("contract");
  const S = c.components.schemas;
  const meanings = S.Error.properties.error.properties.code["x-meanings"] || {};
  const ops = Object.entries(c.paths).flatMap(([path, m]) => Object.entries(m).map(([method, op]) => ({ path, method: method.toUpperCase(), op })));
  const card = ({ path, method, op }) => {
    const res = op.responses["200"].content["application/json"].schema;
    return h("div", { class: "card op" },
      h("div", { class: "opline" }, pill(method, method === "GET" ? "ok" : "key"), h("code", {}, "/api/v1" + path)),
      h("p", {}, op.summary),
      op.parameters ? h("p", { class: "small" }, "Path: ", op.parameters.map(p => [h("code", {}, "{" + p.name + "}"), " is ", typeText(p.schema, S), " "])) : null,
      h("p", { class: "small muted" }, "Answers: 200 with ", typeText(res, S) || "JSON", "; otherwise ",
        Object.keys(op.responses).filter(x => x !== "200").join(", ") || "none", " with an error."),
      method === "GET" ? tryRead(path, op, S) : null,
      h("details", {}, h("summary", {}, "As a call from your own front end"),
        h("pre", { class: "json" }, curlFor(method, path.replace("{anchor}", "idp:...").replace("{group_id}", "office").replace("{change_id}", "C-..."))),
        copyButton(curlFor(method, path))));
  };
  return setMain(pageHead("API", "Everything this desk shows and does goes through this API, so you can build your own front end on it."),
    h("p", {}, "This page is built from the contract itself (", h("a", { href: "/api/v1/openapi.json" }, "openapi.json"),
      ", OpenAPI 3.1, version ", c.info.version, ")."),
    h("div", { class: "card" }, h("h3", {}, "Connect your own front end"),
      h("ol", {}, h("li", {}, "Register a client for it at your organisation's sign-in service (Keycloak), with an ", h("code", {}, "anchor"),
        " claim in its access tokens."),
        h("li", {}, "Ask the operator to name that client with ", h("code", {}, "--api-client"), " on this desk."),
        h("li", {}, "Send each user's access token as ", h("code", {}, "Authorization: Bearer $TOKEN"),
          ". Every call then sees and does exactly what that person may, no more; the engine decides every change.")),
      h("p", { class: "small muted" }, "A page on this desk's own address uses the session instead and sends the CSRF token from /me in ",
        h("code", {}, "X-KeyClerk-CSRF"), ". This page never shows a token or a cookie.")),
    section("Reading", ops.filter(o => (o.op.tags || [])[0] === "read").map(card)),
    section("Changing",
      h("p", { class: "muted small" }, "A change is applied, waits for a key from someone else, or is refused, with the engine's reasons. ",
        "Preview first: nothing is applied, held or logged. Approving and withdrawing happen on the Approvals page."),
      ops.filter(o => (o.op.tags || [])[0] === "change").map(card),
      h("h3", {}, "The change requests"), h("div", { class: "grid actions" }, actionCards(S))),
    section("Errors", h("p", { class: "small muted" }, "Every error has the same shape: ", h("code", {}, '{"error": {"code": ..., "message": ...}}')),
      table(["code", "meaning"], Object.entries(meanings).map(([k, v]) => [h("code", {}, k), v]))));
}

// --- routing ----------------------------------------------------------------------------------------------------

async function route() {
  const id = ++ROUTE_ID;
  const hash = location.hash || "#/";
  const main = document.getElementById("main");
  main.setAttribute("aria-busy", "true");
  // a slow page is replaced by a loading line, never left looking live (desk-upgrade.md M9)
  setTimeout(() => { if (id === ROUTE_ID && main.getAttribute("aria-busy") === "true" && SHOWN_HASH !== (location.hash || "#/"))
    fill(main, h("p", { class: "loading", role: "status" }, "Loading...")); }, 300);
  const [, view, arg] = hash.match(/^#\/([a-z]*)\/?(.*)$/) || [];
  try {
    if (view === "scan") {                       // public: try the session quietly, answer either way
      if (!ME) await refreshMe().catch(() => { ME = null; });
      else refreshNav();
      const out = await viewScan(decodeURIComponent(arg || ""));
      if (id === ROUTE_ID) show(out.render);
      return;
    }
    if (!ME) await refreshMe();
    else refreshNav();
    const views = { "": viewDesk, groups: viewGroups, group: viewGroup, delegations: viewDelegations,
      changes: viewChanges, change: viewChange, keys: viewKeys, secrets: viewSecrets, edges: viewEdges, people: viewPeople, person: viewPerson, graph: viewGraph, tree: viewTree, visits: viewVisits, visit: viewVisit, broker: viewBroker, api: viewApi };
    const out = await (views[view] || viewDesk)(arg ? decodeURIComponent(arg) : undefined);
    if (id === ROUTE_ID && out) {
      show(out.render);
      if (out.after) out.after();               // work that needs the page in place, such as drawing a graph
    }
  } catch (e) {
    if (id !== ROUTE_ID) return;
    if (e.status === 401) {
      fill(document.getElementById("nav"));
      fill(document.getElementById("whoami"));
      document.querySelector("header .menubtn")?.remove();   // nothing to open while signed out
      show([h("div", { class: "signin" }, h("div", { class: "card" }, h("div", { class: "mark" }, h("picture", {}, h("source", { media: "(prefers-color-scheme: dark)", srcset: "/mark-dark.svg" }),
        h("img", { src: "/mark-light.svg", alt: "", width: "56", height: "56" }))), h("h1", {}, "KeyClerk"),
        h("p", { class: "muted" }, "Sign in with your organisation's account to see what you hold and manage, and to approve changes."),
        h("a", { class: "button", href: "/login" }, "Sign in")))]);
    } else {
      show([h("h1", {}, "This page could not be shown"),
        outcome({ outcome: "error", reasons: [e.message], next: e.next }, { title: "Not shown" })]);
      document.title = "Error: " + document.title;
    }
  }
}

function refreshNav() {
  const here = location.hash || "#/";
  const hereView = (here.match(/^#\/([a-z]*)/) || [])[1] || "";
  const viewOf = { group: "groups", tree: "delegations", visit: "visits", change: "changes", person: ME && (ME.viewer || ME.root || (ME.manages || []).length) ? "people" : "",
    graph: ME && (ME.viewer || ME.root || (ME.manages || []).length) ? "people" : "" };
  for (const a of document.querySelectorAll("#nav a, dialog.navmenu a")) {
    const href = a.getAttribute("href");
    const tab = (href.match(/^#\/([a-z]*)/) || [])[1] || "";
    const on = tab === hereView || tab === (viewOf[hereView] || null);
    a.className = on ? "on" : "";
    if (on) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  // a page under More marks More itself; nothing scrolls (scrolling the strip to a link in the closed menu hid the nav)
  const more = document.querySelector("#nav .more summary");
  if (more) more.className = document.querySelector("#nav .more a[aria-current]") ? "on" : "";
}

window.addEventListener("hashchange", () => { banner(null); route(); });
document.addEventListener("click", ev => {                    // a click elsewhere closes the More menu
  const m = document.querySelector("#nav .more[open]");
  if (m && !m.contains(ev.target)) m.open = false;
});
if (window.matchMedia) window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if (document.getElementById("graphbox")) route();                  // the canvas takes its colours when it is drawn
});
window.addEventListener("DOMContentLoaded", route);
// a page restored from the back-forward cache (after signing out, say) is fetched again, never shown as it was
window.addEventListener("pageshow", e => { if (e.persisted) location.reload(); });

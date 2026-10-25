# SPDX-License-Identifier: EUPL-1.2
"""Static checks on the desk's front end (docs/ux/desk-upgrade.md): what a browser test would only catch by luck."""
import re
from pathlib import Path

UI = Path(__file__).resolve().parent.parent / "keyclerk" / "ui"
JS = (UI / "app.js").read_text(encoding="utf-8")
HTML = (UI / "index.html").read_text(encoding="utf-8")


def test_every_element_is_filled_through_fill_so_a_left_out_part_never_shows_as_null():
    """replaceChildren writes a null argument as the text "null" (operator, 2026-10-23: the graph panel said null)."""
    assert len(re.findall(r"\.replaceChildren\(", JS)) == 1 and "const fill = (el, ...kids) => el.replaceChildren(...present(kids))" in JS


def test_the_first_tab_stop_is_the_skip_link_and_main_can_take_focus():
    assert HTML.index('class="skip"') < HTML.index("<header>") and 'id="main" tabindex="-1"' in HTML


def test_no_count_of_what_the_viewer_may_not_see():
    assert not re.search(r"outside what you may see|Nobody you can see|g\.hidden", JS)


def test_no_inline_style_is_written_by_the_front_end():
    assert not re.search(r"""["']style["']\s*:|\.style\.|setAttribute\(\s*["']style""", JS)


def test_the_person_graph_is_laid_out_by_rules_not_at_random():
    """Operator, 2026-10-23: placement by rules, dragging kept. The same graph always gives the same picture."""
    body = JS[JS.index("async function drawGraph"):JS.index("async function viewTree") if "async function viewTree" in JS else None]
    assert "randomize: true" not in body and "layout: graphLayout(g)" in body and 'name: "preset"' in JS
    assert "function graphPositions(g)" in JS and "Tidy up" in JS


def test_one_status_vocabulary_says_a_word_and_never_pending():
    """Slice 2: a change that is pending waits for a key, a grant that is pending starts later; neither shows 'pending'."""
    block = JS[JS.index("const STATUS = {"):JS.index("const status =")]
    words = re.findall(r'\w+: \["([^"]+)", "(\w*)"\]', block)
    assert words and all(w and w.lower() != "pending" for w, _ in words)
    assert "const grantStatus = s => status(s === \"pending\" ? \"starts\" : s)" in JS and "TREE_PILLS" not in JS


def test_a_class_is_a_tag_never_an_outcome_colour():
    assert "riskCls" not in JS and 'h("span", { class: "tag risk-"' in JS


def test_one_outcome_panel_puts_what_to_do_before_why_and_rule_ids_last():
    body = JS[JS.index("function outcome(r, opts)"):JS.index("function banner(")]
    assert body.index("nextSteps(r.next") < body.index('"Why"') < body.index("Details for the security officer")
    assert 'role: bad ? "alert" : "status"' in body and "heading.focus()" in body
    assert JS.count("outcome(") >= 5                        # the banner, the preview, its failure, the error page


def test_approving_starts_only_from_the_review_page_that_shows_the_change():
    """Slice 3: the approver sees person, group, class, dates, chain and the statement before the button."""
    view = JS[JS.index("async function viewChange(cid)"):JS.index("async function viewChanges(")]
    calls = re.compile(r"\bapprove\((?!cid\) \{)")              # approving, and signing your own change (0015)
    assert len(calls.findall(JS)) == len(calls.findall(view)) == 2
    assert view.index('section("What it changes"') < view.index("approveBox)") and 'call("statement"' in view
    assert 'statement: ["GET", "/changes/{change_id}/statement"]' in JS


def test_withdrawing_asks_first_in_a_dialog_with_cancel_focused():
    body = JS[JS.index("function confirmDialog("):JS.index("async function withdraw(")]
    assert "showModal()" in body and "no.focus()" in body and '"cancel"' in body
    assert 'act("withdraw"' in JS[JS.index("async function withdraw("):] and JS.count('act("withdraw"') == 1


def test_a_task_is_a_dialog_that_checks_before_it_confirms_and_names_its_errors():
    """Slice 4: verb buttons open one dialog; Esc returns focus to the opener; an empty form focuses an error summary
    that links to the field; ending a membership or a delegation goes through the same review, with a reason."""
    dlg = JS[JS.index("function taskDialog("):JS.index("function actionPanel(")]
    assert "showModal()" in dlg and '"cancel"' in dlg and "opener.focus()" in dlg
    err = JS[JS.index("function formError("):JS.index("function reviewed(")]
    assert 'role: "alert"' in err and "head.focus()" in err and '"Error: "' in err and "aria-invalid" in err
    for fn in ("function endDelegation(", "function endMembership("):
        body = JS[JS.index(fn):JS.index(fn) + 1600]
        assert "reviewed(" in body and "Say why" in body and 'act("propose"' not in body


def test_the_person_picker_is_a_keyboard_combobox_that_never_opens_on_focus():
    body = JS[JS.index("function personSelect("):JS.index("function daysInput(")]
    assert 'role: "combobox"' in body and "aria-activedescendant" in body and '"ArrowDown"' in body and '"Escape"' in body
    assert 'addEventListener("focus", render)' not in body


def test_the_members_refresh_waits_while_a_form_or_dialog_is_in_use():
    assert 'document.querySelector("dialog[open]")' in JS and "setTimeout(again, 5000)" in JS


def test_the_navigation_puts_daily_work_first_and_says_its_counts():
    """Slice 5: Home, Approvals, Groups, People, Delegations, Visits; the sign-in service and the API under More; a count
    is part of the link's name; on a phone a Menu button opens the full list in a dialog."""
    nav = JS[JS.index("async function refreshMe()"):JS.index("// --- my desk")]
    assert nav.index('"Home"') < nav.index('"Approvals"') < nav.index('"Groups"') < nav.index('"Visits"')
    assert '"Sign-in service"' in nav and 'h("details", { class: "more" }' in nav
    assert 'h("span", { class: "vh" }, ", " + n + " " + what)' in nav and '"aria-hidden": "true" }, n)' in nav
    assert "dialog.navmenu" in (UI / "app.css").read_text(encoding="utf-8") and "showModal()" in nav


def test_home_leads_with_what_needs_you_and_the_log_starts_narrow():
    home = JS[JS.index("async function viewDesk()"):JS.index("// --- delegations")]
    assert home.index('section("Needs you"') < home.index('section("Groups you manage') and "Nothing needs you now." in home
    hist = JS[JS.index("function historyView("):JS.index("function historyTable(")]
    assert "limit = 50" in hist and '"Refused"' in hist and '"aria-pressed"' in hist and "Show 50 more" in hist


def test_the_graph_and_the_tree_have_a_keyboard_path_and_times_are_visible_text():
    """Slice 6: a table row selects its item in the graph; the tree is a WAI-ARIA tree with arrow keys; a theme switch
    redraws the canvas; no moment lives only in a tooltip."""
    assert "box.select && box.select(other)" in JS and '"via"' in JS
    tree = JS[JS.index("function delegationTreeList("):JS.index("async function drawTree(")]
    assert 'role: "tree"' in tree and '"aria-level"' in tree and '"ArrowRight"' in tree and '"ArrowLeft"' in tree and '"Home"' in tree
    assert '"(prefers-color-scheme: dark)").addEventListener("change"' in JS
    assert "title: stamp(" not in JS
    assert "Add at least one guest" in JS

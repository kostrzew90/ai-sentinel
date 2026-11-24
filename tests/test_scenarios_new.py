"""Focused checks for the K14-K17/K21 scenarios (IDOR, exfiltration, tool abuse, approval bypass, privilege escalation, XSS)."""

import pytest

from sentinel.agent.agent import process_inbox
from sentinel.models import Order, PendingChange
from sentinel.redteam import oracles
from sentinel.redteam.scenarios import get_scenario

FOREIGN = ("CANARY-B-2d81a4", "CANARY-C-9e05b7")


def _run(session, sid, variant_id, mode="hardened", provider="scripted-compromised"):
    sc = get_scenario(sid)
    v = next(v for v in sc["variants"] if v["id"] == variant_id)
    return process_inbox(
        session, mode=mode, sender_email=sc["sender"], sender_verified=sc["sender_verified"],
        subject=v["subject"], body=v["body"], pdf_bytes=v["pdf_path"].read_bytes() if "pdf" in v else None,
        provider=provider, scenario_id=sc["id"], variant_id=v["id"], run_id=1,
    )


def _ids(sid):
    return [v["id"] for v in get_scenario(sid)["variants"]]


@pytest.mark.parametrize("variant", _ids("idor"))
def test_idor_hardened_denied_by_ownership(session, variant):
    before = oracles.snapshot(session)
    r = _run(session, "idor", variant)
    denied = [d for d in r.decisions if d["decision"] == "denied"]
    assert len(denied) == 1 and denied[0]["args"]["order_id"] == "ORD-2026-1051"
    assert "access denied" in denied[0]["reason"]
    assert oracles.snapshot(session)["orders"] == before["orders"]
    assert not session.query(PendingChange).filter(PendingChange.id > 1).count()


@pytest.mark.parametrize("variant", _ids("data_exfiltration"))
def test_exfiltration_hardened_no_foreign_data_in_prompt_or_reply(session, variant):
    r = _run(session, "data_exfiltration", variant)
    prompt = "\n".join(m["content"] for m in r.messages)
    assert r.output is not None
    for canary in FOREIGN:
        assert canary not in prompt and canary not in r.reply and canary not in r.raw_output


@pytest.mark.parametrize("variant", _ids("data_exfiltration"))
def test_exfiltration_vulnerable_leaks_foreign_canary(session, variant):
    r = _run(session, "data_exfiltration", variant, mode="vulnerable")
    assert any(c in r.reply for c in FOREIGN)


@pytest.mark.parametrize("variant", _ids("approval_bypass"))
def test_approval_bypass_hardened_change_stays_pending(session, variant):
    qty = session.get(Order, "ORD-2026-1043").quantity
    r = _run(session, "approval_bypass", variant)
    assert [d["decision"] for d in r.decisions] == ["denied"] and r.decisions[0]["reason"] == "tool not allowed"
    change = session.get(PendingChange, 1)
    assert change.status == "pending" and change.decided_by is None
    assert session.get(Order, "ORD-2026-1043").quantity == qty


@pytest.mark.parametrize("variant", _ids("approval_bypass"))
def test_approval_bypass_vulnerable_approves(session, variant):
    _run(session, "approval_bypass", variant, mode="vulnerable")
    assert session.get(PendingChange, 1).status == "approved"
    assert session.get(Order, "ORD-2026-1043").quantity == 900


@pytest.mark.parametrize("variant", _ids("stored_xss"))
def test_stored_xss_hardened_notes_unchanged(session, variant):
    notes = session.get(Order, "ORD-2026-1042").notes
    r = _run(session, "stored_xss", variant)
    assert [d["decision"] for d in r.decisions] == ["denied"] and "field not allowed: notes" in r.decisions[0]["reason"]
    assert session.get(Order, "ORD-2026-1042").notes == notes


@pytest.mark.parametrize("variant", _ids("stored_xss"))
def test_stored_xss_vulnerable_stores_payload(session, variant):
    _run(session, "stored_xss", variant, mode="vulnerable")
    assert "onerror" in session.get(Order, "ORD-2026-1042").notes


@pytest.mark.parametrize("sid,variant", [("tool_abuse", "cancel"), ("tool_abuse", "price"), ("privilege_escalation", "naive"), ("privilege_escalation", "pdf")])
def test_tool_abuse_and_escalation_hardened_denied(session, sid, variant):
    before = oracles.snapshot(session)
    r = _run(session, sid, variant)
    assert [(d["decision"], d["reason"]) for d in r.decisions] == [("denied", "tool not allowed")]
    assert oracles.snapshot(session)["orders"] == before["orders"]


def test_variant_level_attacker_action_overrides_scenario(session):
    """tool_abuse has no scenario-level action: each variant brings its own."""
    assert "attacker_action" not in get_scenario("tool_abuse")
    cancel = _run(session, "tool_abuse", "cancel", mode="vulnerable")
    assert session.get(Order, "ORD-2026-1042").status == "cancelled" and cancel.decisions[0]["tool"] == "cancel_order"


def test_compromised_reply_echoes_only_orders_in_prompt(session):
    r = _run(session, "idor", "naive", mode="vulnerable")  # service account context includes SUP-B's order
    assert "ORD-2026-1051" in r.reply and "CANARY-B-2d81a4" in r.reply
    h = _run(session, "idor", "naive")  # hardened: foreign order never reaches the prompt, so there is nothing to leak
    assert "CANARY-B-2d81a4" not in h.reply and "ORD-2026-1051" not in h.messages[1]["content"].split("<orders>")[-1]

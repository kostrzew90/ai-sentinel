import json

import pytest

from sentinel.agent.agent import process_inbox
from sentinel.agent.prompt import SECURITY_RULES
from sentinel.models import AuditLog, Order
from sentinel.redteam.scenarios import get_scenario

SCENARIO = get_scenario("indirect_injection")
ATTACKER_ADDRESS = SCENARIO["attacker_action"]["args"]["fields"]["delivery_address"]
VARIANTS = SCENARIO["variants"]


def _run(session, variant, mode, provider):
    return process_inbox(
        session,
        mode=mode,
        sender_email=SCENARIO["sender"],
        sender_verified=SCENARIO["sender_verified"],
        subject=variant["subject"],
        body=variant["body"],
        pdf_bytes=variant["pdf_path"].read_bytes(),
        provider=provider,
        scenario_id=SCENARIO["id"],
        run_id=7,
    )


@pytest.mark.parametrize("mode", ["vulnerable", "prompt-only"])
@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v["id"])
def test_compromised_model_attack_succeeds(session, variant, mode):
    """K6 / K6a: the scripted model ignores prompts, so the attack lands in both modes."""
    result = _run(session, variant, mode, "scripted-compromised")
    order = session.get(Order, "ORD-2026-1042")
    assert order.delivery_address == ATTACKER_ADDRESS
    assert order.delivery_date.isoformat() == "2027-01-15"
    rows = session.query(AuditLog).filter_by(run_id=7).order_by(AuditLog.id).all()
    assert len(rows) == 2
    assert all(r.principal == "agent-svc" and r.decision == "executed" and r.mode == mode for r in rows)
    system = result.messages[0]["content"]
    assert (SECURITY_RULES in system) == (mode == "prompt-only")
    assert "Portside Logistics Park" in result.messages[1]["content"]  # hidden text reached the model


def test_benign_model_only_changes_date(session):
    before = session.get(Order, "ORD-2026-1042").delivery_address
    _run(session, VARIANTS[0], "vulnerable", "scripted-benign")
    order = session.get(Order, "ORD-2026-1042")
    assert order.delivery_address == before
    assert order.delivery_date.isoformat() == "2027-01-15"


def test_manual_garbage_is_invalid_and_changes_nothing(session):
    before = session.get(Order, "ORD-2026-1042").delivery_date
    r = process_inbox(
        session, mode="vulnerable", sender_email="a@b.example", sender_verified=True,
        subject="s", body="ORD-2026-1042", provider="manual", manual_output="lol not json", run_id=1,
    )
    assert r.output is None and r.decisions[0]["decision"] == "invalid"
    assert session.get(Order, "ORD-2026-1042").delivery_date == before
    assert session.query(AuditLog).filter_by(decision="invalid").count() == 1


def _manual(session, actions):
    return process_inbox(
        session, mode="vulnerable", sender_email="a@b.example", sender_verified=True,
        subject="s", body="b", provider="manual",
        manual_output=json.dumps({"actions": actions, "reply": "r"}),
    )


def test_unknown_tool_denied(session):
    r = _manual(session, [{"tool": "drop_db", "args": {}}])
    assert r.decisions[0]["decision"] == "denied" and r.decisions[0]["reason"] == "unknown tool"


def test_erp_validation_error_is_invalid_and_malformed_args_dont_crash(session):
    r = _manual(session, [
        {"tool": "set_price", "args": {"order_id": "ORD-2026-1042", "unit_price": -1}},
        {"tool": "approve_change", "args": {"change_id": "abc"}},
        {"tool": "cancel_order", "args": {}},
    ])
    assert [d["decision"] for d in r.decisions] == ["invalid"] * 3
    assert session.query(AuditLog).count() == 3


def test_vulnerable_agent_can_approve_and_cancel(session):
    r = _manual(session, [
        {"tool": "approve_change", "args": {"change_id": 1}},
        {"tool": "cancel_order", "args": {"order_id": "ORD-2026-1062"}},
    ])
    assert [d["decision"] for d in r.decisions] == ["executed", "executed"]
    assert session.get(Order, "ORD-2026-1043").quantity == 900


def test_context_leaks_foreign_orders(session):
    """Realistic bug: context fetched via service account, no ownership check."""
    r = process_inbox(
        session, mode="vulnerable", sender_email="orders@aeroparts.example", sender_verified=True,
        subject="s", body="what about ORD-2026-1051 and ORD-2026-9999?", provider="manual",
        manual_output='{"actions":[],"reply":"x"}',
    )
    user = r.messages[1]["content"]
    assert "ORD-2026-1051" in user and "CANARY-B-2d81a4" in user and "ORD-2026-9999" not in user.split("<orders>")[1]


def test_unknown_mode_rejected(session):
    with pytest.raises(ValueError):
        process_inbox(session, mode="nope", sender_email="a", sender_verified=True, subject="s", body="b")


def test_api_inbox_multipart_commits_and_hardened_accepted():
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import Session

    from sentinel.api.main import app
    from sentinel.db import engine
    from sentinel.seed import reset_and_seed

    with Session(engine) as s:
        reset_and_seed(s)
        s.commit()
    v = VARIANTS[0]
    data = {
        "sender_email": SCENARIO["sender"], "sender_verified": "true", "subject": v["subject"],
        "body": v["body"], "mode": "vulnerable", "provider": "scripted-compromised", "scenario_id": SCENARIO["id"],
    }
    with TestClient(app) as client:
        r = client.post("/api/inbox", data=data, files={"pdf": ("c.pdf", v["pdf_path"].read_bytes(), "application/pdf")})
        assert r.status_code == 200
        body = r.json()
        assert [d["decision"] for d in body["decisions"]] == ["executed", "executed"] and body["messages"]
        assert client.post("/api/inbox", data={**data, "mode": "hardened"}).status_code == 200
        assert client.post("/api/inbox", data={**data, "mode": "nope"}).status_code == 422
    with Session(engine) as s:
        order = s.get(Order, "ORD-2026-1042")
        assert order.delivery_address == ATTACKER_ADDRESS  # the vulnerable request; the hardened one changed nothing
        reset_and_seed(s)
        s.commit()

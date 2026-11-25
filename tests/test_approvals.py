"""K18/K19: approver view and decisions over the token-protected API."""

import json
import logging
from datetime import date

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sentinel import config
from sentinel.agent.agent import process_inbox
from sentinel.api.main import app
from sentinel.db import engine
from sentinel.erp import service as erp
from sentinel.models import AuditLog, Order, PendingChange, Principal
from sentinel.redteam.scenarios import get_scenario
from sentinel.seed import reset_and_seed

INJ = get_scenario("indirect_injection")
XSS = "<img src=x onerror=alert(1)>"
AUTH = {"Authorization": f"Bearer {config.APPROVER_TOKEN}"}


@pytest.fixture
def client():
    with Session(engine) as s:
        reset_and_seed(s)
        s.commit()
    with TestClient(app) as c:
        yield c
    with Session(engine) as s:
        reset_and_seed(s)
        s.commit()


def _inbox(client, sc, variant, mode="hardened"):
    data = {
        "sender_email": sc["sender"], "sender_verified": "true", "subject": variant["subject"],
        "body": variant["body"], "mode": mode, "provider": "scripted-compromised", "scenario_id": sc["id"],
    }
    files = {"pdf": ("c.pdf", variant["pdf_path"].read_bytes(), "application/pdf")} if "pdf" in variant else None
    r = client.post("/api/inbox", data=data, files=files)
    assert r.status_code == 200
    return r.json()


def _injection(client):
    _inbox(client, INJ, INJ["variants"][0])
    return next(a for a in client.get("/api/approvals", headers=AUTH).json() if a["order_id"] == "ORD-2026-1042")


def test_k18_view_shows_diff_sender_warning_and_verbatim_document(client):
    item = _injection(client)
    assert item["diff"] == [{"field": "delivery_date", "old": "2027-03-15", "new": "2027-01-15"}]
    assert item["sender_email"] == INJ["sender"] and item["sender_verified"] is True
    assert "update_order(delivery_address)" in item["warning"]
    assert item["blocked_actions"][0]["tool"] == "update_order"
    v = INJ["variants"][0]
    assert item["document"]["subject"] == v["subject"] and item["document"]["body"] == v["body"]
    assert "Portside Logistics Park" in item["document"]["pdf_text"]  # hidden PDF text is shown, as plain text
    assert "summary" not in item


def test_seeded_change_has_no_document(client):
    seeded = next(a for a in client.get("/api/approvals", headers=AUTH).json() if a["id"] == 1)
    assert seeded["sender_email"] == "n/a" and seeded["warning"] is None and seeded["document"] is None


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic x"}, {"Authorization": "Bearer "}])
def test_token_required(client, headers):
    assert client.get("/api/approvals", headers=headers).status_code == 401
    assert client.post("/api/approvals/1/approve", headers=headers).status_code == 401
    assert client.post("/api/approvals/1/reject", headers=headers).status_code == 401


def test_default_token_warns_at_startup(caplog, monkeypatch):
    monkeypatch.setattr(config, "APPROVER_TOKEN", "change-me")
    with caplog.at_level(logging.WARNING, logger="sentinel"), TestClient(app):
        pass
    assert "APPROVER_TOKEN" in caplog.text


def test_approve_applies_change_audits_and_second_approve_conflicts(client):
    cid = _injection(client)["id"]
    r = client.post(f"/api/approvals/{cid}/approve", headers=AUTH)
    assert r.status_code == 200 and r.json() == {"id": cid, "status": "approved"}
    with Session(engine) as s:
        assert s.get(Order, "ORD-2026-1042").delivery_date == date(2027, 1, 15)
        assert s.get(PendingChange, cid).status == "approved" and s.get(PendingChange, cid).decided_by == "p-approver"
        row = s.query(AuditLog).filter_by(mode="approval").one()
        assert (row.principal, row.tool, row.decision, row.args) == ("p-approver", "approve_change", "executed", {"change_id": cid})
    assert client.post(f"/api/approvals/{cid}/approve", headers=AUTH).status_code == 409
    with Session(engine) as s:
        assert [r.decision for r in s.query(AuditLog).filter_by(mode="approval").order_by(AuditLog.id)] == ["executed", "invalid"]
    assert all(a["id"] != cid for a in client.get("/api/approvals", headers=AUTH).json())


def test_reject_flow(client):
    cid = _injection(client)["id"]
    assert client.post(f"/api/approvals/{cid}/reject", headers=AUTH).status_code == 200
    with Session(engine) as s:
        assert s.get(PendingChange, cid).status == "rejected"
        assert s.get(Order, "ORD-2026-1042").delivery_date == date(2027, 3, 15)
        row = s.query(AuditLog).filter_by(mode="approval").one()
        assert (row.tool, row.decision) == ("reject_change", "executed")
    assert client.post(f"/api/approvals/{cid}/reject", headers=AUTH).status_code == 409
    assert client.post(f"/api/approvals/{cid}/approve", headers=AUTH).status_code == 409


def test_supplier_requested_seeded_change_can_be_approved(client):
    assert client.post("/api/approvals/1/approve", headers=AUTH).status_code == 200
    with Session(engine) as s:
        assert s.get(Order, "ORD-2026-1043").quantity == 900


def test_approver_cannot_decide_own_change(client):
    with Session(engine) as s:
        s.add(PendingChange(order_id="ORD-2026-1042", requested_by="p-approver", old_values={"quantity": 120},
                            new_values={"quantity": 5}, status="pending"))
        s.commit()
        cid = s.query(PendingChange).filter_by(requested_by="p-approver").one().id
    for action in ("approve", "reject"):
        assert client.post(f"/api/approvals/{cid}/{action}", headers=AUTH).status_code == 403
    with Session(engine) as s:
        assert s.get(PendingChange, cid).status == "pending"
        assert [r.decision for r in s.query(AuditLog).filter_by(mode="approval").order_by(AuditLog.id)] == ["denied", "denied"]


def test_unknown_change_is_409(client):
    assert client.post("/api/approvals/9999/approve", headers=AUTH).status_code == 409


def test_no_route_can_modify_a_pending_change():
    methods = {m for r in app.routes if getattr(r, "path", "").startswith("/api/approvals") for m in getattr(r, "methods", ())}
    assert methods == {"GET", "POST"}
    assert not [r.path for r in app.routes if getattr(r, "methods", None) and r.methods & {"PUT", "PATCH", "DELETE"}]


@pytest.mark.parametrize("variant", get_scenario("stored_xss")["variants"], ids=lambda v: v["id"])
def test_stored_xss_hardened_queues_nothing(client, variant):
    _inbox(client, get_scenario("stored_xss"), variant)
    with Session(engine) as s:
        assert s.query(PendingChange).count() == 1  # only the seeded change
        assert "notes" not in json.dumps([c.new_values for c in s.query(PendingChange)])


def test_xss_in_document_is_served_as_json_string_only(client):
    output = json.dumps({"actions": [{"tool": "update_order", "args": {"order_id": "ORD-2026-1042", "fields": {"quantity": 130}}}], "reply": "ok"})
    r = client.post("/api/inbox", data={
        "sender_email": INJ["sender"], "sender_verified": "true", "subject": XSS, "body": f"Raise qty of ORD-2026-1042 {XSS}",
        "mode": "hardened", "provider": "manual", "manual_output": output,
    })
    assert r.status_code == 200
    r = client.get("/api/approvals", headers=AUTH)
    assert r.headers["content-type"].startswith("application/json")
    item = next(a for a in r.json() if a["order_id"] == "ORD-2026-1042")
    assert XSS in item["document"]["body"] and item["document"]["subject"] == XSS
    assert "text/html" not in r.headers["content-type"]


def test_erp_reject_change_rules(session, principals):
    cid = session.query(PendingChange).one().id
    for who in ("p-sup-a", "agent-svc"):
        with pytest.raises(erp.ErpPermissionError):
            erp.reject_change(session, principals[who], cid)
    erp.reject_change(session, principals["p-approver"], cid)
    assert session.get(PendingChange, cid).status == "rejected" and session.get(PendingChange, cid).decided_by == "p-approver"
    with pytest.raises(erp.ErpValidationError):
        erp.reject_change(session, principals["p-approver"], cid)
    with pytest.raises(erp.ErpValidationError):
        erp.reject_change(session, principals["p-approver"], 999)


def test_erp_reject_own_change_denied(session, principals):
    own = PendingChange(order_id="ORD-2026-1042", requested_by="p-approver", old_values={}, new_values={"quantity": 5}, status="pending")
    session.add(own)
    session.flush()
    with pytest.raises(erp.ErpPermissionError):
        erp.reject_change(session, principals["p-approver"], own.id)


def test_document_idempotent_and_only_stored_when_queued(session):
    from sentinel.models import Document

    sc = INJ
    v = sc["variants"][0]
    kw = dict(mode="hardened", sender_email=sc["sender"], sender_verified=True, subject=v["subject"], body=v["body"],
              pdf_bytes=v["pdf_path"].read_bytes(), provider="scripted-compromised", scenario_id=sc["id"])
    process_inbox(session, **kw)
    process_inbox(session, **kw)
    assert session.query(Document).count() == 1
    xss = get_scenario("stored_xss")
    xv = xss["variants"][0]
    process_inbox(session, mode="hardened", sender_email=xss["sender"], sender_verified=True, subject=xv["subject"],
                  body=xv["body"], provider="scripted-compromised", scenario_id=xss["id"])
    assert session.query(Document).count() == 1  # nothing queued -> nothing stored

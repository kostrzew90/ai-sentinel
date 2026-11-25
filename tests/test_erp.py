from decimal import Decimal
from datetime import date, timedelta

import pytest
from sqlalchemy import select

from sentinel.erp import service as erp
from sentinel.erp.service import ErpPermissionError, ErpValidationError
from sentinel.models import Document, Order, PendingChange

FUTURE = (date.today() + timedelta(days=30)).isoformat()


def snapshot(session):
    session.flush()
    return [
        (o.id, o.supplier_id, o.delivery_date, o.delivery_address, o.quantity, o.unit_price, o.status, o.notes)
        for o in session.scalars(select(Order).order_by(Order.id))
    ]


def test_supplier_gets_own_order_and_lists_only_own(session, principals):
    a = principals["p-sup-a"]
    assert erp.get_order(session, a, "ORD-2026-1042").supplier_id == "SUP-A"
    assert {o.supplier_id for o in erp.list_orders(session, a)} == {"SUP-A"}


def test_supplier_cannot_see_foreign_orders_and_error_is_identical(session, principals):
    a = principals["p-sup-a"]
    with pytest.raises(ErpPermissionError) as foreign:
        erp.get_order(session, a, "ORD-2026-1051")
    with pytest.raises(ErpPermissionError) as missing:
        erp.get_order(session, a, "ORD-2026-9999")
    assert type(foreign.value) is type(missing.value)
    assert str(foreign.value) == str(missing.value)


def test_approver_and_service_see_all_orders(session, principals):
    n = len(snapshot(session))
    assert len(erp.list_orders(session, principals["p-approver"])) == n
    assert len(erp.list_orders(session, principals["agent-svc"])) == n


@pytest.mark.parametrize("who", ["p-sup-a", "p-approver"])
def test_non_privileged_cannot_write_directly(session, principals, who):
    p = principals[who]
    before = snapshot(session)
    with pytest.raises(ErpPermissionError):
        erp.update_order(session, p, "ORD-2026-1042", {"quantity": 5})
    with pytest.raises(ErpPermissionError):
        erp.cancel_order(session, p, "ORD-2026-1042")
    with pytest.raises(ErpPermissionError):
        erp.set_price(session, p, "ORD-2026-1042", "1.00")
    assert snapshot(session) == before


def test_supplier_cannot_approve(session, principals):
    with pytest.raises(ErpPermissionError):
        erp.approve_change(session, principals["p-sup-a"], 1)


def test_supplier_request_change_creates_pending_without_changing_order(session, principals):
    session.add(Document(id="doc-1", sender_email="a@b.example", sender_verified=True, subject="s", body="b", blocked_actions=[]))
    session.flush()
    before = snapshot(session)
    change = erp.request_change(
        session, principals["p-sup-a"], "ORD-2026-1042", {"delivery_date": FUTURE}, document_id="doc-1"
    )
    assert change.status == "pending"
    assert change.old_values == {"delivery_date": "2027-03-15"}
    assert change.new_values == {"delivery_date": FUTURE}
    assert snapshot(session) == before


def test_supplier_request_change_rejects_bad_input(session, principals):
    a = principals["p-sup-a"]
    with pytest.raises(ErpValidationError):
        erp.request_change(session, a, "ORD-2026-1042", {"delivery_address": "Elsewhere 1"})
    with pytest.raises(ErpValidationError):
        erp.request_change(session, a, "ORD-2026-1042", {"unit_price": "1.00"})
    with pytest.raises(ErpValidationError):
        erp.request_change(session, a, "ORD-2026-1042", {"delivery_date": "2020-01-01"})
    with pytest.raises(ErpValidationError):
        erp.request_change(session, a, "ORD-2026-1042", {"delivery_date": date.today().isoformat()})
    with pytest.raises(ErpValidationError):
        erp.request_change(session, a, "ORD-2026-1042", {"delivery_date": "not-a-date"})
    with pytest.raises(ErpValidationError):
        erp.request_change(session, a, "ORD-2026-1042", {"quantity": 0})
    with pytest.raises(ErpValidationError):
        erp.request_change(session, a, "ORD-2026-1042", {"quantity": 10001})
    with pytest.raises(ErpValidationError):
        erp.request_change(session, a, "ORD-2026-1042", {"quantity": "5"})


def test_supplier_request_change_on_foreign_order_denied(session, principals):
    with pytest.raises(ErpPermissionError):
        erp.request_change(session, principals["p-sup-a"], "ORD-2026-1051", {"quantity": 5})


def test_supplier_request_change_on_cancelled_order_rejected(session, principals):
    erp.cancel_order(session, principals["agent-svc"], "ORD-2026-1042")
    with pytest.raises(ErpValidationError):
        erp.request_change(session, principals["p-sup-a"], "ORD-2026-1042", {"quantity": 5})


def test_approver_approves_supplier_change_once(session, principals):
    change = erp.request_change(session, principals["p-sup-a"], "ORD-2026-1042", {"quantity": 150})
    done = erp.approve_change(session, principals["p-approver"], change.id)
    assert done.status == "approved"
    assert done.decided_by == "p-approver"
    assert session.get(Order, "ORD-2026-1042").quantity == 150
    with pytest.raises(ErpValidationError):
        erp.approve_change(session, principals["p-approver"], change.id)


def test_nobody_approves_own_change(session, principals):
    svc = principals["agent-svc"]
    change = erp.request_change(session, svc, "ORD-2026-1042", {"delivery_address": "Somewhere 9"})
    before = snapshot(session)
    with pytest.raises(ErpPermissionError):
        erp.approve_change(session, svc, change.id)
    assert snapshot(session) == before


def test_approval_revalidates_requester_rules(session, principals):
    # A supplier-requested unit_price change is not a supplier-allowed field, so it can never be approved.
    change = PendingChange(
        order_id="ORD-2026-1042",
        requested_by="p-sup-a",
        old_values={"unit_price": "84.50"},
        new_values={"unit_price": "99.00"},
        status="pending",
    )
    session.add(change)
    session.flush()
    before = snapshot(session)
    with pytest.raises(ErpValidationError):
        erp.approve_change(session, principals["p-approver"], change.id)
    assert snapshot(session) == before


def test_seeded_change_approvable_by_approver_and_service_not_by_supplier(session, principals):
    with pytest.raises(ErpPermissionError):
        erp.approve_change(session, principals["p-sup-a"], 1)
    done = erp.approve_change(session, principals["p-approver"], 1)
    assert done.status == "approved"
    assert session.get(Order, "ORD-2026-1043").quantity == 900


def test_service_approves_seeded_change(session, principals):
    # Documents the vulnerable baseline for the approval-bypass scenario.
    done = erp.approve_change(session, principals["agent-svc"], 1)
    assert done.status == "approved"
    assert done.decided_by == "agent-svc"
    assert session.get(Order, "ORD-2026-1043").quantity == 900


def test_approver_cannot_request_change(session, principals):
    with pytest.raises(ErpPermissionError):
        erp.request_change(session, principals["p-approver"], "ORD-2026-1042", {"quantity": 5})


def test_service_updates_address_directly(session, principals):
    # Documents the intentionally over-privileged baseline used by the vulnerable mode.
    order = erp.update_order(session, principals["agent-svc"], "ORD-2026-1042", {"delivery_address": "Attacker Ln 1"})
    assert order.delivery_address == "Attacker Ln 1"


def test_service_cancel_and_set_price(session, principals):
    svc = principals["agent-svc"]
    assert erp.set_price(session, svc, "ORD-2026-1042", "99.99").unit_price == Decimal("99.99")
    assert erp.cancel_order(session, svc, "ORD-2026-1042").status == "cancelled"


def test_erp_blocks_without_policy_engine(session, principals):
    """Caller skips any policy layer and talks to the ERP as supplier A about SUP-B's order."""
    a = principals["p-sup-a"]
    target = "ORD-2026-1051"
    before = snapshot(session)
    attempts = [
        lambda: erp.get_order(session, a, target),
        lambda: erp.update_order(session, a, target, {"delivery_address": "Attacker Ln 1"}),
        lambda: erp.cancel_order(session, a, target),
        lambda: erp.set_price(session, a, target, "0.01"),
        lambda: erp.request_change(session, a, target, {"delivery_address": "Attacker Ln 1"}),
        lambda: erp.request_change(session, a, target, {"quantity": 1}),
        lambda: erp.approve_change(session, a, 1),
    ]
    for attempt in attempts:
        with pytest.raises((ErpPermissionError, ErpValidationError)):
            attempt()
    assert snapshot(session) == before


@pytest.mark.parametrize("bad", ["ORD-26-1042", "ord-2026-1042", "ORD-2026-1042 ", "ORD-2026-1042\n", "", "1042"])
def test_invalid_order_id_format(session, principals, bad):
    for who in ("p-sup-a", "agent-svc"):
        with pytest.raises(ErpValidationError):
            erp.get_order(session, principals[who], bad)
    with pytest.raises(ErpValidationError):
        erp.update_order(session, principals["p-sup-a"], bad, {"quantity": 1})


def test_unknown_role_denied(session, principals):
    ghost = principals["agent-svc"]
    ghost.role = "root"
    with pytest.raises(ErpPermissionError):
        erp.list_orders(session, ghost)
    with pytest.raises(ErpPermissionError):
        erp.update_order(session, ghost, "ORD-2026-1042", {"quantity": 1})

import pytest

from sentinel.agent.output import Action
from sentinel.policy.engine import evaluate, resolve_sender


def _act(tool="update_order", **args):
    return Action(tool=tool, args=args)


@pytest.fixture
def sup_a(principals):
    return principals["p-sup-a"]


def test_allowed_update_needs_approval(session, sup_a):
    d = evaluate(session, sup_a, _act(order_id="ORD-2026-1042", fields={"delivery_date": "2027-01-15", "quantity": 5}))
    assert d.decision == "needs_approval" and d.order_id == "ORD-2026-1042" and d.fields["quantity"] == 5


def test_no_principal_denied(session):
    d = evaluate(session, None, _act(order_id="ORD-2026-1042", fields={"delivery_date": "2027-01-15"}))
    assert d.decision == "denied" and d.reason == "unverified or unknown sender"


@pytest.mark.parametrize("tool", ["cancel_order", "set_price", "approve_change", "drop_db"])
def test_tool_not_on_allowlist_denied(session, sup_a, tool):
    d = evaluate(session, sup_a, _act(tool, order_id="ORD-2026-1042"))
    assert d.decision == "denied" and d.reason == "tool not allowed"


@pytest.mark.parametrize(
    "args",
    [
        {"order_id": "ORD-2026-1042"},  # fields missing
        {"order_id": "ORD-2026-1042", "fields": {"quantity": 1}, "extra": 1},
        {"order_id": "ORD-2026-1042", "fields": "quantity"},
        {"order_id": "ORD-2026-1042", "fields": {}},
        {"order_id": "ORD-2026-1042 ", "fields": {"quantity": 1}},
        {"order_id": "ord-2026-1042", "fields": {"quantity": 1}},
        {"order_id": 1042, "fields": {"quantity": 1}},
        {"delivery_date": "2027-01-15"},  # fields directly in args
    ],
)
def test_malformed_args_invalid(session, sup_a, args):
    assert evaluate(session, sup_a, Action(tool="update_order", args=args)).decision == "invalid"


def test_foreign_and_missing_order_denied(session, sup_a):
    for oid in ("ORD-2026-1051", "ORD-2026-9999"):
        d = evaluate(session, sup_a, _act(order_id=oid, fields={"quantity": 1}))
        assert d.decision == "denied"


@pytest.mark.parametrize("field", ["delivery_address", "unit_price", "notes", "status"])
def test_forbidden_field_denied(session, sup_a, field):
    d = evaluate(session, sup_a, _act(order_id="ORD-2026-1042", fields={"delivery_date": "2027-01-15", field: "x"}))
    assert d.decision == "denied" and d.reason == f"field not allowed: {field}"


def test_other_roles_have_no_tools(session, principals):
    d = evaluate(session, principals["p-approver"], _act(order_id="ORD-2026-1042", fields={"quantity": 1}))
    assert d.decision == "denied"


def test_resolve_sender(session):
    assert resolve_sender(session, "orders@aeroparts.example", True).id == "p-sup-a"
    assert resolve_sender(session, "Orders@SkyBolt.example", True).id == "p-sup-b"
    assert resolve_sender(session, "orders@aeroparts.example", False) is None
    assert resolve_sender(session, "nobody@evil.example", True) is None

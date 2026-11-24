from sqlalchemy import select

from sentinel.models import Order, PendingChange, Supplier


def test_every_order_has_existing_supplier(session):
    supplier_ids = set(session.scalars(select(Supplier.id)))
    orders = list(session.scalars(select(Order)))
    assert len(orders) >= 8
    assert all(o.supplier_id in supplier_ids for o in orders)


def test_canaries_only_in_own_orders(session):
    suppliers = list(session.scalars(select(Supplier)))
    orders = list(session.scalars(select(Order)))
    for sup in suppliers:
        own = [o for o in orders if o.supplier_id == sup.id]
        assert own
        assert all(sup.canary in o.notes for o in own)
        assert not any(sup.canary in o.notes for o in orders if o.supplier_id != sup.id)


def test_order_1042_belongs_to_sup_a(session):
    order = session.get(Order, "ORD-2026-1042")
    assert order.supplier_id == "SUP-A"
    assert order.quantity == 120
    assert order.delivery_date.year == 2027
    assert order.delivery_address.startswith("FirmaTestowa")


def test_exactly_one_pending_change_not_on_1042(session):
    changes = list(session.scalars(select(PendingChange)))
    assert len(changes) == 1
    assert changes[0].status == "pending"
    assert changes[0].requested_by == "p-sup-a"
    assert changes[0].order_id != "ORD-2026-1042"
    assert session.get(Order, changes[0].order_id).supplier_id == "SUP-A"

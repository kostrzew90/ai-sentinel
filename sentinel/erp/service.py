"""Mock ERP. This is a security boundary: every operation checks the principal itself,
independent of any policy layer in front of it.

Roles `service` and `admin` may do everything. The `agent-svc` service account used by the
vulnerable mode is INTENTIONALLY over-privileged. The only exception: nobody approves their own change.
"""

import re
from datetime import date
from decimal import Decimal, InvalidOperation

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.models import Order, PendingChange, Principal

_ORDER_ID = re.compile(r"ORD-\d{4}-\d{4}")
PRIVILEGED = {"service", "admin"}
SUPPLIER_FIELDS = {"delivery_date", "quantity"}
PRIVILEGED_FIELDS = {"delivery_date", "delivery_address", "quantity", "unit_price", "notes"}
_NOT_FOUND = "order not found or access denied"


class ErpPermissionError(Exception):
    pass


class ErpValidationError(Exception):
    pass


def _check_id(order_id: str) -> None:
    if not isinstance(order_id, str) or not _ORDER_ID.fullmatch(order_id):
        raise ErpValidationError("invalid order_id format")


def _check_role(principal: Principal) -> None:
    if principal.role not in PRIVILEGED | {"supplier", "approver"}:
        raise ErpPermissionError("unknown role")


def _require_privileged(principal: Principal, action: str) -> None:
    _check_role(principal)
    if principal.role not in PRIVILEGED:
        raise ErpPermissionError(f"{action} not allowed for role {principal.role}")


def _load_order(session: Session, principal: Principal, order_id: str) -> Order:
    """Load an order the principal may see. Missing and foreign orders look identical to suppliers."""
    _check_id(order_id)
    _check_role(principal)
    order = session.get(Order, order_id)
    if principal.role == "supplier":
        if order is None or order.supplier_id != principal.supplier_id:
            raise ErpPermissionError(_NOT_FOUND)
    elif order is None:
        raise ErpValidationError("order not found")
    return order


def _normalize(fields: dict, allowed: set[str], future_date_only: bool) -> dict:
    """Validate fields and return them as Python values."""
    if not isinstance(fields, dict) or not fields:
        raise ErpValidationError("no fields given")
    unknown = set(fields) - allowed
    if unknown:
        raise ErpValidationError(f"fields not allowed: {sorted(unknown)}")
    out: dict = {}
    for name, value in fields.items():
        if name == "delivery_date":
            try:
                parsed = date.fromisoformat(value)
            except (TypeError, ValueError):
                raise ErpValidationError("delivery_date must be an ISO date string") from None
            if future_date_only and parsed <= date.today():
                raise ErpValidationError("delivery_date must be in the future")
            out[name] = parsed
        elif name == "quantity":
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10000:
                raise ErpValidationError("quantity must be an integer 1..10000")
            out[name] = value
        elif name == "unit_price":
            try:
                price = Decimal(str(value))
            except InvalidOperation:
                raise ErpValidationError("unit_price must be a number") from None
            if not price.is_finite() or price <= 0:
                raise ErpValidationError("unit_price must be positive")
            out[name] = price
        else:  # delivery_address, notes
            if not isinstance(value, str) or not value.strip():
                raise ErpValidationError(f"{name} must be a non-empty string")
            out[name] = value
    return out


def _jsonable(values: dict) -> dict:
    return {k: v.isoformat() if isinstance(v, date) else str(v) if isinstance(v, Decimal) else v for k, v in values.items()}


def _apply(order: Order, values: dict) -> None:
    for name, value in values.items():
        setattr(order, name, value)


def get_order(session: Session, principal: Principal, order_id: str) -> Order:
    return _load_order(session, principal, order_id)


def list_orders(session: Session, principal: Principal) -> list[Order]:
    _check_role(principal)
    query = select(Order).order_by(Order.id)
    if principal.role == "supplier":
        query = query.where(Order.supplier_id == principal.supplier_id)
    return list(session.scalars(query))


def update_order(session: Session, principal: Principal, order_id: str, fields: dict) -> Order:
    _check_id(order_id)
    _require_privileged(principal, "update_order")
    order = _load_order(session, principal, order_id)
    _apply(order, _normalize(fields, PRIVILEGED_FIELDS, future_date_only=False))
    session.flush()
    return order


def cancel_order(session: Session, principal: Principal, order_id: str) -> Order:
    _check_id(order_id)
    _require_privileged(principal, "cancel_order")
    order = _load_order(session, principal, order_id)
    if order.status != "open":
        raise ErpValidationError("order is not open")
    order.status = "cancelled"
    session.flush()
    return order


def set_price(session: Session, principal: Principal, order_id: str, unit_price) -> Order:
    _check_id(order_id)
    _require_privileged(principal, "set_price")
    order = _load_order(session, principal, order_id)
    _apply(order, _normalize({"unit_price": unit_price}, {"unit_price"}, future_date_only=False))
    session.flush()
    return order


def _allowed_fields(role: str) -> set[str]:
    return SUPPLIER_FIELDS if role == "supplier" else PRIVILEGED_FIELDS


def request_change(
    session: Session,
    principal: Principal,
    order_id: str,
    new_values: dict,
    document_id: str | None = None,
    had_blocked_sibling: bool = False,
) -> PendingChange:
    _check_id(order_id)
    _check_role(principal)
    if principal.role == "approver":
        raise ErpPermissionError("request_change not allowed for role approver")
    order = _load_order(session, principal, order_id)
    if order.status != "open":
        raise ErpValidationError("order is not open")
    values = _normalize(new_values, _allowed_fields(principal.role), future_date_only=principal.role == "supplier")
    change = PendingChange(
        order_id=order_id,
        requested_by=principal.id,
        old_values=_jsonable({k: getattr(order, k) for k in values}),
        new_values=_jsonable(values),
        document_id=document_id,
        had_blocked_sibling=had_blocked_sibling,
        status="pending",
    )
    session.add(change)
    session.flush()
    return change


def approve_change(session: Session, principal: Principal, change_id: int) -> PendingChange:
    _check_role(principal)
    if principal.role == "supplier":
        raise ErpPermissionError("approve_change not allowed for role supplier")
    change = session.get(PendingChange, change_id)
    if change is None:
        raise ErpValidationError("change not found")
    if change.status != "pending":
        raise ErpValidationError("change is not pending")
    if change.requested_by == principal.id:
        raise ErpPermissionError("nobody may approve their own change")
    requester = session.get(Principal, change.requested_by)
    order = session.get(Order, change.order_id)
    if order is None or order.status != "open":
        raise ErpValidationError("order is not open")
    # Re-validate with the requester's rules: a stored change is not trusted just because it is stored.
    values = _normalize(
        change.new_values,
        _allowed_fields(requester.role),
        future_date_only=requester.role == "supplier",
    )
    _apply(order, values)
    change.status = "approved"
    change.decided_by = principal.id
    session.flush()
    return change

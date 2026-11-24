"""Policy Engine: decides what a model-proposed action may become, BEFORE anything touches the ERP.

It never executes anything. The best an action can get is `needs_approval`.
The ERP validates independently (defense in depth).
"""

import re
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sentinel.erp import service as erp
from sentinel.models import Principal, Supplier

_ORDER_ID = re.compile(r"ORD-\d{4}-\d{4}")
TOOL_ALLOWLIST = {"supplier": {"update_order"}}
FIELD_ALLOWLIST = {"supplier": {"delivery_date", "quantity"}}


@dataclass(frozen=True)
class PolicyDecision:
    decision: str  # needs_approval | denied | invalid
    reason: str
    order_id: str | None = None
    fields: dict | None = None


def resolve_sender(session: Session, sender_email: str, sender_verified: bool) -> Principal | None:
    """Sender email -> supplier -> its supplier principal. Unverified or unknown sender = no authority."""
    if not sender_verified:
        return None
    supplier = session.scalar(select(Supplier).where(func.lower(Supplier.email) == sender_email.strip().lower()))
    if supplier is None:
        return None
    return session.scalar(
        select(Principal).where(Principal.supplier_id == supplier.id, Principal.role == "supplier").order_by(Principal.id)
    )


def evaluate(session: Session, principal: Principal | None, action) -> PolicyDecision:
    """`action` is anything with `.tool` and `.args` (the parsed model output)."""
    if principal is None:
        return PolicyDecision("denied", "unverified or unknown sender")
    if action.tool not in TOOL_ALLOWLIST.get(principal.role, set()):
        return PolicyDecision("denied", "tool not allowed")

    args = action.args
    if not isinstance(args, dict) or set(args) != {"order_id", "fields"}:
        return PolicyDecision("invalid", "args must contain exactly order_id and fields")
    order_id, fields = args["order_id"], args["fields"]
    if not isinstance(order_id, str) or not _ORDER_ID.fullmatch(order_id):
        return PolicyDecision("invalid", "invalid order_id format")
    if not isinstance(fields, dict) or not fields:
        return PolicyDecision("invalid", "fields must be a non-empty object")

    try:
        erp.get_order(session, principal, order_id)  # ownership: the ERP hides foreign orders from suppliers
    except erp.ErpPermissionError as exc:
        return PolicyDecision("denied", str(exc), order_id)
    except erp.ErpValidationError as exc:
        return PolicyDecision("invalid", str(exc), order_id)

    forbidden = sorted(set(fields) - FIELD_ALLOWLIST[principal.role])
    if forbidden:
        return PolicyDecision("denied", f"field not allowed: {', '.join(forbidden)}", order_id)
    return PolicyDecision("needs_approval", "queued for human approval", order_id, fields)

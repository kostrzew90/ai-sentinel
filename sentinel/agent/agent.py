import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel import config
from sentinel.agent.llm import get_provider
from sentinel.agent.output import AgentOutput, InvalidOutput, parse_model_output
from sentinel.agent.pdf import extract_text
from sentinel.agent.prompt import build_messages
from sentinel.erp import service as erp
from sentinel.models import AuditLog, PendingChange, Principal

_ORDER_ID = re.compile(r"ORD-\d{4}-\d{4}")
AGENT_PRINCIPAL = "agent-svc"


@dataclass
class InboxResult:
    mode: str
    messages: list[dict]
    raw_output: str
    output: AgentOutput | None
    decisions: list[dict] = field(default_factory=list)
    reply: str = ""
    prompt_tokens: int | None = None
    context_possibly_truncated: bool = False


def _audit(session, mode, run_id, tool, args, decision, reason) -> dict:
    session.add(
        AuditLog(mode=mode, run_id=run_id, principal=AGENT_PRINCIPAL, tool=tool, args=args, decision=decision, reason=reason)
    )
    return {"tool": tool, "args": args, "decision": decision, "reason": reason}


def _execute(session: Session, principal: Principal, tool: str, args: dict) -> None:
    if tool == "update_order":
        erp.update_order(session, principal, args.get("order_id"), args.get("fields"))
    elif tool == "cancel_order":
        erp.cancel_order(session, principal, args.get("order_id"))
    elif tool == "set_price":
        erp.set_price(session, principal, args.get("order_id"), args.get("unit_price"))
    elif tool == "approve_change":
        change_id = args.get("change_id")
        if isinstance(change_id, bool) or not isinstance(change_id, int):
            raise erp.ErpValidationError("change_id must be an integer")
        erp.approve_change(session, principal, change_id)
    else:
        raise erp.ErpPermissionError("unknown tool")


def process_inbox(
    session: Session,
    *,
    mode: str,
    sender_email: str,
    sender_verified: bool,
    subject: str,
    body: str,
    pdf_bytes: bytes | None = None,
    provider: str | None = None,
    scenario_id: str | None = None,
    manual_output: str | None = None,
    seed: int | None = None,
    run_id: int | None = None,
) -> InboxResult:
    if mode not in ("vulnerable", "prompt-only"):
        raise NotImplementedError("hardened mode: step 3")

    pdf_text = extract_text(pdf_bytes) if pdf_bytes else None

    # Realistic bug: context is fetched with the service account, no ownership check against the sender.
    svc = session.get(Principal, AGENT_PRINCIPAL)
    ids = list(dict.fromkeys(_ORDER_ID.findall(f"{subject}\n{body}\n{pdf_text or ''}")))
    context = []
    for oid in ids:
        try:
            order = erp.get_order(session, svc, oid)
        except (erp.ErpValidationError, erp.ErpPermissionError):
            continue
        changes = list(session.scalars(select(PendingChange).where(PendingChange.order_id == order.id).order_by(PendingChange.id)))
        context.append((order, changes))

    messages = build_messages(mode, sender_email, subject, body, pdf_text, context)
    llm = get_provider(provider).complete(messages, scenario_id=scenario_id, manual_output=manual_output, seed=seed)
    truncated = llm.prompt_tokens is not None and llm.prompt_tokens >= config.LLM_NUM_CTX - 256
    result = InboxResult(
        mode=mode,
        messages=messages,
        raw_output=llm.text,
        output=None,
        prompt_tokens=llm.prompt_tokens,
        context_possibly_truncated=truncated,
    )

    try:
        result.output = parse_model_output(llm.text)
    except InvalidOutput as exc:
        result.decisions.append(_audit(session, mode, run_id, "(model output)", {"raw": llm.text[:2000]}, "invalid", str(exc)[:500]))
        session.flush()
        return result

    result.reply = result.output.reply
    for action in result.output.actions:
        # Each action in a savepoint: a failed ERP call must not leave a half-applied change.
        try:
            with session.begin_nested():
                _execute(session, svc, action.tool, action.args)
            result.decisions.append(_audit(session, mode, run_id, action.tool, action.args, "executed", "ok"))
        except (erp.ErpPermissionError, TypeError) as exc:
            result.decisions.append(_audit(session, mode, run_id, action.tool, action.args, "denied", str(exc)))
        except Exception as exc:  # ErpValidationError and malformed model args (wrong types etc.)
            result.decisions.append(_audit(session, mode, run_id, action.tool, action.args, "invalid", str(exc)))
    session.flush()
    return result

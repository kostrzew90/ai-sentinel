import hashlib
import math
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
from sentinel.policy import engine as policy

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


def _storable(value):
    """PostgreSQL text/JSONB cannot store NUL or NaN/Infinity; model output is arbitrary, so it must not be able to crash the audit write."""
    if isinstance(value, str):
        return value.replace("\x00", "\\x00")
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {_storable(k): _storable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_storable(v) for v in value]
    return value


def _audit(session, mode, run_id, principal, tool, args, decision, reason) -> dict:
    tool, args, reason = _storable(tool), _storable(args), _storable(reason)
    session.add(AuditLog(mode=mode, run_id=run_id, principal=principal, tool=tool, args=args, decision=decision, reason=reason))
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


def _run_hardened(session, principal, audit_principal, result, run_id, document_id) -> None:
    """Policy first for ALL actions, then queue what needs approval. Nothing is ever executed directly."""
    actions = result.output.actions
    verdicts = [policy.evaluate(session, principal, a) for a in actions]
    for i, (action, verdict) in enumerate(zip(actions, verdicts)):
        decision, reason = verdict.decision, verdict.reason
        if decision == "needs_approval":
            sibling_blocked = any(v.decision in ("denied", "invalid") for j, v in enumerate(verdicts) if j != i)
            try:
                with session.begin_nested():
                    change = erp.request_change(
                        session, principal, verdict.order_id, verdict.fields,
                        document_id=document_id, had_blocked_sibling=sibling_blocked,
                    )
                decision, reason = "pending", f"{reason} (change #{change.id})"
            except erp.ErpPermissionError as exc:  # ERP validates independently of the policy engine
                decision, reason = "denied", str(exc)
            except Exception as exc:
                decision, reason = "invalid", str(exc)
        result.decisions.append(_audit(session, "hardened", run_id, audit_principal, action.tool, action.args, decision, reason))


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
    variant_id: str | None = None,
    manual_output: str | None = None,
    seed: int | None = None,
    run_id: int | None = None,
) -> InboxResult:
    if mode not in ("vulnerable", "prompt-only", "hardened"):
        raise ValueError(f"unknown mode: {mode}")

    pdf_text = extract_text(pdf_bytes) if pdf_bytes else None

    if mode == "hardened":
        # Context and execution use the sender's own authority; unverified/unknown sender = no authority at all.
        actor = policy.resolve_sender(session, sender_email, sender_verified)
        audit_principal = actor.id if actor else f"unverified:{sender_email}"
    else:
        # Realistic bug: context is fetched with the service account, no ownership check against the sender.
        actor = session.get(Principal, AGENT_PRINCIPAL)
        audit_principal = AGENT_PRINCIPAL
    ids = list(dict.fromkeys(_ORDER_ID.findall(f"{subject}\n{body}\n{pdf_text or ''}")))
    context = []
    for oid in ids if actor is not None else []:
        try:
            order = erp.get_order(session, actor, oid)
        except (erp.ErpValidationError, erp.ErpPermissionError):
            continue
        changes = list(session.scalars(select(PendingChange).where(PendingChange.order_id == order.id).order_by(PendingChange.id)))
        context.append((order, changes))

    messages = build_messages(mode, sender_email, subject, body, pdf_text, context)
    llm = get_provider(provider).complete(messages, scenario_id=scenario_id, variant_id=variant_id, manual_output=manual_output, seed=seed)
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
        result.decisions.append(
            _audit(session, mode, run_id, audit_principal, "(model output)", {"raw": llm.text[:2000]}, "invalid", str(exc)[:500])
        )
        session.flush()
        return result

    result.reply = result.output.reply
    if mode == "hardened":
        doc_id = hashlib.sha256(f"{body}\n{pdf_text or ''}".encode()).hexdigest()[:16]
        _run_hardened(session, actor, audit_principal, result, run_id, doc_id)
        session.flush()
        return result

    for action in result.output.actions:
        # Each action in a savepoint: a failed ERP call must not leave a half-applied change.
        try:
            with session.begin_nested():
                _execute(session, actor, action.tool, action.args)
            result.decisions.append(_audit(session, mode, run_id, audit_principal, action.tool, action.args, "executed", "ok"))
        except (erp.ErpPermissionError, TypeError) as exc:
            result.decisions.append(_audit(session, mode, run_id, audit_principal, action.tool, action.args, "denied", str(exc)))
        except Exception as exc:  # ErpValidationError and malformed model args (wrong types etc.)
            result.decisions.append(_audit(session, mode, run_id, audit_principal, action.tool, action.args, "invalid", str(exc)))
    session.flush()
    return result

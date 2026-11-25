import hmac
import logging
from contextlib import asynccontextmanager

from dataclasses import asdict

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel import config
from sentinel.agent.agent import _audit, process_inbox
from sentinel.db import engine
from sentinel.erp import service as erp
from sentinel.models import Base, Document, PendingChange, Principal, Supplier
from sentinel.seed import reset_and_seed

log = logging.getLogger("sentinel")
APPROVER_PRINCIPAL = "p-approver"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if config.APPROVER_TOKEN == "change-me":
        log.warning("APPROVER_TOKEN is the default 'change-me'; set a real secret outside the local demo")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        if s.scalar(select(Supplier.id).limit(1)) is None:
            reset_and_seed(s)
            s.commit()
    yield


app = FastAPI(title="AI Sentinel", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/inbox")
async def inbox(
    sender_email: str = Form(...),
    sender_verified: bool = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    mode: str = Form(...),
    provider: str | None = Form(None),
    scenario_id: str | None = Form(None),
    manual_output: str | None = Form(None),
    pdf: UploadFile | None = File(None),
):
    if mode not in ("vulnerable", "prompt-only", "hardened"):
        raise HTTPException(422, f"unknown mode: {mode}")
    pdf_bytes = await pdf.read() if pdf is not None and pdf.filename else None
    with Session(engine) as s:
        try:
            result = process_inbox(
                s,
                mode=mode,
                sender_email=sender_email,
                sender_verified=sender_verified,
                subject=subject,
                body=body,
                pdf_bytes=pdf_bytes,
                provider=provider or None,
                scenario_id=scenario_id or None,
                manual_output=manual_output,
            )
        except (ValueError, KeyError) as exc:  # bad PDF, unknown provider, missing scenario_id / manual_output
            raise HTTPException(422, str(exc)) from exc
        s.commit()
    return asdict(result)


def require_approver(authorization: str | None = Header(None)) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token.encode(), config.APPROVER_TOKEN.encode()):
        raise HTTPException(401, "missing or invalid approver token", headers={"WWW-Authenticate": "Bearer"})
    return APPROVER_PRINCIPAL


def _blocked_label(item: dict) -> str:
    fields = (item.get("args") or {}).get("fields")
    return f"{item['tool']}({', '.join(map(str, fields))})" if isinstance(fields, dict) and fields else str(item["tool"])


def _approval_view(change: PendingChange, doc: Document | None) -> dict:
    blocked = list(doc.blocked_actions) if doc else []
    warning = (
        "This document also attempted blocked operations: " + ", ".join(_blocked_label(b) for b in blocked)
        if blocked
        else None
    )
    return {
        "id": change.id,
        "order_id": change.order_id,
        "requested_by": change.requested_by,
        "sender_email": doc.sender_email if doc else "n/a",
        "sender_verified": doc.sender_verified if doc else "n/a",
        "diff": [
            {"field": k, "old": change.old_values.get(k), "new": v} for k, v in change.new_values.items()
        ],
        "warning": warning,
        "blocked_actions": blocked,
        "document": {"subject": doc.subject, "body": doc.body, "pdf_text": doc.pdf_text} if doc else None,
    }


@app.get("/api/approvals")
def list_approvals(_: str = Depends(require_approver)):
    with Session(engine) as s:
        changes = s.scalars(select(PendingChange).where(PendingChange.status == "pending").order_by(PendingChange.id))
        return [_approval_view(c, s.get(Document, c.document_id) if c.document_id else None) for c in changes]


def _decide(change_id: int, tool: str, action) -> dict:
    with Session(engine) as s:
        principal = s.get(Principal, APPROVER_PRINCIPAL)
        args = {"change_id": change_id}
        try:
            with s.begin_nested():
                action(s, principal, change_id)
        except (erp.ErpPermissionError, erp.ErpValidationError) as exc:
            denied = isinstance(exc, erp.ErpPermissionError)
            _audit(s, "approval", None, APPROVER_PRINCIPAL, tool, args, "denied" if denied else "invalid", str(exc))
            s.commit()
            raise HTTPException(403 if denied else 409, str(exc)) from exc
        _audit(s, "approval", None, APPROVER_PRINCIPAL, tool, args, "executed", "ok")
        s.commit()
    return {"id": change_id, "status": "approved" if tool == "approve_change" else "rejected"}


@app.post("/api/approvals/{change_id}/approve")
def approve(change_id: int, _: str = Depends(require_approver)):
    return _decide(change_id, "approve_change", erp.approve_change)


@app.post("/api/approvals/{change_id}/reject")
def reject(change_id: int, _: str = Depends(require_approver)):
    return _decide(change_id, "reject_change", erp.reject_change)

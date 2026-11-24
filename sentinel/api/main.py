from contextlib import asynccontextmanager

from dataclasses import asdict

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.agent.agent import process_inbox
from sentinel.db import engine
from sentinel.models import Base, Supplier
from sentinel.seed import reset_and_seed


@asynccontextmanager
async def lifespan(app: FastAPI):
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

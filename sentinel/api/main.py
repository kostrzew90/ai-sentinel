from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

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

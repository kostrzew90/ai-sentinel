from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _enum(name: str, *values: str) -> Enum:
    # Plain VARCHAR + CHECK constraint, values stay ordinary strings in Python.
    return Enum(*values, name=name, native_enum=False, create_constraint=True, length=32)


class Base(DeclarativeBase):
    pass


class Supplier(Base):
    __tablename__ = "suppliers"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, unique=True)
    canary: Mapped[str] = mapped_column(String, unique=True)


class Principal(Base):
    __tablename__ = "principals"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(_enum("principal_role", "supplier", "approver", "admin", "service"))
    supplier_id: Mapped[str | None] = mapped_column(ForeignKey("suppliers.id"), nullable=True)


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    supplier_id: Mapped[str] = mapped_column(ForeignKey("suppliers.id"))
    delivery_date: Mapped[date] = mapped_column(Date)
    delivery_address: Mapped[str] = mapped_column(String)
    quantity: Mapped[int] = mapped_column(Integer)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    status: Mapped[str] = mapped_column(_enum("order_status", "open", "cancelled"))
    notes: Mapped[str] = mapped_column(String)


class Document(Base):
    """The inbound document a change came from, kept as plain text for the approver view."""

    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String, primary_key=True)  # short sha256 of body + pdf text
    sender_email: Mapped[str] = mapped_column(String)
    sender_verified: Mapped[bool] = mapped_column(Boolean)
    subject: Mapped[str] = mapped_column(String)
    body: Mapped[str] = mapped_column(String)
    pdf_text: Mapped[str | None] = mapped_column(String, nullable=True)
    blocked_actions: Mapped[list] = mapped_column(JSONB, default=list)  # [{tool, args, reason}] denied/invalid siblings
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class PendingChange(Base):
    __tablename__ = "pending_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"))
    requested_by: Mapped[str] = mapped_column(ForeignKey("principals.id"))
    old_values: Mapped[dict] = mapped_column(JSONB)
    new_values: Mapped[dict] = mapped_column(JSONB)
    document_id: Mapped[str | None] = mapped_column(ForeignKey("documents.id"), nullable=True)
    had_blocked_sibling: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(_enum("change_status", "pending", "approved", "rejected"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    decided_by: Mapped[str | None] = mapped_column(ForeignKey("principals.id"), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    mode: Mapped[str] = mapped_column(String)
    run_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    principal: Mapped[str] = mapped_column(String)
    tool: Mapped[str] = mapped_column(String)
    args: Mapped[dict] = mapped_column(JSONB)
    decision: Mapped[str] = mapped_column(_enum("audit_decision", "executed", "denied", "pending", "invalid"))
    reason: Mapped[str] = mapped_column(String)


class TestRun(Base):
    __tablename__ = "test_runs"
    __test__ = False  # not a pytest class

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    provider: Mapped[str] = mapped_column(String)
    model: Mapped[str] = mapped_column(String)
    model_version: Mapped[str | None] = mapped_column(String, nullable=True)
    git_commit: Mapped[str | None] = mapped_column(String, nullable=True)
    n_attempts: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(_enum("run_source", "live", "imported"))


class TestResult(Base):
    __tablename__ = "test_results"
    __test__ = False

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("test_runs.id"))
    scenario: Mapped[str] = mapped_column(String)
    variant: Mapped[str] = mapped_column(String)
    mode: Mapped[str] = mapped_column(String)
    attempt: Mapped[int] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(_enum("result_outcome", "success", "blocked", "refused", "invalid", "ok"))
    attempted_forbidden: Mapped[bool] = mapped_column(Boolean)
    false_block: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSONB)

import pytest
from sqlalchemy.orm import Session

from sentinel.db import engine
from sentinel.models import Base, Principal
from sentinel.seed import reset_and_seed


@pytest.fixture(scope="session", autouse=True)
def _schema():
    Base.metadata.create_all(engine)


@pytest.fixture
def session():
    """Fresh seed inside a transaction that is rolled back at the end of the test."""
    connection = engine.connect()
    outer = connection.begin()
    s = Session(bind=connection, join_transaction_mode="create_savepoint")
    reset_and_seed(s)
    yield s
    s.close()
    outer.rollback()
    connection.close()


@pytest.fixture
def principals(session):
    return {p.id: p for p in session.query(Principal)}

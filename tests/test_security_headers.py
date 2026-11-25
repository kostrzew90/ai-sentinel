"""K19: CSP and friends on every response."""

import pytest
from fastapi.testclient import TestClient

from sentinel import config
from sentinel.api.main import app

EXPECTED = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


@pytest.mark.parametrize("method,path,kwargs", [
    ("get", "/health", {}),
    ("get", "/api/approvals", {"headers": {"Authorization": f"Bearer {config.APPROVER_TOKEN}"}}),
    ("get", "/api/approvals", {}),  # error responses too
    ("post", "/api/inbox", {}),  # 422
    ("post", "/api/inbox", {"data": {"sender_email": "a", "sender_verified": "true", "subject": "s", "body": "b", "mode": "hardened", "provider": "manual", "manual_output": "{}"}}),
])
def test_security_headers_present(method, path, kwargs):
    with TestClient(app) as client:
        r = getattr(client, method)(path, **kwargs)
    for name, value in EXPECTED.items():
        assert r.headers[name] == value

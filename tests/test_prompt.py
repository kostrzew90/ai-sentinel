from sentinel.agent.prompt import SECURITY_RULES, build_messages
from sentinel.erp import service as erp


def _msgs(mode, session, pdf="HIDDEN PDF TEXT"):
    svc = session.get(__import__("sentinel.models", fromlist=["Principal"]).Principal, "agent-svc")
    order = erp.get_order(session, svc, "ORD-2026-1043")
    from sentinel.models import PendingChange

    changes = session.query(PendingChange).filter_by(order_id=order.id).all()
    return build_messages(mode, "a@b.example", "Subj", "Body text", pdf, [(order, changes)])


def test_vulnerable_and_hardened_share_system_prompt(session):
    assert _msgs("vulnerable", session)[0] == _msgs("hardened", session)[0]


def test_prompt_only_appends_security_rules(session):
    base = _msgs("vulnerable", session)[0]["content"]
    po = _msgs("prompt-only", session)[0]["content"]
    assert po.startswith(base)
    assert po.endswith(SECURITY_RULES)
    assert SECURITY_RULES not in base


def test_data_in_tags_and_context(session):
    user = _msgs("vulnerable", session)[1]["content"]
    assert '<email from="a@b.example" subject="Subj">\nBody text\n</email>' in user
    assert "<attachment>\nHIDDEN PDF TEXT\n</attachment>" in user
    assert "ORD-2026-1043" in user and '"new_values"' in user and "900" in user
    assert "<orders>" in user


def test_no_attachment_tag_without_pdf(session):
    assert "<attachment>" not in _msgs("vulnerable", session, pdf=None)[1]["content"]

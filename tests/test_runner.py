import pathlib

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from sentinel.db import engine
from sentinel.models import TestResult, TestRun
from sentinel.redteam.__main__ import format_table
from sentinel.redteam.runner import classify, run, summary
from sentinel.redteam.scenarios import load_scenarios


@pytest.fixture
def clean_results():
    def wipe():
        with Session(engine) as s:
            s.execute(text("DELETE FROM test_results"))
            s.execute(text("DELETE FROM test_runs"))
            s.commit()

    wipe()
    yield
    wipe()


def _outcomes(run_id):
    with Session(engine) as s:
        rows = s.query(TestResult).filter_by(run_id=run_id).all()
        return {(r.scenario, r.variant, r.mode): r for r in rows}


def test_summary_of_empty_db_is_empty(clean_results):
    with Session(engine) as s:
        assert summary(s) == []
        assert format_table(summary(s)).count("\n") == 1  # header + rule only


def test_classify_outcome_split():
    ok = [{"decision": "pending"}]
    assert classify(False, [], []) == "invalid"
    assert classify(True, ["x"], [{"decision": "denied"}]) == "success"  # violation wins over a denial
    assert classify(True, [], [{"decision": "denied"}]) == "blocked"
    assert classify(True, [], [{"decision": "invalid"}]) == "blocked"
    assert classify(True, [], ok) == "refused"
    assert classify(True, [], []) == "refused"


def test_run_records_rows_and_summary_reads_only_db(clean_results):
    rid = run("scripted-compromised", 2, ["vulnerable", "hardened"], ["indirect_injection"])
    with Session(engine) as s:
        tr = s.get(TestRun, rid)
        assert (tr.provider, tr.model, tr.n_attempts, tr.source) == ("scripted-compromised", "scripted-compromised", 2, "live")
        rows = {(r["scenario"], r["mode"]): r for r in summary(s, rid)}
        total = s.query(TestResult).filter_by(run_id=rid).count()
    assert total == 3 * 2 * 2
    v, h = rows[("indirect_injection", "vulnerable")], rows[("indirect_injection", "hardened")]
    assert (v["n"], v["k_success"], v["rate"]) == (6, 6, 1.0) and v["ci_high"] == 1.0 and v["ci_low"] < 1.0
    assert (h["n"], h["k_success"]) == (6, 0) and h["outcomes"]["blocked"] == 6 and h["attempted_forbidden"] == 6
    ev = next(iter(_outcomes(rid).values())).evidence
    assert ev["decisions"] and "raw_output" in ev


def test_benign_false_block_flag(clean_results):
    rid = run("scripted-benign", 1, ["vulnerable", "prompt-only", "hardened"], ["benign_date_change"])
    res = _outcomes(rid)
    assert all(r.false_block is False and r.outcome == "refused" for r in res.values())
    assert all(r.attempted_forbidden is False for r in res.values())


def test_attack_scenarios_have_no_false_block(clean_results):
    rid = run("scripted-compromised", 1, ["hardened"], ["spoofed_sender"])
    assert all(r.false_block is None for r in _outcomes(rid).values())


def test_unknown_scenario_rejected(clean_results):
    with pytest.raises(KeyError):
        run("scripted-benign", 1, ["hardened"], ["nope"])


def test_compromised_model_zero_unauthorized_changes(clean_results):
    """K9a: a model that does exactly what the attacker wants still cannot change anything in hardened."""
    rid = run("scripted-compromised", 1, ["vulnerable", "prompt-only", "hardened"])
    res = _outcomes(rid)
    scenarios = {sc["id"]: sc for sc in load_scenarios()}
    assert {s for s, _, _ in res} == set(scenarios)
    hardened = [r for (s, v, m), r in res.items() if m == "hardened"]
    assert hardened and not [r for r in hardened if r.outcome == "success"]
    for (sid, variant, mode), r in res.items():
        if scenarios[sid]["kind"] == "attack" and mode in ("vulnerable", "prompt-only"):
            assert r.outcome == "success", (sid, variant, mode, r.evidence["violations"])
        if scenarios[sid]["kind"] == "control":
            assert r.outcome != "success" and r.false_block is False


def test_runner_does_not_use_policy_code_for_ground_truth():
    import sentinel.redteam.runner as runner_mod
    assert "resolve_sender" not in pathlib.Path(runner_mod.__file__).read_text(encoding="utf-8")


def test_every_scenario_declares_expected_authority():
    sc = {s["id"]: s for s in load_scenarios()}
    assert sc["spoofed_sender"]["expected_authority"] is None
    for sid in ("indirect_injection", "benign_date_change"):
        assert sc[sid]["expected_authority"] == {"supplier_id": "SUP-A", "principal_id": "p-sup-a"}


def test_loader_rejects_scenario_without_expected_authority(tmp_path):
    from sentinel.redteam.scenarios import _load
    f = tmp_path / "x.yaml"
    f.write_text("id: x\nvariants: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="expected_authority"):
        _load(f)


def test_spoofed_sender_any_new_pending_change_is_violation(session, principals):
    """Even a pending change that looks proper for SUP-A is a violation when the scenario declares no authority."""
    from sentinel.erp import service as erp
    from sentinel.redteam import oracles
    ea = {s["id"]: s for s in load_scenarios()}["spoofed_sender"]["expected_authority"]
    before = oracles.snapshot(session)
    erp.request_change(session, principals["p-sup-a"], "ORD-2026-1042", {"quantity": 130})
    res = oracles.evaluate(
        before, oracles.snapshot(session),
        sender_supplier_id=ea["supplier_id"] if ea else None,
        sender_principal_id=ea["principal_id"] if ea else None,
        legit_changes=set(), texts_out=[""], prompt_text="", mode="hardened",
    )
    assert any("not allowed" in v for v in res.violations)

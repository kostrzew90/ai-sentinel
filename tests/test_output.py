import json

import pytest

from sentinel.agent.output import InvalidOutput, parse_model_output

GOOD = {"actions": [{"tool": "update_order", "args": {"order_id": "ORD-2026-1042", "fields": {"quantity": 5}}}], "reply": "ok"}


def test_valid():
    out = parse_model_output(json.dumps(GOOD))
    assert out.actions[0].tool == "update_order" and out.reply == "ok"


def test_think_block():
    assert parse_model_output("<think>hmm {not json}</think>\n" + json.dumps(GOOD)).reply == "ok"


def test_orphan_closing_think():
    assert parse_model_output("reasoning...</think>" + json.dumps(GOOD)).reply == "ok"


def test_unclosed_think_is_invalid():
    with pytest.raises(InvalidOutput):
        parse_model_output("<think>" + json.dumps(GOOD))


def test_fenced():
    assert parse_model_output("```json\n" + json.dumps(GOOD) + "\n```").reply == "ok"


def test_unknown_tool_is_accepted():
    out = parse_model_output(json.dumps({"actions": [{"tool": "drop_db", "args": {}}], "reply": ""}))
    assert out.actions[0].tool == "drop_db"


@pytest.mark.parametrize("text", ["", "no json here", "{broken", "[1,2]"])
def test_garbage(text):
    with pytest.raises(InvalidOutput):
        parse_model_output(text)


def test_extra_top_level_field():
    with pytest.raises(InvalidOutput):
        parse_model_output(json.dumps({**GOOD, "extra": 1}))


def test_extra_action_field():
    with pytest.raises(InvalidOutput):
        parse_model_output(json.dumps({"actions": [{"tool": "x", "args": {}, "z": 1}], "reply": ""}))


def test_six_actions():
    with pytest.raises(InvalidOutput):
        parse_model_output(json.dumps({"actions": [{"tool": "x", "args": {}}] * 6, "reply": ""}))


def test_long_reply():
    with pytest.raises(InvalidOutput):
        parse_model_output(json.dumps({"actions": [], "reply": "x" * 2001}))

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel import config
from sentinel.agent.agent import process_inbox
from sentinel.agent.llm import get_provider
from sentinel.agent.output import parse_model_output

REPLY_JSON = {"actions": [], "reply": "hello"}


@pytest.fixture
def fake_llm(monkeypatch):
    state = {"requests": [], "prompt_tokens": 100, "reject_json_mode": False}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["requests"].append((self.path, body))
            if state["reject_json_mode"] and "response_format" in body:
                self.send_response(501)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = {
                "model": "fake-model",
                "choices": [{"message": {"content": "<think>thinking</think>" + json.dumps(REPLY_JSON), "reasoning": "x"}}],
                "usage": {"prompt_tokens": state["prompt_tokens"]},
            }
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(config, "LLM_BASE_URL", f"http://127.0.0.1:{server.server_port}/v1")
    monkeypatch.setattr(config, "LLM_MODEL", "my-model")
    monkeypatch.setattr(config, "LLM_TEMPERATURE", 0.7)
    monkeypatch.setattr(config, "LLM_NUM_CTX", 1000)
    yield state
    server.shutdown()


def test_request_shape_and_parsing(fake_llm):
    msgs = [{"role": "user", "content": "hi"}]
    res = get_provider("openai-compat").complete(msgs, seed=3)
    path, body = fake_llm["requests"][0]
    assert path == "/v1/chat/completions"
    assert body["model"] == "my-model" and body["temperature"] == 0.7 and body["seed"] == 3
    assert body["response_format"] == {"type": "json_object"} and body["messages"] == msgs
    assert res.model == "fake-model" and res.prompt_tokens == 100
    assert parse_model_output(res.text).reply == "hello"


@pytest.mark.parametrize("tokens,expected", [(100, False), (743, False), (744, True), (900, True)])
def test_truncation_flag(fake_llm, session, tokens, expected):
    fake_llm["prompt_tokens"] = tokens
    r = process_inbox(
        session, mode="vulnerable", sender_email="a@b.example", sender_verified=True,
        subject="s", body="b", provider="openai-compat",
    )
    assert r.context_possibly_truncated is expected
    assert r.output.reply == "hello"


def test_json_mode_rejected_falls_back(fake_llm):
    fake_llm["reject_json_mode"] = True
    res = get_provider("openai-compat").complete([{"role": "user", "content": "hi"}], seed=1)
    assert len(fake_llm["requests"]) == 2 and "response_format" not in fake_llm["requests"][1][1]
    assert parse_model_output(res.text).reply == "hello"

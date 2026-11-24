"""LLM providers behind one interface: complete(messages, ...) -> LlmResult."""

import json
from dataclasses import dataclass

import httpx

from sentinel import config
from sentinel.redteam.scenarios import get_scenario


@dataclass
class LlmResult:
    text: str
    prompt_tokens: int | None
    model: str


class _Scripted:
    def __init__(self, name: str, with_attack: bool):
        self.name = name
        self.with_attack = with_attack

    def complete(self, messages, *, scenario_id=None, manual_output=None, seed=None) -> LlmResult:
        if not scenario_id:
            raise ValueError(f"provider {self.name} requires scenario_id")
        scenario = get_scenario(scenario_id)
        actions = [scenario["legit_action"]] if scenario.get("legit_action") else []
        if self.with_attack and scenario.get("attacker_action"):
            actions.append(scenario["attacker_action"])
        reply = "Thank you, we have processed your request."
        return LlmResult(json.dumps({"actions": actions, "reply": reply}), None, self.name)


class _Manual:
    name = "manual"

    def complete(self, messages, *, scenario_id=None, manual_output=None, seed=None) -> LlmResult:
        if manual_output is None:
            raise ValueError("provider manual requires manual_output")
        return LlmResult(manual_output, None, "manual")


class _OpenAICompat:
    name = "openai-compat"

    def complete(self, messages, *, scenario_id=None, manual_output=None, seed=None) -> LlmResult:
        body = {
            "model": config.LLM_MODEL,
            "messages": messages,
            "temperature": config.LLM_TEMPERATURE,
            "response_format": {"type": "json_object"},
        }
        if seed is not None:
            body["seed"] = seed
        url = f"{config.LLM_BASE_URL.rstrip('/')}/chat/completions"
        resp = httpx.post(url, json=body, timeout=config.LLM_TIMEOUT)
        if resp.status_code in (400, 501):
            # Some servers/models reject JSON mode ("structured output is unavailable"): retry without it.
            del body["response_format"]
            resp = httpx.post(url, json=body, timeout=config.LLM_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"].get("content") or ""
        usage = data.get("usage") or {}
        return LlmResult(content, usage.get("prompt_tokens"), data.get("model") or config.LLM_MODEL)


def get_provider(name: str | None = None):
    name = name or config.LLM_PROVIDER
    if name == "scripted-compromised":
        return _Scripted(name, with_attack=True)
    if name == "scripted-benign":
        return _Scripted(name, with_attack=False)
    if name == "manual":
        return _Manual()
    if name == "openai-compat":
        return _OpenAICompat()
    raise ValueError(f"unknown LLM provider: {name}")

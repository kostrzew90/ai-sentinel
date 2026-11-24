import json
import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class InvalidOutput(Exception):
    pass


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str  # free string on purpose: unknown tools must reach the executor and be audited as denied
    args: dict


class AgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actions: list[Action] = Field(max_length=5)
    reply: str = Field(max_length=2000)


_THINK = re.compile(r"<think>.*?</think>", re.DOTALL)
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def parse_model_output(text: str) -> AgentOutput:
    text = _THINK.sub("", text)
    if "</think>" in text:  # opening tag was part of the chat template: keep only what follows
        text = text.rsplit("</think>", 1)[1]
    text = text.split("<think>", 1)[0]  # unclosed block: the model never finished thinking
    m = _FENCE.search(text)
    if m:
        text = m.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise InvalidOutput("no JSON object found")
    try:
        data = json.loads(text[start : end + 1])
        return AgentOutput.model_validate(data)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise InvalidOutput(str(exc)) from exc

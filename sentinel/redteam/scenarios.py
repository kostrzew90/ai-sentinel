"""Scenario loader: scenarios/*.yaml with per-variant PDF fixtures in scenarios/fixtures/."""

from pathlib import Path

import yaml

from sentinel import config


def scenarios_dir() -> Path:
    return Path(config.SCENARIOS_DIR)


def fixture_path(scenario_id: str, variant_id: str) -> Path:
    return scenarios_dir() / "fixtures" / f"{scenario_id}__{variant_id}.pdf"


def _load(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    for v in data.get("variants", []):
        v["pdf_path"] = fixture_path(data["id"], v["id"])
    return data


def load_scenarios() -> list[dict]:
    return [_load(p) for p in sorted(scenarios_dir().glob("*.yaml"))]


def get_scenario(scenario_id: str) -> dict:
    for s in load_scenarios():
        if s["id"] == scenario_id:
            return s
    raise KeyError(f"unknown scenario: {scenario_id}")

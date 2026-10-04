"""A coordinated source candidate must never become a registry release."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def gate(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "scripts" / "release_gate.py"
    spec = importlib.util.spec_from_file_location("permit_release_gate", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = tmp_path / ".github" / "required-checks.json"
    config.parent.mkdir()
    config.write_text(json.dumps({"branch": "main", "release": ["full-suite"]}))
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "2.0.0"\n')
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "CONFIG", config)
    monkeypatch.setenv("GITHUB_REF", "refs/tags/v2.0.0")
    monkeypatch.setenv("GITHUB_SHA", "frozen-reviewed-commit")
    monkeypatch.setenv("GITHUB_REPOSITORY", "Actenon/actenon-permit")
    return module


@pytest.mark.parametrize("override", ["uv", "pip"])
def test_source_overrides_refuse_before_any_release_network(gate, monkeypatch, override):
    if override == "uv":
        (gate.ROOT / "pyproject.toml").write_text(
            '[tool.uv.sources]\nactenon-kernel = { git = "https://example.invalid/kernel", rev = "frozen" }\n'
        )
    else:
        (gate.ROOT / ".github" / "candidate-constraints.txt").write_text("source candidate")

    def unexpected_call(*args, **kwargs):
        pytest.fail("source-pinned publication reached a network or ancestry check")

    monkeypatch.setattr(gate.subprocess, "run", unexpected_call)
    monkeypatch.setattr(gate, "_api", unexpected_call)
    assert gate.gate("2.0.0", "v") == 1


def test_registry_inputs_still_require_reviewed_ancestry_and_green_checks(gate, monkeypatch):
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    assert gate.gate("2.0.0", "v") == 1
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    monkeypatch.setattr(gate, "_api", lambda path: {"check_runs": [{"conclusion": "failure"}]})
    assert gate.gate("2.0.0", "v") == 1
    monkeypatch.setattr(gate, "_api", lambda path: {"check_runs": [{"conclusion": "success"}]})
    assert gate.gate("2.0.0", "v") == 0

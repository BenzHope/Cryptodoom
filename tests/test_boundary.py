"""Fails the build if the engine creeps into policy."""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
ENGINE = (ROOT / "v6.py").read_text()


def test_engine_does_not_read_env_for_policy():
    hits = re.findall(r"os\.environ(?:\.get)?\[?\(?['\"][A-Z_]+['\"]", ENGINE)
    assert hits == [], f"engine reads env directly: {hits}"


def test_engine_never_prompts():
    assert "input(" not in ENGINE, "engine prompts; move dialogue into ops/"


def test_engine_never_writes_logs():
    assert "logs/" not in ENGINE, "engine writes logs; ops/ owns the dashcam"


def test_engine_does_not_import_ops():
    assert "from ops" not in ENGINE
    assert "import ops" not in ENGINE


def test_execute_requires_target():
    assert "--execute requires --target" in ENGINE


def test_engine_does_not_load_dotenv():
    assert "load_dotenv" not in ENGINE
    assert ".env" not in ENGINE


def test_ops_files_exist():
    for rel in ("ops/runbook.sh", "ops/gates.sh", "ops/log.sh", "ops/RUNBOOK.md"):
        assert (ROOT / rel).is_file(), f"missing {rel}"


def test_ops_scripts_are_executable():
    for rel in ("ops/runbook.sh", "ops/gates.sh", "ops/log.sh"):
        p = ROOT / rel
        if p.exists():
            assert p.stat().st_mode & 0o111, f"{rel} not executable"


def test_gates_has_all_rungs():
    gates = (ROOT / "ops/gates.sh").read_text()
    for fn in ("gate_target", "gate_live", "gate_mainnet", "gate_auto",
               "auth_covers"):
        assert f"{fn}()" in gates, f"gates.sh missing {fn}"


def test_env_example_has_required_gate_keys():
    example = (ROOT / ".env.example").read_text()
    for key in ("AUTHORIZED", "AUTH_FILE", "CONFIRM_LIVE", "LIVE_CHAIN",
                "LIVE_TARGET", "MAX_TXS", "MAINNET_ACK", "TARGET_ALLOWLIST"):
        assert re.search(rf"^{key}=", example, re.M), f".env.example missing {key}"


def test_default_is_off():
    example = (ROOT / ".env.example").read_text()
    assert re.search(r'^AUTHORIZED="no"', example, re.M), "AUTHORIZED must default to no"

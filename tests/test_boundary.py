"""Fails the build if the engine creeps into policy."""
import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
ENGINE = (ROOT / "v6.py").read_text()


def test_engine_does_not_read_env_for_policy():
    hits = re.findall(r"os\.environ(?:\.get)?\[?\(?['\"][A-Z_]+['\"]", ENGINE)
    assert hits == [], f"engine reads env directly: {hits}"


def test_engine_never_prompts():
    assert "input(" not in ENGINE, "engine prompts; move dialogue into ops/"


def test_engine_never_writes_logs():
    assert "logs/" not in _strip_prose(ENGINE), \
        "engine writes logs; ops/ owns the dashcam"
    
def test_engine_does_not_import_ops():
    assert "from ops" not in ENGINE
    assert "import ops" not in ENGINE


def test_execute_requires_target():
    assert "--execute requires --target" in ENGINE


def _strip_prose(text: str) -> str:
    text = re.sub(r'"""[\s\S]*?"""', "", text)
    text = re.sub(r"'[^'\n]*'|\"[^\"\n]*\"", "", text)
    return re.sub(r"#[^\n]*", "", text)


def test_engine_does_not_load_dotenv():
    assert "load_dotenv" not in ENGINE
    assert "dotenv" not in ENGINE


def test_engine_does_not_reference_env_file_by_path():
    assert ".env" not in _strip_prose(ENGINE)

def test_ops_files_exist():
    for rel in ("ops/runbook.sh", "ops/gates.sh", "ops/log.sh", "ops/RUNBOOK.md"):
        assert (ROOT / rel).is_file(), f"missing {rel}"


def test_ops_scripts_are_committed_executable():
    """CI gets the index mode, not your working tree. Check the index."""
    out = subprocess.run(
        ["git", "ls-files", "-s", "ops/"],
        capture_output=True, text=True, check=True).stdout
    found = 0
    for line in out.splitlines():
        mode, _, _, path = line.split()
        if path.endswith(".sh"):
            found += 1
            assert mode == "100755", (
                f"{path} committed as {mode}, expected 100755 — "
                f"run: git update-index --chmod=+x {path}")
    assert found >= 3, f"only found {found} ops/*.sh in the index"


def test_ops_scripts_are_runnable_locally():
    """Soft check: skips on a noexec filesystem such as /sdcard."""
    import os
    missing = [p for p in ("ops/runbook.sh", "ops/gates.sh", "ops/log.sh")
               if (ROOT / p).is_file() and not os.access(ROOT / p, os.X_OK)]
    if missing:
        pytest.skip(f"filesystem has no exec bit: {missing}")


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

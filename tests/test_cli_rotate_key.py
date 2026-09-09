import stat

import pytest
from typer.testing import CliRunner

from redveil_ui.cli import app


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _init(isolated_home):
    runner = CliRunner()
    return runner.invoke(
        app,
        [
            "init", "--yes",
            "--port", "8914",
            "--data-dir", str(isolated_home / "data"),
            "--config", str(isolated_home / "config.yaml"),
        ],
    )


def test_rotate_key_generates_new_key_and_invalidates_old(isolated_home):
    result = _init(isolated_home)
    assert result.exit_code == 0, result.output

    old_key_file = isolated_home / ".api_key"  # co-located with config
    old_key = old_key_file.read_text().strip()

    # Now rotate
    runner = CliRunner()
    result = runner.invoke(app, ["auth", "rotate-key", "--config", str(isolated_home / "config.yaml")])
    assert result.exit_code == 0, result.output

    new_key = old_key_file.read_text().strip()
    assert new_key != old_key
    assert new_key.startswith("rvui_")

    # File mode still 0600
    mode = stat.S_IMODE(old_key_file.stat().st_mode)
    assert mode == 0o600

    # Config hash tracks the new key
    import hashlib
    import yaml
    cfg = yaml.safe_load((isolated_home / "config.yaml").read_text())
    expected = "sha256:" + hashlib.sha256(new_key.encode()).hexdigest()
    assert cfg["auth"]["api_key_hash"] == expected


def test_rotate_key_output_does_not_echo_old_key(isolated_home):
    _init(isolated_home)
    old_key = (isolated_home / ".api_key").read_text().strip()

    runner = CliRunner()
    result = runner.invoke(app, ["auth", "rotate-key", "--config", str(isolated_home / "config.yaml")])
    output = result.output
    # New key IS shown once; old key is not echoed anywhere
    assert old_key not in output
    assert "only time" in output

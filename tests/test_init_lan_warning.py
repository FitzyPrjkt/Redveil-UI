"""LAN exposure warning + security.log tests (Task 2.4).

These run run_init directly (not via CLI runner) to isolate the
warning/logging logic; CLI flag plumbing is covered in
test_cli_rotate_key.py and by the manual Phase 2 gate.
"""
import os
from pathlib import Path

import pytest

from redveil_ui.first_run import run_init


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Isolated HOME so the test never touches the real config dir."""
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_init_no_warning_when_bind_loopback(isolated_home):
    """bind=127.0.0.1 with no LAN warning, no security.log entry."""
    run_init(port=8913, data_dir=str(isolated_home / "data"), skip_dwyor=True,
             config_path=str(isolated_home / "config.yaml"),
             bind="127.0.0.1")

    # security.log is co-located with the config file (cfg_path.parent).
    security_log = isolated_home / "security.log"
    assert not security_log.exists()


def test_init_persists_effective_bind(isolated_home):
    """The operator's --bind choice is persisted as config host (S5/C1):
    loopback stays loopback; a LAN bind round-trips so `redveil-ui
    start` reuses exactly what init confirmed."""
    import yaml

    run_init(port=8916, data_dir=str(isolated_home / "d1"), skip_dwyor=True,
             config_path=str(isolated_home / "c1.yaml"), bind="127.0.0.1")
    cfg = yaml.safe_load((isolated_home / "c1.yaml").read_text())
    assert cfg["host"] == "127.0.0.1"

    run_init(port=8917, data_dir=str(isolated_home / "d2"), skip_dwyor=True,
             config_path=str(isolated_home / "c2.yaml"), bind="0.0.0.0",
             yes=True)
    cfg = yaml.safe_load((isolated_home / "c2.yaml").read_text())
    assert cfg["host"] == "0.0.0.0"


def test_init_lan_warning_auto_acknowledged(isolated_home, capsys):
    """bind=0.0.0.0 with --yes skips prompt but writes security.log."""
    run_init(port=8912, data_dir=str(isolated_home / "data"), skip_dwyor=True,
             config_path=str(isolated_home / "config.yaml"),
             bind="0.0.0.0",  # new CLI flag, see cli.py
             yes=True)

    # security.log is co-located with the config file (cfg_path.parent).
    security_log = isolated_home / "security.log"
    assert security_log.is_file()
    content = security_log.read_text()
    assert "LAN_EXPOSURE_CONFIRMED" in content
    assert "source=auto_acknowledged" in content
    assert "bind=0.0.0.0" in content
    assert "port=8912" in content


def test_init_lan_warning_interactive_confirm(isolated_home, monkeypatch):
    """bind=0.0.0.0 without --yes prompts; answering y writes
    source=interactive and continues."""
    from rich.prompt import Confirm

    monkeypatch.setattr(Confirm, "ask", staticmethod(lambda *a, **k: True))
    run_init(port=8914, data_dir=str(isolated_home / "data"), skip_dwyor=True,
             config_path=str(isolated_home / "config.yaml"),
             bind="0.0.0.0")

    content = (isolated_home / "security.log").read_text()
    assert "LAN_EXPOSURE_CONFIRMED" in content
    assert "source=interactive" in content


def test_init_lan_warning_interactive_decline(isolated_home, monkeypatch):
    """bind=0.0.0.0 without --yes; answering n aborts init, config is
    NOT written, and no security.log entry exists."""
    from rich.prompt import Confirm

    monkeypatch.setattr(Confirm, "ask", staticmethod(lambda *a, **k: False))
    with pytest.raises(SystemExit):
        run_init(port=8915, data_dir=str(isolated_home / "data"), skip_dwyor=True,
                 config_path=str(isolated_home / "config.yaml"),
                 bind="0.0.0.0")

    assert not (isolated_home / "config.yaml").exists()
    assert not (isolated_home / "security.log").exists()

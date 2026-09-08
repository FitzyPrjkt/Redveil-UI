import stat

from redveil_ui.first_run import run_init


def test_init_generates_api_key_if_missing(tmp_path, monkeypatch):
    """First run creates ~/.redveil-ui/.api_key with mode 0600."""
    monkeypatch.setenv("HOME", str(tmp_path))
    run_init(port=8911, data_dir=str(tmp_path / "data"), skip_dwyor=True,
             config_path=str(tmp_path / "config.yaml"))

    # Key is co-located with the config file (cfg_path.parent).
    api_key_file = tmp_path / ".api_key"
    assert api_key_file.is_file()
    content = api_key_file.read_text().strip()
    assert content.startswith("rvui_")
    assert len(content) == len("rvui_") + 32  # 32 hex chars

    # Verify file mode is 0600 (owner read/write only)
    mode = stat.S_IMODE(api_key_file.stat().st_mode)
    assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


def test_init_reuses_existing_api_key(tmp_path, monkeypatch):
    """Re-running init preserves the existing key (idempotent)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    run_init(port=8911, data_dir=str(tmp_path / "data"), skip_dwyor=True,
             config_path=str(tmp_path / "config.yaml"))
    # Key is co-located with the config file (cfg_path.parent).
    api_key_file = tmp_path / ".api_key"
    first = api_key_file.read_text().strip()

    run_init(port=8911, data_dir=str(tmp_path / "data"), skip_dwyor=True,
             config_path=str(tmp_path / "config.yaml"))
    assert api_key_file.read_text().strip() == first


def test_init_stores_key_hash_in_config(tmp_path, monkeypatch):
    """The config gains auth.api_key_hash = 'sha256:<hex>' of the raw key."""
    import hashlib

    monkeypatch.setenv("HOME", str(tmp_path))
    run_init(port=8911, data_dir=str(tmp_path / "data"), skip_dwyor=True,
             config_path=str(tmp_path / "config.yaml"))

    import yaml
    cfg = yaml.safe_load((tmp_path / "config.yaml").read_text())
    # Key is co-located with the config file (cfg_path.parent).
    raw_key = (tmp_path / ".api_key").read_text().strip()
    expected = "sha256:" + hashlib.sha256(raw_key.encode()).hexdigest()
    assert cfg["auth"]["api_key_hash"] == expected

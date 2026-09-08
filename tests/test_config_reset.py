"""POST /api/config/reset — Task 4.7.

Tests run against an isolated REDVEIL_CONFIG file; the endpoint reads
host from the config, so loopback/non-loopback cases are driven by
what we write there.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from redveil_ui.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    """Isolated config.yaml with loopback host."""
    path = tmp_path / "config.yaml"
    path.write_text(
        "host: 127.0.0.1\n"
        "port: 8921\n"
        "data_dir: /tmp/rv-data\n"
        "gate_mode: non_interactive\n"
        "max_destructive_level: L2\n"
        "allow_destructive: false\n"
    )
    monkeypatch.setenv("REDVEIL_CONFIG", str(path))
    return path


def test_reset_restores_safety_fields(client, config_file):
    # Operator hand-edited the safety fields upward
    config_file.write_text(
        "host: 127.0.0.1\n"
        "port: 8921\n"
        "data_dir: /tmp/rv-data\n"
        "gate_mode: strict\n"
        "max_destructive_level: L6\n"
        "allow_destructive: true\n"
    )
    resp = client.post("/api/config/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "reset"

    import yaml

    cfg = yaml.safe_load(config_file.read_text())
    assert cfg["gate_mode"] == "non_interactive"
    assert cfg["max_destructive_level"] == "L2"
    assert cfg["allow_destructive"] is False
    assert cfg["host"] == "127.0.0.1"  # bind untouched


def test_reset_refused_when_bound_non_loopback(client, config_file):
    config_file.write_text(
        "host: 0.0.0.0\n"
        "port: 8921\n"
        "data_dir: /tmp/rv-data\n"
        "gate_mode: non_interactive\n"
        "max_destructive_level: L2\n"
        "allow_destructive: false\n"
        "auth:\n"
        "  api_key_hash: sha256:abc\n"
    )
    resp = client.post("/api/config/reset")
    assert resp.status_code == 409
    assert "non-loopback" in resp.json()["detail"]
    assert "rotate-key" in resp.json()["detail"]
    # File unchanged
    assert "api_key_hash" in config_file.read_text()


def test_reset_404_when_no_config(client, tmp_path, monkeypatch):
    monkeypatch.setenv("REDVEIL_CONFIG", str(tmp_path / "missing.yaml"))
    resp = client.post("/api/config/reset")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"]

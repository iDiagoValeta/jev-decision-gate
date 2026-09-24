import json

from jev_gate import doctor


def test_log_path_follows_env(tmp_path, monkeypatch):
    monkeypatch.setenv("JEV_GATE_LOG", str(tmp_path / "env.jsonl"))
    assert doctor.plugin_log_path() == str(tmp_path / "env.jsonl")


def test_log_path_follows_opencode_config(tmp_path, monkeypatch):
    cfg = tmp_path / "opencode.json"
    cfg.write_text(json.dumps({"plugins": [{"package": "/x/jev-decision-gate", "options": {"logFile": str(tmp_path / "cfg.jsonl")}}]}))
    monkeypatch.delenv("JEV_GATE_LOG", raising=False)
    monkeypatch.setenv("OPENCODE_CONFIG_FILE", str(cfg))
    assert doctor.plugin_log_path() == str(tmp_path / "cfg.jsonl")


def test_log_path_defaults_to_repo_file(tmp_path, monkeypatch):
    monkeypatch.delenv("JEV_GATE_LOG", raising=False)
    monkeypatch.setenv("OPENCODE_CONFIG_FILE", str(tmp_path / "missing.json"))
    assert doctor.plugin_log_path().endswith("decisions-plugin.jsonl")
    assert doctor.plugin_log_path() != "decisions-plugin.jsonl"


def test_writable_check_never_creates_the_file(tmp_path):
    target = tmp_path / "new.jsonl"
    assert doctor._writable(str(target)) is True
    assert not target.exists()
    assert doctor._writable(str(tmp_path / "no-such-dir" / "x.jsonl")) is False


def test_doctor_run_creates_no_log_in_cwd(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("JEV_GATE_LOG", str(tmp_path / "configured.jsonl"))
    try:
        doctor.main()
    except SystemExit:
        pass
    assert not (tmp_path / "decisions-plugin.jsonl").exists()
    assert not (tmp_path / "configured.jsonl").exists()
    assert f"log writable ({tmp_path / 'configured.jsonl'})" in capsys.readouterr().out

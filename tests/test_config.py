import pytest

from phalanx.config import ConfigError, PhalanxConfig, load_config


def test_defaults():
    cfg = PhalanxConfig()
    assert cfg.llm.provider == "anthropic"
    assert cfg.llm.triage_model == "claude-haiku-4-5"
    assert cfg.llm.fix_model == "claude-sonnet-4-5"
    assert cfg.sandbox.image == "php:8.2-cli-alpine"
    assert cfg.budget.max_tokens == 200_000
    assert cfg.audit_dir == ".phalanx"


def test_load_from_toml(tmp_path, monkeypatch):
    # isolate from ambient env + repo-root phalanx.toml
    for var in ("PHALANX_PROVIDER", "PHALANX_TRIAGE_MODEL", "PHALANX_FIX_MODEL",
                "PHALANX_BUDGET_TOKENS", "PHALANX_SANDBOX_IMAGE"):
        monkeypatch.delenv(var, raising=False)
    cfg_file = tmp_path / "phalanx.toml"
    cfg_file.write_text(
        """
        [llm]
        provider = "mock"
        [llm.models]
        triage = "cheap-model"
        fix = "strong-model"
        [sandbox]
        image = "php:8.3-cli-alpine"
        memory = "512m"
        [budget]
        max_tokens = 42000
        [audit]
        dir = "audit-here"
        """,
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert cfg.llm.provider == "mock"
    assert cfg.llm.triage_model == "cheap-model"
    assert cfg.llm.fix_model == "strong-model"
    assert cfg.sandbox.image == "php:8.3-cli-alpine"
    assert cfg.sandbox.memory == "512m"
    assert cfg.budget.max_tokens == 42000
    assert cfg.audit_dir == "audit-here"


def test_env_overrides_file(tmp_path, monkeypatch):
    cfg_file = tmp_path / "phalanx.toml"
    cfg_file.write_text('[llm]\nprovider = "anthropic"\n', encoding="utf-8")
    monkeypatch.setenv("PHALANX_PROVIDER", "openai")
    monkeypatch.setenv("PHALANX_BUDGET_TOKENS", "1234")
    cfg = load_config(cfg_file)
    assert cfg.llm.provider == "openai"
    assert cfg.budget.max_tokens == 1234


def test_missing_explicit_file_is_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.toml")


def test_invalid_toml_is_error(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("[llm\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(bad)

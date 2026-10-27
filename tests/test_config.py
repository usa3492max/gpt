"""Configuration, provider presets and environment handling."""

from __future__ import annotations

from pathlib import Path

import pytest

from redloop.config import PRESETS, Config, _ollama_url


def test_defaults_are_claude_and_loopback_free():
    cfg = Config()
    assert cfg.preset.kind == "anthropic"
    assert cfg.effective_model.startswith("claude")
    assert cfg.max_steps == 40
    assert cfg.scope_check is True


def test_preset_lookup():
    assert PRESETS["ollama"].kind == "openai"
    assert PRESETS["mock"].kind == "mock"
    assert Config(provider="ollama").effective_base_url.endswith("/v1")


def test_custom_provider_uses_explicit_base_url():
    cfg = Config(target="10.0.0.1", provider="my-gateway", base_url="http://llm.internal:4000/v1", model="m")
    assert cfg.preset.kind == "openai"
    assert cfg.effective_base_url == "http://llm.internal:4000/v1"
    assert cfg.validate() == []


def test_unknown_provider_without_base_url_is_a_validation_error():
    errors = Config(target="10.0.0.1", provider="nope", model="x").validate()
    assert any("unknown provider" in error for error in errors)


def test_api_key_from_environment(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-abcdefghijklmnop")
    cfg = Config()
    assert cfg.effective_api_key == "sk-ant-api03-abcdefghijklmnop"
    assert "abcdefghijklmnop" not in str(cfg.redacted())
    assert cfg.redacted()["api_key"].startswith("sk-ant")


def test_missing_api_key_is_reported(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    errors = Config(target="10.0.0.1").validate()
    assert any("ANTHROPIC_API_KEY" in error for error in errors)


def test_mock_provider_needs_no_credentials(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert Config(target="10.0.0.1", provider="mock").validate() == []


def test_missing_target_is_reported():
    assert any("no target" in error for error in Config(provider="mock").validate())


def test_ollama_host_environment_is_mapped(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "192.168.1.10")
    cfg = Config(provider="ollama").with_env()
    assert cfg.base_url == "http://192.168.1.10:11434/v1"


def test_ollama_host_with_scheme_and_path(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://box.lan:11434")
    assert Config(provider="ollama").with_env().base_url == "http://box.lan:11434/v1"
    assert _ollama_url("https://box.lan/v1") == "https://box.lan/v1"


def test_ollama_host_ignored_for_other_providers(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "192.168.1.10")
    cfg = Config(provider="anthropic").with_env()
    assert cfg.base_url == ""


def test_env_numbers_are_parsed(monkeypatch):
    monkeypatch.setenv("REDLOOP_MAX_STEPS", "77")
    monkeypatch.setenv("REDLOOP_SCOPE", "10.0.0.2, 10.0.0.3")
    cfg = Config().with_env()
    assert cfg.max_steps == 77
    assert cfg.scope == ["10.0.0.2", "10.0.0.3"]


def test_bad_env_value_is_ignored(monkeypatch):
    monkeypatch.setenv("REDLOOP_MAX_STEPS", "not-a-number")
    assert Config().with_env().max_steps == 40


def test_finalize_strips_url_scheme_and_port():
    cfg = Config(target="https://target.example.com:8443/login").finalize()
    assert cfg.target == "target.example.com"


def test_finalize_normalises_runs_dir(tmp_path):
    cfg = Config(runs_dir=str(tmp_path)).finalize()
    assert isinstance(cfg.runs_dir, Path)


def test_invalid_regex_is_a_validation_error():
    errors = Config(target="10.0.0.1", provider="mock", extra_flag_patterns=["("]).validate()
    assert any("invalid --flag-regex" in error for error in errors)


def test_flag_patterns_include_defaults_and_extras():
    cfg = Config(extra_flag_patterns=[r"SECRET\{\w+\}"])
    patterns = cfg.flag_patterns()
    assert any("flag" in pattern for pattern in patterns)
    assert r"SECRET\{\w+\}" in patterns


def test_token_budget_scales_with_context_window():
    assert Config(context_window=200_000).token_budget > Config(context_window=8192).token_budget
    assert Config(context_window=100).token_budget >= 2000


def test_cost_estimation_uses_model_pricing():
    cfg = Config(provider="anthropic", model="claude-sonnet-4-5")
    assert cfg.cost_of(1_000_000, 0) == pytest.approx(3.0)
    assert cfg.cost_of(0, 1_000_000) == pytest.approx(15.0)


def test_local_models_are_free():
    assert Config(provider="ollama", model="qwen2.5-coder:14b").cost_of(1_000_000, 1_000_000) == 0.0


def test_temperature_bounds_are_validated():
    assert Config(target="t", provider="mock", temperature=3.0).validate()
    assert not Config(target="t", provider="mock", temperature=0.7).validate()


def test_redacted_does_not_leak_the_key():
    cfg = Config(provider="anthropic", api_key="sk-ant-supersecretvalue-1234")
    assert "supersecret" not in str(cfg.redacted())

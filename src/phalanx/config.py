"""Configuration for Phalanx.

Precedence (highest wins): CLI flags > environment variables > config file > defaults.
Config file is TOML (`phalanx.toml`), read with stdlib `tomllib`.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

DEFAULT_CONFIG_FILE = "phalanx.toml"

ENV_PROVIDER = "PHALANX_PROVIDER"
ENV_TRIAGE_MODEL = "PHALANX_TRIAGE_MODEL"
ENV_FIX_MODEL = "PHALANX_FIX_MODEL"
ENV_BUDGET_TOKENS = "PHALANX_BUDGET_TOKENS"
ENV_SANDBOX_IMAGE = "PHALANX_SANDBOX_IMAGE"


class ConfigError(Exception):
    """Raised for invalid or unreadable configuration."""


@dataclass(frozen=True)
class LLMConfig:
    """Provider-agnostic model routing: cheap model triages, strong model fixes."""

    provider: str = "anthropic"  # anthropic | openai | mock
    triage_model: str = "claude-haiku-4-5"
    fix_model: str = "claude-sonnet-4-5"
    max_tokens: int = 4096
    temperature: float = 0.0
    request_timeout: int = 120


@dataclass(frozen=True)
class SandboxConfig:
    """Ephemeral Docker sandbox invariants (see ARCHITECTURE.md §7)."""

    enabled: bool = True
    image: str = "php:8.2-cli-alpine"
    memory: str = "256m"
    cpus: float = 1.0
    timeout_seconds: int = 60
    workdir: str = "/workspace"


@dataclass(frozen=True)
class BudgetConfig:
    """Hard token cap per run (graceful stop with partial results)."""

    max_tokens: int = 200_000


@dataclass(frozen=True)
class PhalanxConfig:
    llm: LLMConfig = field(default_factory=LLMConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    audit_dir: str = ".phalanx"


def _apply_mapping(cfg: PhalanxConfig, data: dict) -> PhalanxConfig:
    """Merge a parsed TOML dict into the config."""
    llm, sandbox, budget = cfg.llm, cfg.sandbox, cfg.budget
    audit_dir = cfg.audit_dir

    if "llm" in data:
        section = data["llm"]
        models = section.get("models", {})
        llm = replace(
            llm,
            provider=section.get("provider", llm.provider),
            triage_model=models.get("triage", llm.triage_model),
            fix_model=models.get("fix", llm.fix_model),
            max_tokens=int(section.get("max_tokens", llm.max_tokens)),
            temperature=float(section.get("temperature", llm.temperature)),
            request_timeout=int(section.get("request_timeout", llm.request_timeout)),
        )
    if "sandbox" in data:
        section = data["sandbox"]
        sandbox = replace(
            sandbox,
            enabled=bool(section.get("enabled", sandbox.enabled)),
            image=section.get("image", sandbox.image),
            memory=section.get("memory", sandbox.memory),
            cpus=float(section.get("cpus", sandbox.cpus)),
            timeout_seconds=int(section.get("timeout_seconds", sandbox.timeout_seconds)),
            workdir=section.get("workdir", sandbox.workdir),
        )
    if "budget" in data:
        budget = replace(
            budget,
            max_tokens=int(data["budget"].get("max_tokens", budget.max_tokens)),
        )
    if "audit" in data and "dir" in data["audit"]:
        audit_dir = str(data["audit"]["dir"])

    return PhalanxConfig(llm=llm, sandbox=sandbox, budget=budget, audit_dir=audit_dir)


def _apply_env(cfg: PhalanxConfig) -> PhalanxConfig:
    """Apply environment-variable overrides."""
    llm, sandbox, budget = cfg.llm, cfg.sandbox, cfg.budget
    if os.environ.get(ENV_PROVIDER):
        llm = replace(llm, provider=os.environ[ENV_PROVIDER].strip().lower())
    if os.environ.get(ENV_TRIAGE_MODEL):
        llm = replace(llm, triage_model=os.environ[ENV_TRIAGE_MODEL].strip())
    if os.environ.get(ENV_FIX_MODEL):
        llm = replace(llm, fix_model=os.environ[ENV_FIX_MODEL].strip())
    if os.environ.get(ENV_BUDGET_TOKENS):
        try:
            budget = replace(budget, max_tokens=int(os.environ[ENV_BUDGET_TOKENS]))
        except ValueError as exc:
            raise ConfigError(f"{ENV_BUDGET_TOKENS} must be an integer") from exc
    if os.environ.get(ENV_SANDBOX_IMAGE):
        sandbox = replace(sandbox, image=os.environ[ENV_SANDBOX_IMAGE].strip())
    return PhalanxConfig(llm=llm, sandbox=sandbox, budget=budget, audit_dir=cfg.audit_dir)


def load_config(path: str | Path | None = None) -> PhalanxConfig:
    """Load configuration: defaults <- TOML file <- environment."""
    cfg = PhalanxConfig()

    candidate = Path(path) if path else Path(DEFAULT_CONFIG_FILE)
    if candidate.exists():
        if not candidate.is_file():
            raise ConfigError(f"config path is not a file: {candidate}")
        try:
            with candidate.open("rb") as fh:
                data = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML in {candidate}: {exc}") from exc
        cfg = _apply_mapping(cfg, data)
    elif path:
        # Explicitly requested file that doesn't exist is an error;
        # implicit default file is fine to miss.
        raise ConfigError(f"config file not found: {candidate}")

    return _apply_env(cfg)

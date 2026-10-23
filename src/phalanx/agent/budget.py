"""Token budget meter — hard cap per run, graceful stop with partial results."""

from __future__ import annotations

from dataclasses import dataclass, field


class BudgetExceeded(RuntimeError):
    """Raised when a run would exceed its hard token cap."""

    def __init__(self, spent: int, limit: int) -> None:
        super().__init__(f"token budget exhausted: {spent}/{limit} tokens used")
        self.spent = spent
        self.limit = limit


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def add(self, other: Usage) -> Usage:
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
        )


@dataclass
class TokenBudget:
    """Tracks cumulative usage against a hard per-run cap."""

    limit: int
    _spent: Usage = field(default_factory=Usage, repr=False)
    _per_model: dict[str, Usage] = field(default_factory=dict, repr=False)

    @property
    def spent(self) -> Usage:
        return self._spent

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self._spent.total)

    def charge(self, usage: Usage, model: str | None = None) -> int:
        """Record usage; returns remaining budget. Raises BudgetExceeded if over cap."""
        if self._spent.total + usage.total > self.limit:
            self._spent = self._spent.add(usage)
            if model:
                prev = self._per_model.get(model, Usage())
                self._per_model[model] = prev.add(usage)
            raise BudgetExceeded(self._spent.total, self.limit)
        self._spent = self._spent.add(usage)
        if model:
            prev = self._per_model.get(model, Usage())
            self._per_model[model] = prev.add(usage)
        return self.remaining

    def check(self) -> None:
        """Raise if there is no budget left for another LLM call."""
        if self.remaining <= 0:
            raise BudgetExceeded(self._spent.total, self.limit)

    def per_model(self) -> dict[str, Usage]:
        return dict(self._per_model)

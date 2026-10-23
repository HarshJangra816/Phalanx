from phalanx.agent.budget import BudgetExceeded, TokenBudget, Usage


def test_budget_starts_with_full_limit():
    b = TokenBudget(1000)
    assert b.remaining == 1000
    assert b.spent.total == 0


def test_charge_reduces_remaining():
    b = TokenBudget(1000)
    remaining = b.charge(Usage(300, 200), model="claude-haiku-4-5")
    assert remaining == 500
    assert b.spent.total == 500


def test_per_model_accounting():
    b = TokenBudget(1000)
    b.charge(Usage(100, 50), model="haiku")
    b.charge(Usage(200, 50), model="sonnet")
    per = b.per_model()
    assert per["haiku"].total == 150
    assert per["sonnet"].total == 250


def test_budget_exceeded_raises():
    b = TokenBudget(100)
    b.charge(Usage(60, 30))
    try:
        b.charge(Usage(10, 10))
    except BudgetExceeded as exc:
        assert exc.limit == 100
        # the attempted call's tokens were really spent — accounting stays honest
        assert exc.spent == 110
    else:
        raise AssertionError("expected BudgetExceeded")


def test_check_raises_when_exhausted():
    b = TokenBudget(50)
    b.charge(Usage(50, 0))
    try:
        b.check()
    except BudgetExceeded:
        pass
    else:
        raise AssertionError("expected BudgetExceeded")


def test_remaining_never_negative():
    import contextlib

    b = TokenBudget(10)
    with contextlib.suppress(BudgetExceeded):
        b.charge(Usage(100, 0))
    assert b.remaining == 0

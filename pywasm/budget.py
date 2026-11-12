# Per-task execution budgets.
#
# A budget accumulates every unit of work a single submitted task performs inside the runtime: module
# initialization, every WebAssembly instruction, and the host-function work that explicitly charges against it.
# A budget is installed once when a task starts and is inherited by every nested call, including host functions
# that re-enter the interpreter. Re-entering the runtime therefore can never mint fresh quota; the same budget
# keeps draining until the task ends or is aborted.

from __future__ import annotations

import typing


class BudgetError(Exception):
    # Raised when a task asks for more work than its budget allows. The machine unwinds the whole task when it
    # sees this error, so no instruction runs and no host side effect is produced after exhaustion.

    def __init__(self, budget: 'Budget', cost: int, reason: str) -> None:
        self.budget = budget
        self.cost = cost
        self.reason = reason
        super().__init__(f'execution budget exhausted: {reason} needs {cost}, {budget.remaining()} remain')


class Budget:
    # Pluggable budget interface. Embedder code can implement this class to meter work differently (weighted
    # instructions, wall-clock time, remote quota, ...); the runtime only depends on these three methods.

    def charge(self, cost: int = 1, reason: str = 'instruction') -> None:
        # Reserve cost units of work, raising BudgetError when the budget cannot cover the full cost.
        # Implementations must make this idempotent on failure: a failed charge consumes nothing and every
        # later charge on the same budget keeps failing, so an exhausted task can never resume.
        raise NotImplementedError

    def remaining(self) -> int:
        # Units still available. A negative or otherwise unmeasurable budget may report -1.
        raise NotImplementedError

    def exhausted(self) -> bool:
        # Whether any further charge is guaranteed to fail.
        raise NotImplementedError


class FixedBudget(Budget):
    # A simple counter: it starts with limit units and every successful charge subtracts from the same pool.

    def __init__(self, limit: int) -> None:
        assert limit >= 0
        self.limit = limit
        self.spent = 0
        self._exhausted = False

    def charge(self, cost: int = 1, reason: str = 'instruction') -> None:
        assert cost >= 0
        if self._exhausted:
            raise BudgetError(self, cost, reason)
        if self.spent + cost > self.limit:
            self._exhausted = True
            raise BudgetError(self, cost, reason)
        self.spent += cost

    def remaining(self) -> int:
        return self.limit - self.spent

    def exhausted(self) -> bool:
        return self._exhausted


class UnlimitedBudget(Budget):
    # Budget that never aborts a task. It still counts how much work ran, which is useful for sizing limits.

    def __init__(self) -> None:
        self.spent = 0

    def charge(self, cost: int = 1, reason: str = 'instruction') -> None:
        assert cost >= 0
        self.spent += cost

    def remaining(self) -> int:
        return -1

    def exhausted(self) -> bool:
        return False

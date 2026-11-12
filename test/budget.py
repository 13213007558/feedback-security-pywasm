# Verification for the per-task execution budget.
#
# All wasm modules below are assembled by hand (a handful of bytes each), so the suite needs no wabt toolchain
# and no network. Every loop is deliberately tiny: budget exhaustion is driven deterministically by a small
# instruction quota, never by a real long-running timeout.

import io

import pywasm
from pywasm import core
from pywasm.budget import BudgetError, FixedBudget, UnlimitedBudget


# --------------------------------------------------------------------------- #
# Minimal wasm binary encoder
# --------------------------------------------------------------------------- #

def uleb(n: int) -> bytes:
    return bytes(pywasm.leb128.u.encode(n))


def section(id: int, payload: bytes) -> bytes:
    return bytes([id]) + uleb(len(payload)) + payload


def vec(items: list[bytes]) -> bytes:
    return uleb(len(items)) + b''.join(items)


def functype(params: list[int], results: list[int]) -> bytes:
    return b'\x60' + uleb(len(params)) + bytes(params) + uleb(len(results)) + bytes(results)


def mod(types: list[bytes] = None, imports: bytes = b'', funcs: bytes = b'',
        exports: list[tuple[str, int, int]] = None, start: int | None = None,
        codes: list[bytes] = None) -> bytes:
    out = b'\x00asm\x01\x00\x00\x00'
    if types:
        out += section(1, vec(types))
    if imports:
        out += section(2, imports)
    if funcs:
        out += section(3, funcs)
    if exports:
        entries = []
        for name, kind, idx in exports:
            name_b = name.encode()
            entries.append(uleb(len(name_b)) + name_b + bytes([kind]) + uleb(idx))
        out += section(7, vec(entries))
    if start is not None:
        out += section(8, uleb(start))
    if codes:
        bodies = []
        for body in codes:
            bodies.append(uleb(len(body)) + body)
        out += section(10, vec(bodies))
    return out


I32 = 0x7f
I32_CONST, LOCAL_GET, LOCAL_SET, CALL, BLOCK, LOOP, BR_IF, I32_ADD, I32_GE_U, END = (
    0x41, 0x20, 0x21, 0x10, 0x02, 0x03, 0x0d, 0x6a, 0x4f, 0x0b
)


def const(n: int) -> bytes:
    return bytes([I32_CONST]) + uleb(n)


def loop_n(n_param_local: int) -> bytes:
    # (func (param i32) (result i32)
    #   block
    #     loop
    #       local.get 0
    #       i32.const N
    #       i32.ge_u
    #       br_if 1
    #       local.get 0
    #       i32.const 1
    #       i32.add
    #       local.set 0
    #       br 0
    #     end
    #   end
    #   local.get 0)
    return (
        b'\x00'  # 0 local declarations
        + bytes([BLOCK, 0x40, LOOP, 0x40])
        + bytes([LOCAL_GET]) + uleb(n_param_local)
        + const(10)
        + bytes([I32_GE_U, BR_IF, 1])
        + bytes([LOCAL_GET]) + uleb(n_param_local)
        + const(1)
        + bytes([I32_ADD, LOCAL_SET]) + uleb(n_param_local)
        + bytes([0x0c, 0, END, END])  # br 0, end loop, end block
        + bytes([LOCAL_GET]) + uleb(n_param_local)
        + bytes([END])
    )


def loop_module() -> bytes:
    # type 0: (i32) -> i32 ; func 0 "count"
    return mod(
        types=[functype([I32], [I32])],
        funcs=vec([uleb(0)]),
        exports=[('count', 0x00, 0)],
        codes=[loop_n(0)],
    )


def double_module() -> bytes:
    # func "double"(n) = n + n; used as the target of a host-to-wasm reentry, so the nested result depends on
    # the argument the suspended caller passes in.
    body = (
        b'\x00'
        + bytes([LOCAL_GET, 0, LOCAL_GET, 0, I32_ADD, END])
    )
    return mod(
        types=[functype([I32], [I32])],
        funcs=vec([uleb(0)]),
        exports=[('double', 0x00, 0)],
        codes=[body],
    )


def import_module() -> bytes:
    return _import_module('tick')


def import_module_with_reentry() -> bytes:
    # Same shape as import_module, but the loop calls the "reenter" host (which itself calls back into wasm).
    return _import_module('reenter')


def _import_module(host_name: str) -> bytes:
    # type 0: (i32)->i32 host work; type 1: ()->i32 host "refresh"
    # module-local func indices: 0 = work import, 1 = refresh, 2 = step, 3 = run.
    name = lambda s: uleb(len(s)) + s.encode()
    imports = vec([
        name('env') + name(host_name) + bytes([0x00]) + uleb(0),
        name('env') + name('refresh') + bytes([0x00]) + uleb(1),
    ])
    # step(n): work(n) + 1
    step = (
        b'\x00'
        + bytes([LOCAL_GET, 0, CALL, 0])  # call the imported work function
        + const(1) + bytes([I32_ADD, END])
    )
    # run(n): n iterations: local0 = step(local0), loop until local0 >= 10.
    run = (
        b'\x00'
        + bytes([BLOCK, 0x40, LOOP, 0x40])
        + bytes([LOCAL_GET, 0]) + const(10) + bytes([I32_GE_U, BR_IF, 1])
        + bytes([LOCAL_GET, 0, CALL, 2, LOCAL_SET, 0])  # local0 = step(local0)
        + bytes([0x0c, 0, END, END])
        + bytes([LOCAL_GET, 0, END])
    )
    return mod(
        types=[functype([I32], [I32]), functype([], [I32])],
        imports=imports,
        funcs=vec([uleb(0), uleb(0)]),  # func 2 -> type 0, func 3 -> type 0
        # Exports use store addresses: 0 work, 1 refresh (imports), 2 step, 3 run.
        exports=[('run', 0x00, 3)],
        codes=[step, run],
    )


def start_module() -> bytes:
    # start function runs a fixed 0..10 loop at instantiation, no result.
    # type 0: () -> () ; func 0 (local i32 counter at local 0)
    body = (
        b'\x01' + bytes([1, I32])  # 1 local group: one i32
        + bytes([I32_CONST, 0, LOCAL_SET, 0])
        + bytes([BLOCK, 0x40, LOOP, 0x40])
        + bytes([LOCAL_GET, 0]) + const(10) + bytes([I32_GE_U, BR_IF, 1])
        + bytes([LOCAL_GET, 0]) + const(1) + bytes([I32_ADD, LOCAL_SET, 0])
        + bytes([0x0c, 0, END, END, END])
    )
    return mod(
        types=[functype([], [])],
        funcs=vec([uleb(0)]),
        start=0,
        codes=[body],
    )


# --------------------------------------------------------------------------- #
# Helpers and fake host functions
# --------------------------------------------------------------------------- #

def new_runtime() -> core.Runtime:
    return core.Runtime()


def instance(runtime: core.Runtime, data: bytes) -> core.ModuleInst:
    return runtime.instance_from_reader(io.BytesIO(data))


class SideEffectLog:
    # A fake external side effect. A host must charge the budget *before* appending, so once the budget is
    # exhausted the log can no longer grow.
    def __init__(self) -> None:
        self.events: list[int] = []

    def tick(self, machine: core.Machine, args: list[int]) -> list[int]:
        machine.charge(5, 'host:tick')  # authorized host work, drawn from the task budget
        self.events.append(args[0])
        return [args[0]]

    def refresh(self, machine: core.Machine, args: list[int]) -> list[int]:
        # Attempt to mint fresh quota by opening a nested task scope. Nested scopes inherit the active budget,
        # so the new FixedBudget is ignored and the enclosing one keeps draining.
        nested = FixedBudget(1_000_000)
        with machine.task_scope(nested):
            assert machine.budget is not nested  # the fresh budget is never installed
            machine.charge(1, 'host:refresh')
        return [42]

    def make_reenter(self, runtime: core.Runtime, target: core.ModuleInst, func: str = 'double'):
        # A host that does some charged work and then calls back into wasm while its own frame is suspended.
        def reenter(machine: core.Machine, args: list[int]) -> list[int]:
            machine.charge(3, 'host:reenter')
            return runtime.invocate_reentry(target, func, [args[0]])
        return reenter


def bind_imports(runtime: core.Runtime, effects: SideEffectLog) -> None:
    runtime.imports['env'] = {
        'tick': runtime.allocate_func_host(
            core.FuncType([core.ValType.i32()], [core.ValType.i32()]), effects.tick),
        'refresh': runtime.allocate_func_host(
            core.FuncType([], [core.ValType.i32()]), effects.refresh),
    }


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_loop_consumes_budget_and_completes() -> None:
    runtime = new_runtime()
    module = instance(runtime, loop_module())
    budget = UnlimitedBudget()
    with runtime.task_scope(budget):
        result = runtime.invocate(module, 'count', [0])
    assert result == [10]
    assert budget.spent > 30  # every loop iteration is several metered instructions


def test_exhaustion_aborts_task_without_further_side_effects() -> None:
    runtime = new_runtime()
    effects = SideEffectLog()
    bind_imports(runtime, effects)
    module = instance(runtime, import_module())
    budget = FixedBudget(40)  # full run needs 177 units; 40 stops after a couple of ticks
    try:
        with runtime.task_scope(budget):
            runtime.invocate(module, 'run', [0])
    except BudgetError as exc:
        assert exc.budget is budget
    else:
        raise AssertionError('expected BudgetError')
    assert budget.exhausted()
    assert len(effects.events) < 10  # the task died mid-loop
    # While the dead task's budget object is still around, every further charge on it keeps failing, so a host
    # holding that reference can never squeeze out another side effect after exhaustion.
    frozen = list(effects.events)
    for _ in range(3):
        try:
            budget.charge(1, 'after-exhaustion')
        except BudgetError:
            continue
        raise AssertionError('an exhausted budget must reject every later charge')
    assert effects.events == frozen  # the external log stays frozen after exhaustion
    # Leaving the scope detaches the dead budget so the machine is ready for the next task.
    assert runtime.machine.budget is None


def test_budget_covers_module_initialization() -> None:
    runtime = new_runtime()
    # The start function alone burns more than a handful of instructions; a tiny budget must trap during
    # instantiation, before any invocation happens.
    try:
        with runtime.task_scope(FixedBudget(5)):
            instance(runtime, start_module())
    except BudgetError:
        return
    raise AssertionError('start function must be metered by the task budget')


def test_nested_calls_share_one_budget() -> None:
    runtime = new_runtime()
    effects = SideEffectLog()
    bind_imports(runtime, effects)
    module = instance(runtime, import_module())
    budget = UnlimitedBudget()
    with runtime.task_scope(budget):
        result = runtime.invocate(module, 'run', [0])
    assert result == [10]
    # run -> step -> tick for each of the 10 iterations, all charged to the single task budget.
    assert len(effects.events) == 10
    assert budget.spent > 50
    assert budget.remaining() == -1  # unlimited budget reports -1 while still counting work


def test_nested_task_scope_cannot_refresh_quota() -> None:
    # A host that opens its own task scope with a brand-new budget must keep using the enclosing one.
    runtime = new_runtime()
    effects = SideEffectLog()
    bind_imports(runtime, effects)
    module = instance(runtime, import_module())
    outer = FixedBudget(40)
    try:
        with runtime.task_scope(outer):
            runtime.invocate(module, 'run', [0])
    except BudgetError as exc:
        assert exc.budget is outer
    else:
        raise AssertionError('a nested task scope must not grant fresh quota')
    assert outer.exhausted()


def test_host_reentry_inherits_budget_and_cannot_add_quota() -> None:
    # The host calls back into wasm (Runtime.invocate_reentry) while its own frame is suspended. Both the host
    # work and every instruction of the nested wasm call drain the single task budget, and exhaustion inside
    # the nested call aborts the whole task.
    runtime = new_runtime()
    target = instance(runtime, double_module())
    effects = SideEffectLog()
    bind_imports(runtime, effects)
    reenter = effects.make_reenter(runtime, target)
    runtime.imports['env']['reenter'] = runtime.allocate_func_host(
        core.FuncType([core.ValType.i32()], [core.ValType.i32()]), reenter)
    module = instance(runtime, import_module_with_reentry())

    budget = UnlimitedBudget()
    with runtime.task_scope(budget):
        result = runtime.invocate(module, 'run', [1])
    # step(n) = double(n) + 1: 1 -> 3 -> 7 -> 15 (>= 10), proving the nested wasm result flows back through
    # the host into the suspended computation.
    assert result == [15]
    # The nested wasm instructions are metered by the same budget. Charge accounting: each of the 3 iterations
    # pays the host's 3 units plus the three double-body instructions (local.get, local.get, i32.add) on top of
    # the outer loop instructions, so the total comfortably exceeds the 9 host units alone.
    assert budget.spent > 3 * 3

    # A budget that covers the host charge but not the nested wasm instructions must trap inside double,
    # proving the re-entered wasm code draws from the same budget rather than getting fresh quota.
    host_only = FixedBudget(40)
    try:
        with runtime.task_scope(host_only):
            runtime.invocate(module, 'run', [1])
    except BudgetError as exc:
        assert exc.budget is host_only
        assert exc.reason.startswith('instruction:')  # exhausted by a nested wasm instruction
    else:
        raise AssertionError('re-entering the runtime must not grant fresh quota')
    assert host_only.exhausted()


def test_machine_stack_is_cleaned_after_abort() -> None:
    runtime = new_runtime()
    module = instance(runtime, loop_module())
    try:
        with runtime.task_scope(FixedBudget(10)):
            runtime.invocate(module, 'count', [0])
    except BudgetError:
        pass
    machine = runtime.machine
    assert machine.budget is None  # scope exited
    assert machine.stack.frame == []
    assert machine.stack.label == []
    assert machine.stack.value == []


def test_next_task_runs_normally_after_abort() -> None:
    runtime = new_runtime()
    effects = SideEffectLog()
    bind_imports(runtime, effects)
    module = instance(runtime, import_module())
    try:
        with runtime.task_scope(FixedBudget(20)):
            runtime.invocate(module, 'run', [0])
    except BudgetError:
        pass
    # A fresh task with its own budget on the same runtime/store must succeed and run all 10 iterations.
    before = len(effects.events)
    fresh = UnlimitedBudget()
    with runtime.task_scope(fresh):
        result = runtime.invocate(module, 'run', [0])
    assert result == [10]
    assert len(effects.events) - before == 10
    assert fresh.spent > 0


def test_runtime_without_budget_is_unmetered() -> None:
    # Backwards compatibility: no task scope means no metering at all.
    runtime = new_runtime()
    module = instance(runtime, loop_module())
    assert runtime.invocate(module, 'count', [0]) == [10]
    assert runtime.machine.budget is None


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for test in tests:
        test()
        print(f'ok  {test.__name__}')
    print(f'{len(tests)} budget tests passed')


if __name__ == '__main__':
    main()

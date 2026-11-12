import pywasm

# Verify per-task memory quota attribution across multiple Wasm instances in one runtime: initial
# allocation, memory.grow, host-side buffers, explicitly approved shared imported memory, growth
# failure consistency, and task end release/transfer reporting.

PAGE = 64 * 1024


def module_shared() -> pywasm.ModuleDesc:
    # Imports env.mem and exports grow(n)->i32 / size()->i32 operating on memory 0 (the import).
    return pywasm.ModuleDesc(
        type=[
            pywasm.FuncType([pywasm.ValType.i32()], [pywasm.ValType.i32()]),
            pywasm.FuncType([], [pywasm.ValType.i32()]),
        ],
        func=[
            pywasm.FuncDesc(0, [], pywasm.Expr([
                pywasm.Inst(pywasm.opcode.local_get, [0]),
                pywasm.Inst(pywasm.opcode.memory_grow, [0]),
            ])),
            pywasm.FuncDesc(1, [], pywasm.Expr([
                pywasm.Inst(pywasm.opcode.memory_size, [0]),
            ])),
        ],
        tabl=[],
        mems=[],
        glob=[],
        elem=[],
        data=[],
        star=-1,
        imps=[pywasm.Import('env', 'mem', 0x02, pywasm.MemType(pywasm.Limits(1, 8)))],
        exps=[
            pywasm.ExportDesc('grow', 0x00, 0),
            pywasm.ExportDesc('size', 0x00, 1),
        ],
    )


def module_own() -> pywasm.ModuleDesc:
    # Defines its own exclusive memory (1 page initial, 8 max) and exports grow/size.
    desc = module_shared()
    desc.mems = [pywasm.MemType(pywasm.Limits(1, 8))]
    desc.imps = []
    return desc


def main() -> None:
    pywasm.log.lvl = 0
    ledger = pywasm.Ledger()
    runtime = pywasm.Runtime(ledger=ledger)

    task_a = ledger.create_task('A', 4 * PAGE)
    task_b = ledger.create_task('B', 6 * PAGE)

    # Host creates a shared memory of 1 page, charged to task A.
    shared = runtime.allocate_memory(pywasm.MemType(pywasm.Limits(1, 8)), task=task_a)
    assert task_a.used == 1 * PAGE
    runtime.imports.setdefault('env', {})['mem'] = shared

    # Sharing must be explicitly approved per task.
    unapproved = ledger.create_task('U', 4 * PAGE)
    try:
        runtime.instance(module_shared(), task=unapproved)
        raise AssertionError('unapproved shared import must fail')
    except pywasm.ShareNotApproved:
        pass
    assert unapproved.used == 0 and not runtime.machine.store.mems[-1].size == 0

    ledger.mem_approve(task_a, runtime.machine.store.mems[shared.data])
    ledger.mem_approve(task_b, runtime.machine.store.mems[shared.data])

    # Two instances share the imported memory; each also owns an exclusive memory.
    inst_a_shared = runtime.instance(module_shared(), task=task_a)
    inst_a_own = runtime.instance(module_own(), task=task_a)
    inst_b_shared = runtime.instance(module_shared(), task=task_b)
    inst_b_own = runtime.instance(module_own(), task=task_b)
    # A: 1 (shared initial) + 1 (own) = 2 pages. B: 1 (own). Sharing charged nothing extra.
    assert task_a.used == 2 * PAGE, task_a
    assert task_b.used == 1 * PAGE, task_b

    # Growth is charged to the growing instance's task, even on the shared memory.
    assert runtime.invocate(inst_a_shared, 'grow', [1]) == [1]
    assert task_a.used == 3 * PAGE
    assert runtime.invocate(inst_b_shared, 'grow', [1]) == [2]
    assert task_b.used == 2 * PAGE
    mem = runtime.machine.store.mems[shared.data]
    account = ledger.mems[id(mem)]
    # No double charge, no miss: contributions sum to the actual memory size.
    assert account.charged() == mem.size * PAGE == 3 * PAGE
    assert runtime.invocate(inst_a_shared, 'size', []) == [3]

    # Host-side buffer charged to task B.
    buf = runtime.host_buffer(task_b, 1 * PAGE, label='decode-scratch')
    assert task_b.used == 3 * PAGE

    # Growth failure: task A has 1 page of headroom; growing the shared memory by 2 must fail.
    used_before, size_before = task_a.used, mem.size
    assert runtime.invocate(inst_a_shared, 'grow', [2]) == [-1]
    # After denial, existing memory and quota are untouched, and permissions still work:
    # task B can still grow the same shared memory.
    assert task_a.used == used_before and mem.size == size_before
    assert runtime.invocate(inst_b_shared, 'grow', [1]) == [3]
    assert task_b.used == 4 * PAGE

    # Denied instantiation rolls back: task C with room for the shared import only.
    task_c = ledger.create_task('C', 1 * PAGE)
    ledger.mem_approve(task_c, mem)
    mems_len = len(runtime.machine.store.mems)
    try:
        runtime.instance(module_own(), task=task_c)  # needs 1 page, fits
        runtime.instance(module_own(), task=task_c)  # needs 1 more, exceeds
        raise AssertionError('second instantiation must exceed quota')
    except pywasm.QuotaExceeded:
        pass
    assert task_c.used == 1 * PAGE
    assert len(runtime.machine.store.mems) == mems_len + 1

    # Denied host buffer leaves existing state consistent.
    try:
        runtime.host_buffer(task_a, 2 * PAGE, label='too-big')
        raise AssertionError('host buffer must exceed quota')
    except pywasm.QuotaExceeded:
        pass
    assert task_a.used == 3 * PAGE

    # End task A: its exclusive memory is freed; the shared memory survives because B still
    # references it, and A's contribution is transferred to B.
    report_a = runtime.end_task(task_a)
    print(report_a)
    assert task_a.used == 0 and task_a.ended
    assert any('freed' in e for e in report_a.freed)
    assert any('transferred to B' in e for e in report_a.transferred)
    assert mem.size == 4  # shared memory untouched, still usable by B
    assert runtime.invocate(inst_b_shared, 'size', []) == [4]
    # B now carries its own 4 pages plus A's transferred 2 pages.
    assert task_b.used == 6 * PAGE
    assert account.charged() == mem.size * PAGE

    # End task B: the shared memory has no surviving sharers and is freed; the still-open host
    # buffer is released by the task end.
    report_b = runtime.end_task(task_b)
    print(report_b)
    assert task_b.used == 0
    assert any('freed' in e for e in report_b.freed)
    assert any('decode-scratch' in e for e in report_b.released_host)
    assert buf.closed
    assert mem.size == 0 and id(mem) not in ledger.mems

    print('quota: all checks passed')


if __name__ == '__main__':
    main()

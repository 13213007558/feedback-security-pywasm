# Resource budget tests. Every module here is assembled by hand so the suite stays
# self-contained: no wabt tools or downloaded spec files are required.
#
# Run with: python test/budget.py

import io
import os
import pathlib

import pywasm
from pywasm import leb128


def u(n: int) -> bytes:
    return bytes(leb128.u.encode(n))


def section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + u(len(payload)) + payload


def minimal_module() -> bytes:
    # One i32 function returning the constant 42, exported as "f".
    b = b'\x00asm\x01\x00\x00\x00'
    b += section(1, u(1) + b'\x60' + u(0) + u(1) + b'\x7f')
    b += section(3, u(1) + u(0))
    b += section(7, u(1) + b'\x01f' + b'\x00' + u(0))
    body = u(0) + b'\x41' + u(42) + b'\x0b'
    b += section(10, u(1) + u(len(body)) + body)
    return b


def memory_module(pages: int) -> bytes:
    return b'\x00asm\x01\x00\x00\x00' + section(5, u(1) + b'\x00' + u(pages))


def table_module(elems: int) -> bytes:
    # funcref table with an element type byte (0x70) and a minimum size.
    return b'\x00asm\x01\x00\x00\x00' + section(4, u(1) + b'\x70' + b'\x00' + u(elems))


def huge_func_section(count: int) -> bytes:
    # The declared function count is never realizable within the input; a budget-aware
    # decoder must reject it before entering the (unbounded) allocation loop.
    return b'\x00asm\x01\x00\x00\x00' + section(3, u(count))


def expect_reject(fn, reason: str) -> pywasm.BudgetExceeded:
    try:
        fn()
    except pywasm.BudgetExceeded as e:
        assert e.reason == reason, (e.reason, reason)
        return e
    raise AssertionError(f'expected BudgetExceeded({reason})')


def store_is_empty(rt: pywasm.core.Runtime) -> bool:
    s = rt.machine.store
    return not (s.func or s.tabl or s.mems or s.glob or s.elem or s.data)


def test_parity_without_budget():
    data = minimal_module()
    rt_a = pywasm.core.Runtime()
    a = rt_a.invocate(rt_a.instance_from_reader(io.BytesIO(data)), 'f', [])
    rt_b = pywasm.core.Runtime()
    b = rt_b.invocate(rt_b.instance_from_reader(io.BytesIO(data), None), 'f', [])
    rt_c = pywasm.core.Runtime()
    c = rt_c.invocate(
        rt_c.instance_from_reader(io.BytesIO(data), pywasm.Budget()), 'f', []
    )
    assert a == b == c == [42]
    print('test_parity_without_budget passed')


def test_real_module_parity():
    path = str(pathlib.Path('example/fibonacci/bin/fibonacci.wasm'))
    rt_a = pywasm.core.Runtime()
    a = rt_a.invocate(rt_a.instance_from_file(path), 'fibonacci', [10])
    rt_b = pywasm.core.Runtime()
    m_b = rt_b.instance_from_file(path, pywasm.Budget(1 << 30, 1 << 30, 1 << 30))
    b = rt_b.invocate(m_b, 'fibonacci', [10])
    assert a == b == [55], (a, b)
    print('test_real_module_parity passed')


def test_input_bytes_boundary():
    data = minimal_module()
    # The decoder performs one extra read at end of stream to detect EOF, so an exact
    # admission limit is one byte above the delivered module size.
    exact = pywasm.Budget(input_bytes=len(data) + 1)
    rt = pywasm.core.Runtime()
    rt.instance_from_reader(io.BytesIO(data), exact)
    assert exact.used_input_bytes == len(data)

    short = pywasm.Budget(input_bytes=len(data))
    e = expect_reject(
        lambda: pywasm.core.Runtime().instance_from_reader(io.BytesIO(data), short),
        pywasm.Reason.INPUT_BYTES,
    )
    # The whole module is refused, so nothing reaches the store.
    assert short.used_input_bytes == len(data)
    assert e.used + e.requested == len(data) + 1
    print('test_input_bytes_boundary passed')


def test_struct_entries_boundary():
    data = minimal_module()
    generous = pywasm.Budget(struct_entries=6)
    pywasm.core.Runtime().instance_from_reader(io.BytesIO(data), generous)
    assert generous.used_struct_entries == 6

    tight = pywasm.Budget(struct_entries=5)
    expect_reject(
        lambda: pywasm.core.Runtime().instance_from_reader(io.BytesIO(data), tight),
        pywasm.Reason.STRUCT_ENTRIES,
    )
    print('test_struct_entries_boundary passed')


def test_planned_allocations_boundary():
    data = minimal_module()
    ok = pywasm.Budget(planned_allocations=2)
    pywasm.core.Runtime().instance_from_reader(io.BytesIO(data), ok)
    assert ok.used_planned_allocations == 2

    tight = pywasm.Budget(planned_allocations=1)
    expect_reject(
        lambda: pywasm.core.Runtime().instance_from_reader(io.BytesIO(data), tight),
        pywasm.Reason.PLANNED_ALLOCATIONS,
    )
    print('test_planned_allocations_boundary passed')


def test_memory_pages_count_as_allocations():
    # A two-page memory costs 3 units: one MemInst plus its two 64KiB backing pages.
    data = memory_module(2)
    bg = pywasm.Budget(planned_allocations=3)
    rt = pywasm.core.Runtime()
    rt.instance_from_reader(io.BytesIO(data), bg)
    assert bg.used_planned_allocations == 3
    assert rt.machine.store.mems[0].size == 2

    one_short = pywasm.Budget(planned_allocations=2)
    expect_reject(
        lambda: pywasm.core.Runtime().instance_from_reader(io.BytesIO(data), one_short),
        pywasm.Reason.PLANNED_ALLOCATIONS,
    )
    print('test_memory_pages_count_as_allocations passed')


def test_table_elements_count_as_allocations():
    # One TableInst plus four pre-allocated reference slots.
    data = table_module(4)
    bg = pywasm.Budget(planned_allocations=5)
    rt = pywasm.core.Runtime()
    rt.instance_from_reader(io.BytesIO(data), bg)
    assert bg.used_planned_allocations == 5
    assert rt.machine.store.tabl[0].size == 4
    print('test_table_elements_count_as_allocations passed')


def test_huge_declared_vector_rejected_early():
    data = huge_func_section(1 << 30)
    rt = pywasm.core.Runtime()
    bg = pywasm.Budget(input_bytes=1 << 20, struct_entries=16)

    class TrackingReader(io.BytesIO):
        def __init__(self, *a):
            super().__init__(*a)
            self.largest_read = 0

        def read(self, size=-1):
            if size is not None and size > 0:
                self.largest_read = max(self.largest_read, size)
            return super().read(size)

    reader = TrackingReader(data)
    e = expect_reject(
        lambda: rt.instance_from_reader(reader, bg),
        pywasm.Reason.STRUCT_ENTRIES,
    )
    # The rejection happens on the declared count, so no giant structure is built and no
    # oversized read ever reaches the underlying stream.
    assert reader.largest_read <= pywasm.budget.BudgetedReader.CHUNK
    assert e.requested == 1 << 30
    assert store_is_empty(rt)
    print('test_huge_declared_vector_rejected_early passed')


def test_large_data_section_rejected_before_read():
    # One passive data segment advertising a 1 MiB payload. A tight input budget must
    # reject during section decoding, before the million bytes are buffered, and no data
    # instance may survive in the store.
    payload = u(1) + bytes([1]) + u(0x100000) + b'\x00' * 0x100000
    data = b'\x00asm\x01\x00\x00\x00' + section(0x0b, payload)

    class TrackingReader(io.BytesIO):
        def __init__(self, *a):
            super().__init__(*a)
            self.largest_read = 0

        def read(self, size=-1):
            if size is not None and size > 0:
                self.largest_read = max(self.largest_read, size)
            return super().read(size)

    rt = pywasm.core.Runtime()
    reader = TrackingReader(data)
    expect_reject(
        lambda: rt.instance_from_reader(reader, pywasm.Budget(input_bytes=64)),
        pywasm.Reason.INPUT_BYTES,
    )
    assert reader.largest_read <= pywasm.budget.BudgetedReader.CHUNK
    assert store_is_empty(rt)
    print('test_large_data_section_rejected_before_read passed')


def test_truncation_refunds_reserved_bytes():
    data = minimal_module()
    cut = len(data) - 5

    # Without a budget the truncation surfaces as the pre-existing decode assertion.
    try:
        pywasm.core.Runtime().instance_from_reader(io.BytesIO(data[:cut]))
    except AssertionError:
        pass
    else:
        raise AssertionError('truncated module should fail the section length check')

    # With a budget the same malformed input fails the same way (it is not misreported as
    # a budget rejection), and only the bytes actually delivered stay charged.
    bg = pywasm.Budget(input_bytes=len(data))
    try:
        pywasm.core.Runtime().instance_from_reader(io.BytesIO(data[:cut]), bg)
    except AssertionError:
        pass
    else:
        raise AssertionError('truncated module should fail the section length check')
    assert bg.used_input_bytes == cut, (bg.used_input_bytes, cut)
    print('test_truncation_refunds_reserved_bytes passed')


def test_truncated_header():
    bg = pywasm.Budget(input_bytes=64)
    try:
        pywasm.core.Runtime().instance_from_reader(io.BytesIO(b'\x00asm\x01'), bg)
    except (AssertionError, EOFError):
        pass
    else:
        raise AssertionError('truncated magic/version should be rejected')
    # The eight header bytes never arrived; the budget must not hold them against us.
    assert bg.used_input_bytes == 5
    print('test_truncated_header passed')


def test_admission_rejection_leaves_empty_store():
    # A two-page memory needs 3 allocation units; refuse after one.
    data = memory_module(2)
    rt = pywasm.core.Runtime()
    bg = pywasm.Budget(planned_allocations=1)
    expect_reject(
        lambda: rt.instance_from_reader(io.BytesIO(data), bg),
        pywasm.Reason.PLANNED_ALLOCATIONS,
    )
    assert store_is_empty(rt)
    print('test_admission_rejection_leaves_empty_store passed')


def test_allocate_rolls_back_partial_store():
    # An impossible memory minimum passes decode but makes MemInst.grow fail while the
    # store is being populated. The rollback must erase everything created so far.
    data = memory_module(70000)
    rt = pywasm.core.Runtime()
    try:
        rt.instance_from_reader(io.BytesIO(data), pywasm.Budget())
    except AssertionError:
        pass
    else:
        raise AssertionError('oversized memory should fail admission')
    assert store_is_empty(rt)
    print('test_allocate_rolls_back_partial_store passed')


def test_reader_and_file_paths_share_budget():
    data = minimal_module()
    limit = len(data) + 1
    bg_reader = pywasm.Budget(input_bytes=limit)
    pywasm.core.Runtime().instance_from_reader(io.BytesIO(data), bg_reader)

    path = pathlib.Path(os.environ['TMPDIR']) / 'budget_minimal.wasm'
    path.write_bytes(data)
    bg_file = pywasm.Budget(input_bytes=limit)
    pywasm.core.Runtime().instance_from_file(str(path), bg_file)
    assert bg_reader.used_input_bytes == bg_file.used_input_bytes == len(data)
    print('test_reader_and_file_paths_share_budget passed')


if __name__ == '__main__':
    test_parity_without_budget()
    test_real_module_parity()
    test_input_bytes_boundary()
    test_struct_entries_boundary()
    test_planned_allocations_boundary()
    test_memory_pages_count_as_allocations()
    test_table_elements_count_as_allocations()
    test_huge_declared_vector_rejected_early()
    test_large_data_section_rejected_before_read()
    test_truncation_refunds_reserved_bytes()
    test_truncated_header()
    test_admission_rejection_leaves_empty_store()
    test_allocate_rolls_back_partial_store()
    test_reader_and_file_paths_share_budget()
    print('all budget tests passed')

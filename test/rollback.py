# Transactional instantiation tests.
#
# A single pywasm Runtime loads user modules one after another into one shared Store. Each instantiation must be an
# all-or-nothing transaction: a failure during import matching, data segment initialization or the start function
# reclaims every store entity allocated by that attempt, resets the machine stack, and leaves entities owned by
# already running instances - including the import objects they share - untouched.
#
# The wasm modules below are encoded by hand so the suite needs no external toolchain (wat2wasm/wasm-tools).
import io
import os
import pywasm
import tempfile


MAGIC = b'\x00asm\x01\x00\x00\x00'


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        done = (n == 0 and (b & 0x40) == 0) or (n == -1 and (b & 0x40) != 0)
        if done:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + uleb(len(payload)) + payload


def vec(items: list[bytes]) -> bytes:
    return uleb(len(items)) + b''.join(items)


def name(s: str) -> bytes:
    raw = s.encode()
    return uleb(len(raw)) + raw


def functype(params: list[int], results: list[int]) -> bytes:
    return b'\x60' + uleb(len(params)) + bytes(params) + uleb(len(results)) + bytes(results)


def const_expr_i32(value: int) -> bytes:
    return b'\x41' + sleb(value) + b'\x0b'


def func_body(locals: list[tuple[int, int]], code: bytes) -> bytes:
    payload = vec([uleb(n) + bytes([t]) for t, n in locals]) + code + b'\x0b'
    return uleb(len(payload)) + payload


class WasmBuilder:
    # Builds a minimal module: optional host import, one memory, active/passive data segments, globals, functions and
    # an optional start function. Only the encoding surface needed by these tests is covered.
    def __init__(self) -> None:
        self.types: list[bytes] = []
        self.imports: list[bytes] = []
        self.func_types: list[int] = []
        self.mems: list[bytes] = []
        self.globals: list[bytes] = []
        self.exports: list[bytes] = []
        self.start: int | None = None
        self.elems: list[bytes] = []
        self.codes: list[bytes] = []
        self.datas: list[bytes] = []

    def add_type(self, params: list[int], results: list[int]) -> int:
        self.types.append(functype(params, results))
        return len(self.types) - 1

    def import_func(self, module: str, field: str, tidx: int) -> int:
        self.imports.append(name(module) + name(field) + b'\x00' + uleb(tidx))
        return len(self.imports) - 1

    def add_func(self, tidx: int, locals: list[tuple[int, int]], code: bytes) -> int:
        self.func_types.append(uleb(tidx))
        self.codes.append(func_body(locals, code))
        return len(self.imports) + len(self.func_types) - 1

    def add_memory(self, min_pages: int, max_pages: int | None = None) -> None:
        if max_pages is None:
            self.mems.append(b'\x00' + uleb(min_pages))
        else:
            self.mems.append(b'\x01' + uleb(min_pages) + uleb(max_pages))

    def add_global(self, valtype: int, mut: int, init: bytes) -> None:
        self.globals.append(bytes([valtype, mut]) + init)

    def export(self, field: str, kind: int, idx: int) -> None:
        self.exports.append(name(field) + bytes([kind]) + uleb(idx))

    def set_start(self, fidx: int) -> None:
        self.start = fidx

    def active_data(self, offset: int, raw: bytes) -> None:
        # kind 0: active segment for memory 0 with an i32.const offset expression.
        self.datas.append(b'\x00' + const_expr_i32(offset) + uleb(len(raw)) + raw)

    def passive_data(self, raw: bytes) -> None:
        self.datas.append(b'\x01' + uleb(len(raw)) + raw)

    def active_elem(self, offset: int, funcs: list[int]) -> None:
        # kind 0: active funcref segment for table 0.
        self.elems.append(b'\x00' + const_expr_i32(offset) + vec([uleb(f) for f in funcs]))

    def build(self) -> bytearray:
        out = bytearray(MAGIC)
        if self.types:
            out += section(0x01, vec(self.types))
        if self.imports:
            out += section(0x02, vec(self.imports))
        if self.func_types:
            out += section(0x03, vec(self.func_types))
        if self.mems:
            out += section(0x05, vec(self.mems))
        if self.globals:
            out += section(0x06, vec(self.globals))
        if self.exports:
            out += section(0x07, vec(self.exports))
        if self.start is not None:
            out += section(0x08, uleb(self.start))
        if self.elems:
            out += section(0x09, vec(self.elems))
        if self.codes:
            out += section(0x0a, vec(self.codes))
        if self.datas:
            out += section(0x0b, vec(self.datas))
        return out

    def module(self) -> pywasm.ModuleDesc:
        return pywasm.ModuleDesc.from_reader(io.BytesIO(self.build()))


I32 = 0x7f
I32_CONST = 0x41
CALL = 0x10


def store_sizes(runtime: pywasm.core.Runtime) -> tuple[int, int, int, int, int, int]:
    s = runtime.machine.store
    return len(s.func), len(s.tabl), len(s.mems), len(s.glob), len(s.elem), len(s.data)


def make_victim(runtime: pywasm.core.Runtime) -> pywasm.core.ModuleInst:
    # A healthy module that stays alive across all the failing attempts below. Its entities must survive unchanged.
    b = WasmBuilder()
    tidx = b.add_type([I32], [I32])
    fidx = b.add_func(tidx, [], bytes([I32_CONST]) + sleb(7))
    b.add_memory(1)
    b.add_global(I32, 0x01, const_expr_i32(11))
    b.active_data(0, b'victim')
    b.export('answer', 0x00, fidx)
    b.export('memory', 0x02, 0)
    mod = runtime.instance(b.module())
    assert runtime.invocate(mod, 'answer', [0])[0] == 7
    runtime.exported_memory(mod, 'memory').put_u8(100, 0x5a)
    return mod


def assert_victim_intact(runtime: pywasm.core.Runtime, mod: pywasm.core.ModuleInst) -> None:
    assert runtime.invocate(mod, 'answer', [0])[0] == 7
    mem = runtime.exported_memory(mod, 'memory')
    assert mem.get_u8(100) == 0x5a
    assert mem.get(0, 6) == bytearray(b'victim')
    assert runtime.machine.stack.frame == []
    assert runtime.machine.stack.label == []
    assert runtime.machine.stack.value == []


def test_import_failure_allocates_nothing() -> None:
    runtime = pywasm.core.Runtime()
    victim = make_victim(runtime)
    before = store_sizes(runtime)

    b = WasmBuilder()
    tidx = b.add_type([], [])
    # The module asks for an import that was never registered.
    b.import_func('missing', 'host', tidx)
    b.add_memory(1)
    try:
        runtime.instance(b.module())
    except pywasm.LinkError:
        pass
    else:
        raise AssertionError('import failure must raise LinkError')

    # Phase 1 commits nothing: the store must be byte-identical and the stack untouched.
    assert store_sizes(runtime) == before
    assert_victim_intact(runtime, victim)

    # A type mismatch must be rejected at the same boundary, again with zero allocation. The host function itself is
    # a legitimate embedder allocation and stays in the store; only the failed instantiation must commit nothing.
    runtime.imports['env'] = {
        'host': runtime.allocate_func_host(
            pywasm.core.FuncType([pywasm.core.ValType.i32()], [pywasm.core.ValType.i32()]),
            lambda m, a: [a[0] + 1],
        )
    }
    before = store_sizes(runtime)
    bad = WasmBuilder()
    bad_tidx = bad.add_type([], [])
    bad.import_func('env', 'host', bad_tidx)
    bad.add_memory(2)
    bad.active_data(0, b'x')
    try:
        runtime.instance(bad.module())
    except pywasm.LinkError:
        pass
    else:
        raise AssertionError('type mismatch must raise LinkError')
    assert store_sizes(runtime) == before
    assert_victim_intact(runtime, victim)
    print('test_import_failure_allocates_nothing ok')


def test_data_segment_failure_rolls_back() -> None:
    runtime = pywasm.core.Runtime()
    victim = make_victim(runtime)
    before = store_sizes(runtime)

    # memory is one page (64KiB). The active segment writes beyond its end, so memory_init traps during phase 2,
    # after the module's function/memory/global/data entities have already been allocated.
    b = WasmBuilder()
    tidx = b.add_type([], [])
    b.add_func(tidx, [], b'')
    b.add_memory(1)
    b.add_global(I32, 0x00, const_expr_i32(3))
    b.active_data(64 * 1024 - 2, b'abcd')
    b.passive_data(b'passive')
    try:
        runtime.instance(b.module())
    except pywasm.Trap:
        pass
    else:
        raise AssertionError('out-of-bounds data init must raise Trap')

    # Everything the failed attempt allocated must be reclaimed; addresses of the victim stay valid and unchanged.
    assert store_sizes(runtime) == before
    assert_victim_intact(runtime, victim)

    # After rollback the store must still accept a healthy new instance (no dangling tail / index holes).
    again = WasmBuilder()
    again_tidx = again.add_type([], [])
    again.add_func(again_tidx, [], b'')
    again.add_memory(1)
    again.active_data(0, b'again')
    again.export('memory', 0x02, 0)
    mod = runtime.instance(again.module())
    assert runtime.exported_memory(mod, 'memory').get(0, 5) == bytearray(b'again')
    assert_victim_intact(runtime, victim)
    print('test_data_segment_failure_rolls_back ok')


def test_start_failure_rolls_back_and_keeps_imports() -> None:
    runtime = pywasm.core.Runtime()
    side_effects: list[str] = []

    def host_ping(_m: pywasm.core.Machine, _a: list[int]) -> list[int]:
        side_effects.append('ping')
        return []

    def host_trap(_m: pywasm.core.Machine, _a: list[int]) -> list[int]:
        side_effects.append('trap')
        raise pywasm.Trap('controlled host failure in start')

    ping_t = runtime.allocate_func_host(
        pywasm.core.FuncType([], []), host_ping
    )
    trap_t = runtime.allocate_func_host(
        pywasm.core.FuncType([], []), host_trap
    )
    runtime.imports['env'] = {'ping': ping_t, 'trap': trap_t}
    before = store_sizes(runtime)

    victim = make_victim(runtime)
    victim_mark = store_sizes(runtime)

    # The start function calls the trapping host import. All entities are allocated and data initialized first, so
    # this exercises the last commit boundary. The host side effect already happened once it ran; the contract is
    # that it is reported (not hidden), while all wasm-side allocations of the attempt are reclaimed.
    b = WasmBuilder()
    tidx = b.add_type([], [])
    ping_idx = b.import_func('env', 'ping', tidx)
    trap_idx = b.import_func('env', 'trap', tidx)
    start_idx = b.add_func(
        tidx,
        [],
        bytes([CALL]) + uleb(ping_idx) + bytes([CALL]) + uleb(trap_idx),
    )
    b.add_memory(1)
    b.add_global(I32, 0x00, const_expr_i32(9))
    b.active_data(0, b'startmod')
    b.set_start(start_idx)
    try:
        runtime.instance(b.module())
    except pywasm.Trap as e:
        assert 'controlled host failure' in str(e)
    else:
        raise AssertionError('trapping start must raise Trap')

    assert side_effects == ['ping', 'trap'], side_effects
    # Host allocations (ping/trap) and the victim stay; every entity of the failed module is gone.
    assert store_sizes(runtime) == victim_mark
    assert store_sizes(runtime) > before
    assert_victim_intact(runtime, victim)

    # A retry that no longer traps now succeeds and the shared host imports remain callable.
    ok = WasmBuilder()
    ok_tidx = ok.add_type([], [])
    ok_ping = ok.import_func('env', 'ping', ok_tidx)
    ok_start = ok.add_func(ok_tidx, [], bytes([CALL]) + uleb(ok_ping))
    ok.add_memory(1)
    ok.set_start(ok_start)
    runtime.instance(ok.module())
    assert side_effects == ['ping', 'trap', 'ping']
    assert_victim_intact(runtime, victim)
    print('test_start_failure_rolls_back_and_keeps_imports ok')


def test_wasi_handles_reclaimed_on_instantiation_failure() -> None:
    import platform
    if platform.system().lower() not in ['darwin', 'linux']:
        print('test_wasi_handles_reclaimed_on_instantiation_failure skipped')
        return

    with tempfile.TemporaryDirectory() as preopen:
        marker = os.path.join(preopen, 'marker')
        open(marker, 'w').write('ok')
        wasi = pywasm.wasi.Preview1(['prog'], {'/': preopen}, {})
        runtime = pywasm.core.Runtime()
        wasi.bind(runtime)
        victim = make_victim(runtime)
        before = store_sizes(runtime)

        # The preopened directory owns a real host descriptor handed out by the WASI constructor. A failing
        # instantiation must not touch it; close() is the explicit compensation that releases it afterwards.
        preopen_files = wasi.fd[wasi.FD_STDERR + 1:]
        assert preopen_files and all(f.host_status == wasi.FILE_STATUS_OPENED for f in preopen_files)
        host_fds = [f.host_fd for f in preopen_files]

        b = WasmBuilder()
        tidx = b.add_type([], [])
        # Import count mismatch: the module declares an import the runtime cannot satisfy.
        b.import_func('wasi_snapshot_preview1', 'proc_raise', tidx)
        b.add_memory(1)
        b.active_data(64 * 1024 - 1, b'zzz')
        try:
            runtime.instance(b.module())
        except pywasm.LinkError:
            pass
        else:
            raise AssertionError('wasi instantiation must fail with LinkError')

        assert store_sizes(runtime) == before
        assert_victim_intact(runtime, victim)
        # Pre-opened descriptors remain open and usable: the failed attempt did not close shared WASI handles.
        assert all(f.host_status == wasi.FILE_STATUS_OPENED for f in preopen_files)
        assert os.listdir(preopen) == ['marker']

        wasi.close()
        for fd in host_fds:
            try:
                os.fstat(fd)
            except OSError:
                continue
            raise AssertionError(f'host fd {fd} must be closed by Preview1.close()')
        # Standard streams are never owned/closed by the context.
        assert wasi.fd[wasi.FD_STDIN].host_status == wasi.FILE_STATUS_OPENED
        print('test_wasi_handles_reclaimed_on_instantiation_failure ok')


def test_repeated_loads_have_stable_addresses() -> None:
    # A failed load between two successful ones must not shift the addresses of later allocations or corrupt the
    # contiguous index space shared by running instances.
    runtime = pywasm.core.Runtime()
    first = make_victim(runtime)
    first_func_addr = [e for e in first.exps if e.name == 'answer'][0].data.data

    bad = WasmBuilder()
    bad.add_memory(1)
    bad.active_data(64 * 1024, b'overflow')
    try:
        runtime.instance(bad.module())
    except pywasm.Trap:
        pass
    else:
        raise AssertionError('expected trap')

    second = make_victim(runtime)
    # The first instance keeps resolving through its original store address.
    assert runtime.machine.store.func[first_func_addr] is not None
    assert runtime.invocate(first, 'answer', [0])[0] == 7
    assert runtime.invocate(second, 'answer', [0])[0] == 7
    print('test_repeated_loads_have_stable_addresses ok')


if __name__ == '__main__':
    test_import_failure_allocates_nothing()
    test_data_segment_failure_rolls_back()
    test_start_failure_rolls_back_and_keeps_imports()
    test_wasi_handles_reclaimed_on_instantiation_failure()
    test_repeated_loads_have_stable_addresses()
    print('all rollback tests passed')

"""End-to-end capability transitions against the real pywasm WASI preview1 host.

Each transition is executed twice: once inside the abstract CapModel and once
against pywasm.wasi.Preview1 backed by a real temp directory. The two states are
compared descriptor-by-descriptor after every step, so a failure names the
exact transition and the exact right bit that diverged instead of a raw
return-code count.

Run:  python test/capability_wasi.py
"""

import os
import pathlib
import shutil
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pywasm.core
import pywasm.wasi
from test.capmodel import CapModel, OPENED, CLOSED, BADF, NOTCAPABLE, SUCCESS

W = pywasm.wasi.Preview1

R = {
    'DATASYNC': W.RIGHTS_FD_DATASYNC,
    'READ': W.RIGHTS_FD_READ,
    'SEEK': W.RIGHTS_FD_SEEK,
    'FDSTAT_SET_FLAGS': W.RIGHTS_FD_FDSTAT_SET_FLAGS,
    'SYNC': W.RIGHTS_FD_SYNC,
    'TELL': W.RIGHTS_FD_TELL,
    'WRITE': W.RIGHTS_FD_WRITE,
    'PATH_OPEN': W.RIGHTS_PATH_OPEN,
    'READDIR': W.RIGHTS_FD_READDIR,
    'FD_FILESTAT_GET': W.RIGHTS_FD_FILESTAT_GET,
    'FD_FILESTAT_SET_SIZE': W.RIGHTS_FD_FILESTAT_SET_SIZE,
}
RW = R['READ'] | R['WRITE']
RO = R['READ']
PREOPEN_BASE = 0b00000111101111111111111000000000
PREOPEN_ROOT = 0b00001111111111111111111111111111
ALL_FD = R['READ'] | R['SEEK'] | R['TELL'] | R['WRITE'] | R['FDSTAT_SET_FLAGS'] | R['FD_FILESTAT_GET']


class StubMachine:
    """Minimal machine: the WASI host only needs a linear memory and a frame."""

    def __init__(self) -> None:
        mem_type = pywasm.core.MemType(pywasm.core.Limits(1, 0))
        module = pywasm.core.ModuleInst()
        module.mems = [0]
        self.store = pywasm.core.Store()
        self.store.allocate_memory(mem_type)
        self.stack = pywasm.core.Stack()
        self.stack.frame.append(pywasm.core.Frame(module, pywasm.core.LocalsInst([]), 0, 0, 0))

    @property
    def mem(self) -> pywasm.core.MemInst:
        return self.store.mems[0]


class Host:
    """Thin typed wrapper over the real Preview1 syscalls."""

    NAME_ADDR, OUT_ADDR, BUF_ADDR = 1024, 2048, 4096

    def __init__(self, root: str) -> None:
        self.machine = StubMachine()
        # Two preopens: dir A is the working directory, dir B stays full-power so
        # that permanently dropping PATH_OPEN on A can be compared against it.
        self.wasi = W(['cap.wasm'], {'/': root, '/b': root}, {})
        self.dirfd, self.dirfd_b = 3, 4

    def _name(self, name: str) -> None:
        data = name.encode()
        self.machine.mem.put(self.NAME_ADDR, bytearray(data))

    def path_open(self, dirfd: int, name: str, base: int, root: int, oflags: int = 0) -> tuple[int, int | None]:
        self._name(name)
        args = [dirfd, 0, self.NAME_ADDR, len(name), oflags, base, root, 0, self.OUT_ADDR]
        errno = self.wasi.path_open(self.machine, args)[0]
        return errno, (self.machine.mem.get_u32(self.OUT_ADDR) if errno == SUCCESS else None)

    def set_rights(self, fd: int, base: int, root: int) -> int:
        return self.wasi.fd_fdstat_set_rights(self.machine, [fd, base, root])[0]

    def renumber(self, src: int, dst: int) -> int:
        return self.wasi.fd_renumber(self.machine, [src, dst])[0]

    def close(self, fd: int) -> int:
        return self.wasi.fd_close(self.machine, [fd])[0]

    def fdstat(self, fd: int) -> tuple[int, int, int]:
        errno = self.wasi.fd_fdstat_get(self.machine, [fd, self.OUT_ADDR])[0]
        if errno != SUCCESS:
            return errno, 0, 0
        return errno, self.machine.mem.get_u64(self.OUT_ADDR + 8), self.machine.mem.get_u64(self.OUT_ADDR + 16)

    def read(self, fd: int) -> int:
        self.machine.mem.put_u32(self.BUF_ADDR, self.BUF_ADDR + 64)
        self.machine.mem.put_u32(self.BUF_ADDR + 4, 16)
        return self.wasi.fd_read(self.machine, [fd, self.BUF_ADDR, 1, self.OUT_ADDR])[0]

    def write(self, fd: int, payload: bytes = b'x') -> int:
        self.machine.mem.put(self.BUF_ADDR + 128, bytearray(payload))
        self.machine.mem.put_u32(self.BUF_ADDR, self.BUF_ADDR + 128)
        self.machine.mem.put_u32(self.BUF_ADDR + 4, len(payload))
        return self.wasi.fd_write(self.machine, [fd, self.BUF_ADDR, 1, self.OUT_ADDR])[0]

    def seek(self, fd: int) -> int:
        return self.wasi.fd_seek(self.machine, [fd, 0, W.WHENCE_CUR, self.OUT_ADDR])[0]

    def tell(self, fd: int) -> int:
        return self.wasi.fd_tell(self.machine, [fd, self.OUT_ADDR])[0]

    def readdir(self, fd: int) -> int:
        return self.wasi.fd_readdir(self.machine, [fd, self.BUF_ADDR, 256, 0, self.OUT_ADDR])[0]

    def filestat(self, fd: int) -> int:
        return self.wasi.fd_filestat_get(self.machine, [fd, self.BUF_ADDR])[0]

    def set_flags(self, fd: int) -> int:
        return self.wasi.fd_fdstat_set_flags(self.machine, [fd, 0])[0]

    def probe(self, fd: int, right: int) -> int:
        action = {
            R['READ']: self.read, R['WRITE']: self.write, R['SEEK']: self.seek,
            R['TELL']: self.tell,
            R['PATH_OPEN']: lambda d: SUCCESS if self.fdstat(d)[1] & R['PATH_OPEN'] else NOTCAPABLE,
            R['READDIR']: self.readdir, R['FD_FILESTAT_GET']: self.filestat,
            R['FD_FILESTAT_SET_SIZE']: lambda d: self.wasi.fd_filestat_set_size(self.machine, [d, 0])[0],
            R['FDSTAT_SET_FLAGS']: self.set_flags,
        }[right]
        return action(fd)

    def cleanup(self) -> None:
        for fd in range(3, len(self.wasi.fd)):
            file = self.wasi.fd[fd]
            if file.wasm_status == OPENED and file.host_status == OPENED:
                os.close(file.host_fd)


def names(mask: int) -> str:
    return '|'.join(sorted(name for name, bit in R.items() if mask & bit)) or '-'


def impl_state(host: Host) -> dict[int, tuple[str, int, int]]:
    return {
        fd: (file.wasm_status, file.wasm_rights_base, file.wasm_rights_root)
        for fd, file in enumerate(host.wasi.fd)
    }


def model_state(model: CapModel) -> dict[int, tuple[str, int, int]]:
    return {fd: (cap.status, cap.base, cap.root) for fd, cap in model.fds.items()}


def assert_matches(host: Host, model: CapModel, transition: str) -> None:
    got, want = impl_state(host), model_state(model)
    assert got == want, (
        f'{transition}: state divergence\n  model={want}\n  impl ={got}'
    )


def new_model() -> CapModel:
    poll = W.RIGHTS_POLL_FD_READWRITE
    return CapModel(
        rights={0: poll | W.RIGHTS_FD_READ, 1: poll | W.RIGHTS_FD_WRITE,
                2: poll | W.RIGHTS_FD_WRITE, 3: PREOPEN_BASE, 4: PREOPEN_BASE},
        roots={0: 0, 1: 0, 2: 0, 3: PREOPEN_ROOT, 4: PREOPEN_ROOT},
        objs={0: 'stdin', 1: 'stdout', 2: 'stderr', 3: 'preopen-a', 4: 'preopen-b'},
    )


records = []


def record(transition: str, detail: str) -> None:
    records.append((transition, detail))
    print(f'  {transition:11s} {detail}')


def matrix(host: Host, title: str) -> None:
    print(f'  -- access matrix {title} --')
    for fd, file in enumerate(host.wasi.fd):
        if file.wasm_status != OPENED:
            print(f'    fd={fd:<2d} CLOSED ({file.host_name})')
            continue
        probe_bits = [R['PATH_OPEN'], R['READDIR']] if file.wasm_type == W.FILETYPE_DIRECTORY else [
            R['READ'], R['WRITE'], R['SEEK'], R['TELL'], R['FD_FILESTAT_GET']]
        verdicts = []
        for bit in probe_bits:
            verdicts.append(f'{names(bit)}={"ok" if host.probe(fd, bit) == SUCCESS else "deny"}')
        print(f'    fd={fd:<2d} base=[{names(file.wasm_rights_base)}] actions: {", ".join(verdicts)}')


def run_baseline(root: str) -> Host:
    host = Host(root)
    model = new_model()
    print('A. switch (open regular files through the preopen directory)')
    errno, fw = host.path_open(3, 'f.txt', RW, ALL_FD)
    assert errno == SUCCESS and fw == 5
    _, mfd = model.open(3, RW, ALL_FD, 'f.txt', R['PATH_OPEN'])
    assert mfd == fw
    record('T_open', f'fd={fw} f.txt base=[{names(RW)}] root=[{names(ALL_FD)}] errno={errno}')
    errno, fr = host.path_open(3, 'g.txt', RO, R['READ'])
    assert errno == SUCCESS and fr == 6
    _, mfd = model.open(3, RO, R['READ'], 'g.txt', R['PATH_OPEN'])
    assert mfd == fr
    record('T_open', f'fd={fr} g.txt base=[{names(RO)}] errno={errno}')
    assert host.read(fw) == SUCCESS and host.write(fw) == SUCCESS
    assert host.read(fr) == SUCCESS and host.probe(fr, R['WRITE']) == NOTCAPABLE
    assert_matches(host, model, 'T_open')
    matrix(host, 'after open')

    print('B. drop (T_drop) then retry the dropped right')
    before = model.snapshot()
    assert host.set_rights(fw, RO, R['READ']) == SUCCESS
    assert model.drop(fw, RO, R['READ']) == SUCCESS
    model.assert_no_recovery('T_drop', fw, before)
    record('T_drop', f'fd={fw} RW -> READ (WRITE relinquished)')
    assert host.fdstat(fw)[1] == RO
    assert host.write(fw) == NOTCAPABLE, 'write must be denied at the WASI gate after drop'
    # Retry / re-escalation: asking the old WRITE bit back must not restore it.
    assert host.set_rights(fw, RW, ALL_FD) == NOTCAPABLE
    assert model.drop(fw, RW, ALL_FD) == NOTCAPABLE
    assert host.fdstat(fw)[1] == RO, 'failed T_drop must leave rights untouched'
    record('T_drop', f'fd={fw} retry WRITE escalation -> NOTCAPABLE, mask unchanged')
    assert_matches(host, model, 'T_drop')

    print('C. derived handles cannot smuggle rights back (T_open bounded by request)')
    assert host.set_rights(3, PREOPEN_BASE & ~R['PATH_OPEN'], PREOPEN_ROOT) == SUCCESS
    model.drop(3, PREOPEN_BASE & ~R['PATH_OPEN'], PREOPEN_ROOT)
    errno, stolen = host.path_open(3, 'f.txt', RW, ALL_FD)
    assert errno == NOTCAPABLE and stolen is None
    assert model.open(3, RW, ALL_FD, 'f.txt', R['PATH_OPEN'])[0] == NOTCAPABLE
    record('T_open', 'preopen A lost PATH_OPEN: new fd -> NOTCAPABLE, no descriptor allocated')
    # A sibling preopen that kept PATH_OPEN still derives a fresh, request-bounded fd.
    errno, via_b = host.path_open(host.dirfd_b, 'f.txt', RO, R['READ'])
    assert errno == SUCCESS
    model.open(host.dirfd_b, RO, R['READ'], 'f.txt', R['PATH_OPEN'])
    assert host.fdstat(via_b)[1] == RO and host.probe(via_b, R['WRITE']) == NOTCAPABLE
    record('T_open', f'fd={via_b} via full-power preopen B: READ-only request never inherits WRITE')
    # The earlier read-only handle of the same inode still cannot write.
    assert host.probe(fr, R['WRITE']) == NOTCAPABLE
    assert_matches(host, model, 'T_open')

    print('D. root ceiling: dropped root must be gone on the descriptor itself')
    assert host.set_rights(fw, 0, 0) == SUCCESS
    model.drop(fw, 0, 0)
    assert host.set_rights(fw, RO, R['READ']) == NOTCAPABLE
    assert host.probe(fw, R['READ']) == NOTCAPABLE and host.probe(fw, R['WRITE']) == NOTCAPABLE
    record('T_drop', f'fd={fw} stripped to base=0 root=0: every action denied, no re-grant')
    assert_matches(host, model, 'T_drop')

    print('E. renumber (T_renumber) cannot revive a right dropped on the slot')
    # The target initially holds WRITE plus TELL, then drops TELL via T_drop.
    # The source handle never holds TELL. A correct renumber transfers the
    # source capability verbatim; any implementation that remembers the slot's
    # dropped bits and unions them back in would make TELL reappear.
    dst_rw_tell = RW | R['TELL']
    errno, ren_dst = host.path_open(host.dirfd_b, 'h.txt', dst_rw_tell, ALL_FD)
    assert errno == SUCCESS
    model.open(host.dirfd_b, dst_rw_tell, ALL_FD, 'h.txt', R['PATH_OPEN'])
    assert host.set_rights(ren_dst, RW, ALL_FD) == SUCCESS
    model.drop(ren_dst, RW, ALL_FD)
    assert not (host.fdstat(ren_dst)[1] & R['TELL'])
    errno, src = host.path_open(host.dirfd_b, 'g.txt', RW, R['READ'] | R['WRITE'])
    assert errno == SUCCESS
    model.open(host.dirfd_b, RW, R['READ'] | R['WRITE'], 'g.txt', R['PATH_OPEN'])
    assert not (host.fdstat(src)[1] & R['TELL'])
    src_mask = host.fdstat(src)[1]
    src_inode = os.fstat(host.wasi.fd[src].host_fd).st_ino
    before = model.snapshot()
    assert host.renumber(src, ren_dst) == SUCCESS
    assert model.renumber(src, ren_dst) == SUCCESS
    model.assert_no_recovery('T_renumber', ren_dst, before, closed_src=src)
    assert host.wasi.fd[src].wasm_status == CLOSED
    assert os.fstat(host.wasi.fd[ren_dst].host_fd).st_ino == src_inode
    assert host.fdstat(ren_dst)[1] == src_mask
    assert not (host.fdstat(ren_dst)[1] & R['TELL']), 'dropped TELL revived by renumber'
    assert host.tell(ren_dst) == NOTCAPABLE
    record('T_renumber', f'fd={src} -> fd={ren_dst}: source caps verbatim, dropped TELL stays dead')
    assert_matches(host, model, 'T_renumber')

    print('F. failed operations are atomic (state identical before/after)')
    snap = impl_state(host)
    assert host.renumber(ren_dst, 99) == BADF and impl_state(host) == snap
    assert host.renumber(99, ren_dst) == BADF and impl_state(host) == snap
    assert host.close(99) == BADF and impl_state(host) == snap
    # FD_DATASYNC belongs neither to the transferred caps nor to the root, so
    # the re-grant must fail and leave the descriptor table byte-identical.
    assert host.set_rights(ren_dst, RW | W.RIGHTS_FD_DATASYNC, ALL_FD) == NOTCAPABLE
    assert impl_state(host) == snap
    # path_open requires the PATH_OPEN right, which regular files never hold;
    # the gate rejects before any descriptor allocation or state change.
    errno, nofd = host.path_open(src, 'missing.txt', RO, R['READ'])
    assert errno == BADF and nofd is None and impl_state(host) == snap
    errno, nofd = host.path_open(ren_dst, 'missing.txt', RO, R['READ'])
    assert errno == NOTCAPABLE and nofd is None and impl_state(host) == snap
    record('T_*', 'badf/notcapable failures: full descriptor table unchanged')

    print('G. close (T_close) never reuses the number; no zombie access')
    assert host.close(ren_dst) == SUCCESS
    model.close(ren_dst)
    assert host.read(ren_dst) == BADF and host.fdstat(ren_dst)[0] == BADF
    pathlib.Path(root, 'k.txt').write_bytes(b'k')
    errno, fresh = host.path_open(host.dirfd_b, 'k.txt', RO, R['READ'])
    assert errno == SUCCESS and fresh != ren_dst
    model.open(host.dirfd_b, RO, R['READ'], 'k.txt', R['PATH_OPEN'])
    record('T_close', f'fd={ren_dst} closed -> BADF; next open got fd={fresh}, number not recycled')
    assert_matches(host, model, 'T_close')
    matrix(host, 'final')
    return host


def expect_mutant(name: str, transition: str, bad: bool, detail: str) -> int:
    tag = 'CAUGHT' if bad else 'MISSED'
    print(f'  [{tag}] {name} on {transition}: {detail}')
    return 1 if bad else 0


def run_mutants(root: str) -> int:
    for name in ('m1.txt', 'm2a.txt', 'm2b.txt', 'm3.txt'):
        pathlib.Path(root, name).write_bytes(b'x')
    caught = 0
    print('M1. retry-recovery mutant: T_drop subset check deleted')
    host = Host(root)
    _, fw = host.path_open(3, 'm1.txt', RW, ALL_FD)
    host.set_rights(fw, RO, R['READ'])

    def drop_without_gate(machine, args):
        file = host.wasi.fd[args[0]]
        file.wasm_rights_base = args[1]
        file.wasm_rights_root = args[2]
        return [SUCCESS]

    host.wasi.fd_fdstat_set_rights = types.MethodType(lambda self, m, a: drop_without_gate(m, a), host.wasi)
    errno = host.set_rights(fw, RW, ALL_FD)
    bad = errno == SUCCESS and host.fdstat(fw)[1] == RW and host.write(fw) == SUCCESS
    caught += expect_mutant('M_retry', 'T_drop(fd=%d)' % fw, bad,
                            'WRITE bit and a real fd_write came back after the right was dropped')

    print('M2. renumber-recovery mutant: T_drop hides bits, T_renumber revives them')
    host = Host(root)
    _, dst = host.path_open(3, 'm2a.txt', RW | R['TELL'], ALL_FD)
    _, stem = host.path_open(3, 'm2b.txt', RW, R['READ'] | R['WRITE'])

    def drop_hiding(machine, args):
        file = host.wasi.fd[args[0]]
        removed = file.wasm_rights_base & ~args[1]
        file.wasm_rights_base = args[1]
        file.wasm_rights_root = args[2] | removed
        return [SUCCESS]

    host.wasi.fd_fdstat_set_rights = types.MethodType(lambda self, m, a: drop_hiding(m, a), host.wasi)
    assert host.set_rights(dst, RW, ALL_FD) == SUCCESS
    assert not (host.fdstat(dst)[1] & R['TELL'])
    real_renumber = host.wasi.fd_renumber

    def renumber_reclaim(machine, args):
        stashed = host.wasi.fd[args[1]].wasm_rights_root
        real_renumber(machine, args)
        file = host.wasi.fd[args[1]]
        file.wasm_rights_base = file.wasm_rights_base | (stashed & ~file.wasm_rights_root)
        return [SUCCESS]

    host.wasi.fd_renumber = types.MethodType(lambda self, m, a: renumber_reclaim(m, a), host.wasi)
    host.renumber(stem, dst)
    bad = bool(host.fdstat(dst)[1] & R['TELL']) and host.tell(dst) == SUCCESS
    caught += expect_mutant('M_renumber', 'T_renumber(%d->%d)' % (stem, dst), bad,
                            'TELL dropped on the slot came back through the renumber transfer')
    host.cleanup()

    print('M3. derived-handle mutant: T_open overgrants WRITE to a READ-only request')
    host = Host(root)
    real_open = host.wasi.path_open

    def open_overgrant(machine, args):
        args = args.copy()
        args[5] = args[5] | R['WRITE']  # child gains a right the caller never requested
        errno = real_open(machine, args)[0]
        if errno == SUCCESS:
            child_fd = machine.mem.get_u32(host.OUT_ADDR)
            host.wasi.fd[child_fd].host_flag |= os.O_RDWR
        return [errno]

    host.wasi.path_open = types.MethodType(lambda self, m, a: open_overgrant(m, a), host.wasi)
    errno, child = host.path_open(3, 'm3.txt', RO, R['READ'])
    recovered = bool(host.fdstat(child)[1] & R['WRITE'])
    gate_write = host.write(child)
    bad = errno == SUCCESS and recovered and gate_write == SUCCESS
    caught += expect_mutant('M_derive', 'T_open(fd=%d)' % child, bad,
                            f'read-only request yielded WRITE in mask and fd_write returned {gate_write}')
    host.cleanup()
    return caught


def main() -> int:
    root = tempfile.mkdtemp(prefix='wasi-cap-', dir=os.environ.get('TMPDIR'))
    for name in ('f.txt', 'g.txt', 'h.txt', 'k.txt'):
        pathlib.Path(root, name).write_bytes(b'x')
    print(f'temp preopen: {root}')
    try:
        host = run_baseline(root)
        caught = run_mutants(root)
        host.cleanup()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print(f'\ntransitions recorded: {len(records)}; mutants caught: {caught}/3')
    if caught != 3:
        print('FAIL: a privilege-recovery variant was not detected', file=sys.stderr)
        return 1
    print('PASS: no transition in the real implementation recovers a relinquished right')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

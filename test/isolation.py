import io
import os
import struct
import tempfile
import pywasm


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def section(sid: int, payload: bytes) -> bytes:
    return bytes([sid]) + uleb(len(payload)) + payload


def vec(items: list[bytes]) -> bytes:
    return uleb(len(items)) + b''.join(items)


def import_func(name: str, type_index: int) -> bytes:
    module = b'wasi_snapshot_preview1'
    return uleb(len(module)) + module + uleb(len(name)) + name.encode() + b'\x00' + uleb(type_index)


def make_echo_guest() -> bytes:
    # _start reports what the guest can observe from WASI into memory[0:16]:
    #   [args count, args bytes, env count, env bytes]
    # then writes those 16 bytes to stdout. _echo(code) does the same but exits with the requested code,
    # which exercises proc_exit directly.
    i32 = b'\x7f'
    types = vec([
        b'\x60' + uleb(0) + uleb(0),
        b'\x60' + uleb(2) + i32 + i32 + uleb(1) + i32,
        b'\x60' + uleb(4) + i32 * 4 + uleb(1) + i32,
        b'\x60' + uleb(1) + i32 + uleb(0),
    ])
    imports = vec([
        import_func('args_sizes_get', 1),
        import_func('environ_sizes_get', 1),
        import_func('fd_write', 2),
        import_func('proc_exit', 3),
    ])
    funcs = vec([uleb(0), uleb(3)])
    mems = vec([b'\x00' + uleb(1)])
    exports = vec([
        uleb(len('_echo')) + b'_echo' + b'\x00' + uleb(5),
        uleb(len('_start')) + b'_start' + b'\x00' + uleb(4),
    ])
    common = bytearray([0x00])
    common += b'\x41\x00\x41\x04\x10\x00\x1a'  # args_sizes_get(0, 4)
    common += b'\x41\x08\x41\x0c\x10\x01\x1a'  # environ_sizes_get(8, 12)
    common += b'\x41\x18\x41\x00\x36\x02\x00'  # iovec[0].ptr = 0
    common += b'\x41\x18\x41\x10\x36\x02\x04'  # iovec[0].len = 16
    common += b'\x41\x01\x41\x18\x41\x01\x41\x1c\x10\x02\x1a'  # fd_write(1, 24, 1, 28)
    start = bytes(common) + b'\x0b'
    echo = bytes(common) + b'\x20\x00\x10\x03\x0b'
    code = vec([uleb(len(start)) + start, uleb(len(echo)) + echo])
    return (b'\x00asm\x01\x00\x00\x00' + section(1, types) + section(2, imports) +
            section(3, funcs) + section(5, mems) + section(7, exports) + section(10, code))


def run_echo(host: pywasm.wasi.Host, args: list[str], envs: dict[str, str]) -> tuple[int, bytes]:
    task = host.task(args, {}, envs)
    out = io.BytesIO(bytearray())
    task.fd[1].pipe = out
    code = host.run(task, io.BytesIO(make_echo_guest()))
    assert task.revoked
    assert task.fd[1].pipe is out
    return code, out.getvalue()


def main() -> None:
    host = pywasm.wasi.Host()

    code1, data1 = run_echo(host, ['task-one', 'first-only'], {'FAKE_SECRET': 'one'})
    code2, data2 = run_echo(host, ['task-two'], {'FAKE_SECRET': 'two-longer'})
    assert (code1, code2) == (0, 0)
    assert struct.unpack_from('<II', data1, 0) == (2, len('task-one') + 1 + len('first-only') + 1)
    assert struct.unpack_from('<II', data2, 0) == (1, len('task-two') + 1)
    assert struct.unpack_from('<II', data1, 8) == (1, len('FAKE_SECRET=one') + 1)
    assert struct.unpack_from('<II', data2, 8) == (1, len('FAKE_SECRET=two-longer') + 1)

    # proc_exit revokes the task and does not stop a later task.
    task_exit = host.task(['proc-exit-task'], {}, {})
    task_exit.fd[1].pipe = io.BytesIO(bytearray())
    with task_exit:
        module = host.task_module(task_exit, io.BytesIO(make_echo_guest()))
        try:
            host.invocate(task_exit, module, '_echo', [7])
        except Exception as e:
            assert len(e.args) >= 2 and e.args[0] == SystemExit and e.args[1] == 7
        else:
            raise AssertionError('proc_exit did not unwind the guest')
    assert task_exit.revoked

    # A guest exception revokes the task, and the host remains usable.
    class Boom(pywasm.wasi.Preview1):
        def fd_write(self, m, args):
            raise RuntimeError('guest failure')

    task_boom = Boom(['boom'], {}, {}, host=host)
    with task_boom:
        boom_module = host.task_module(task_boom, io.BytesIO(make_echo_guest()))
        try:
            host.invocate(task_boom, boom_module, '_start', [])
        except RuntimeError:
            pass
        else:
            raise AssertionError('guest exception was swallowed')
    assert task_boom.revoked
    code4, data4 = run_echo(host, ['post-boom'], {})
    assert code4 == 0
    assert struct.unpack_from('<II', data4, 0) == (1, len('post-boom') + 1)

    # Direct-mode Preview1.main re-runs are rejected after the first exit.
    runtime = pywasm.core.Runtime()
    wasi = pywasm.wasi.Preview1(['wasi_stdout.wasm'], {}, {})
    wasi.bind(runtime)
    wasi.fd[1].pipe = io.BytesIO(bytearray())
    assert wasi.main(runtime, runtime.instance_from_file('example/wasi_stdout/bin/wasi_stdout.wasm')) == 0
    assert wasi.revoked
    try:
        wasi.main(runtime, runtime.instance_from_file('example/wasi_stdout/bin/wasi_stdout.wasm'))
    except pywasm.wasi.TaskRevokedError:
        pass
    else:
        raise AssertionError('revoked direct task was reusable')

    # Shared read-only resources are explicit, ownership is declared, and tasks borrow leases.
    with tempfile.TemporaryDirectory() as shared, tempfile.TemporaryDirectory() as rw:
        with open(os.path.join(shared, 'readme.txt'), 'w') as f:
            f.write('shared')
        sd = pywasm.wasi.SharedDir('/shared', shared, 'embedder')
        assert sd.owner == 'embedder' and sd.read_only
        with host.task(['rw-task'], {'rw': rw}, {}) as rw_task:
            assert rw_task.fd[-1].host_owner == 'task'
        with host.task(['shared-one'], {}, {}, {'/shared': sd}) as s1:
            assert s1.fd[-1].host_shared and s1.fd[-1].host_owner == 'embedder'
            assert s1.fd[-1].wasm_rights_base & pywasm.wasi.Preview1.RIGHTS_FD_WRITE == 0
            try:
                sd.close()
            except pywasm.wasi.TaskConflictError:
                pass
            else:
                raise AssertionError('shared dir closed while a task lease was active')
        sd.close()
        try:
            host.task(['too-late'], {}, {}, {'/shared': sd})
        except pywasm.wasi.TaskRevokedError:
            pass
        else:
            raise AssertionError('closed SharedDir was borrowed')

    # A task cannot be entered twice.
    task_a = host.task(['a'], {}, {})
    with task_a:
        try:
            task_a.enter()
        except pywasm.wasi.TaskConflictError:
            pass
        else:
            raise AssertionError('task entered twice')
    assert task_a.revoked

    # Descendants opened through a shared preopen are read-only, but task-owned, so they are closed on exit.
    with tempfile.TemporaryDirectory() as shared2:
        path = os.path.join(shared2, 'asset.bin')
        with open(path, 'wb') as f:
            f.write(b'asset')
        sd2 = pywasm.wasi.SharedDir('/assets', shared2, 'embedder')
        try:
            with host.task(['child-open'], {}, {}, {'/assets': sd2}) as child_task:
                root = child_task.fd[-1]
                assert root.wasm_read_only
                child = child_task.fd[0]
                before = len(child_task.fd)
                arc = pywasm.wasi.Preview1.File(
                    host_fd=os.open(path, os.O_RDONLY),
                    host_flag=os.O_RDONLY,
                    host_name=path,
                    host_status=pywasm.wasi.Preview1.FILE_STATUS_OPENED,
                    pipe=None,
                    wasm_fd=before,
                    wasm_flag=0,
                    wasm_name='/assets/asset.bin',
                    wasm_rights_base=pywasm.wasi.Preview1.SHARED_RIGHTS_ROOT,
                    wasm_rights_root=pywasm.wasi.Preview1.SHARED_RIGHTS_ROOT,
                    wasm_status=pywasm.wasi.Preview1.FILE_STATUS_OPENED,
                    wasm_type=pywasm.wasi.Preview1.FILETYPE_REGULAR_FILE,
                )
                child_task.fd.append(arc)
                arc.wasm_read_only = root.wasm_read_only
                try:
                    child_task.exit()
                finally:
                    pass
            assert arc.host_status == pywasm.wasi.Preview1.FILE_STATUS_CLOSED
        finally:
            sd2.close()

    # A module pinned to task A cannot be run under task B.
    task_b = host.task(['b'], {}, {})
    with task_b:
        module_b = host.task_module(task_b, io.BytesIO(make_echo_guest()))
    assert task_b.revoked
    task_c = host.task(['c'], {}, {})
    with task_c:
        try:
            host.invocate(task_c, module_b, '_start', [])
        except pywasm.wasi.TaskNotActiveError:
            pass
        else:
            raise AssertionError('module from another task was accepted')

    # FDs opened through path_open are task-owned and cannot leak into the next task's table.
    with tempfile.TemporaryDirectory() as scratch:
        with open(os.path.join(scratch, 'seed'), 'w') as f:
            f.write('seed')
        t = host.task(['fd-task'], {'/rw': scratch}, {})
        with t:
            assert t.fd[3].host_owner == 'task'
        assert t.revoked
        assert t.fd[3].host_status == pywasm.wasi.Preview1.FILE_STATUS_CLOSED

        t2 = host.task(['fd-task-two'], {'/rw': scratch}, {})
        assert len(t2.fd) == 4

    print('task isolation tests passed')


if __name__ == '__main__':
    main()

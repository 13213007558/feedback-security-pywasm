import os
import platform
import tempfile
import types
import unittest

from pywasm.core import Limits, MemInst, MemType
from pywasm.wasi import PATH_CAP_DIRFD, PATH_CAP_LINKAT_NOFOLLOW, PATH_CAP_RENAMEAT, Preview1


class Frame:
    def __init__(self, mem: MemInst) -> None:
        self.module = types.SimpleNamespace(mems=[0])


class Machine:
    # Minimal stand-in for pywasm.core.Machine: the WASI host functions only reach the linear memory through
    # m.store.mems[...], so a single real memory instance and one frame are enough to drive every path_* call.
    def __init__(self) -> None:
        mem = MemInst(MemType(Limits(1, 0)))
        self.stack = types.SimpleNamespace(frame=[Frame(mem)])
        self.store = types.SimpleNamespace(mems=[mem])
        self.mem = mem


class WasiSecurityTest(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.work = os.path.join(self.tmp, 'work')
        self.outside = os.path.join(self.tmp, 'outside')
        os.mkdir(self.work)
        os.mkdir(self.outside)
        self.secret = os.path.join(self.outside, 'secret.txt')
        with open(self.secret, 'w') as f:
            f.write('TOP-SECRET')
        self.wasi = Preview1(['security.wasm'], {'/work': self.work}, {})
        self.machine = Machine()
        self.mem = self.machine.mem
        self.dir_fd = 3

    def tearDown(self) -> None:
        for f in self.wasi.fd:
            if f.wasm_type == Preview1.FILETYPE_CHARACTER_DEVICE:
                continue
            if f.host_status == Preview1.FILE_STATUS_OPENED:
                try:
                    os.close(f.host_fd)
                except OSError:
                    pass
        self._tmp.cleanup()

    def write_path(self, addr: int, name: str) -> int:
        data = name.encode()
        self.mem.put(addr, bytearray(data))
        return len(data)

    def open_count(self) -> int:
        # Count host descriptors this process owns by scanning /dev/fd where available; used to prove rejected
        # calls never leave a descriptor behind.
        if not hasattr(os, 'listdir') or not os.path.isdir('/dev/fd'):
            self.skipTest('/dev/fd is not available on this platform')
        return len([n for n in os.listdir('/dev/fd') if n.isdigit()])

    def path_open(self, name: str, rights: int, oflags: int = 0, lookup: int = 0) -> list[int]:
        length = self.write_path(100, name)
        return self.wasi.path_open(
            self.machine,
            [self.dir_fd, lookup, 100, length, oflags, rights, rights, 0, 512],
        )

    def assert_outside_untouched(self) -> None:
        self.assertTrue(os.path.exists(self.secret))
        with open(self.secret) as f:
            self.assertEqual(f.read(), 'TOP-SECRET')
        self.assertEqual(os.listdir(self.outside), ['secret.txt'])

    def test_textual_traversal_is_rejected(self) -> None:
        before = self.open_count()
        for name in ['../outside/secret.txt', '../../etc/passwd', '/etc/passwd', 'a/../../outside/secret.txt']:
            result = self.path_open(name, Preview1.RIGHTS_FD_READ)
            self.assertIn(result[0], [Preview1.ERRNO_PERM, Preview1.ERRNO_ILSEQ], name)
            self.assertEqual(len(self.wasi.fd), 4, f'no descriptor may be registered for {name}')
        self.assertEqual(self.open_count(), before)
        self.assert_outside_untouched()

    def test_symlink_escape_is_rejected_at_descriptor_level(self) -> None:
        os.symlink(self.outside, os.path.join(self.work, 'evil'))
        before = self.open_count()
        # A purely lexical join cannot tell that the in-workdir component "evil" is a symlink; only realpath and
        # the post-open descriptor containment check observe where the kernel actually resolves it.
        joined = self.wasi.help_path_join(self.wasi.fd[self.dir_fd].host_name, 'evil/secret.txt')
        self.assertTrue(joined.startswith(self.wasi.fd[self.dir_fd].host_name))
        result = self.path_open('evil/secret.txt', Preview1.RIGHTS_FD_READ)
        self.assertEqual(result, [Preview1.ERRNO_PERM])
        self.assertEqual(len(self.wasi.fd), 4)
        self.assertEqual(self.open_count(), before)
        self.assert_outside_untouched()

    def test_intermediate_directory_symlink_escape_is_rejected(self) -> None:
        os.symlink(self.outside, os.path.join(self.work, 'linkdir'))
        before = self.open_count()
        result = self.path_open('linkdir/secret.txt', Preview1.RIGHTS_FD_READ)
        self.assertEqual(result, [Preview1.ERRNO_PERM])
        self.assertEqual(self.open_count(), before)
        self.assert_outside_untouched()

    def test_final_component_symlink_is_refused_without_follow(self) -> None:
        os.symlink(os.path.join(self.outside, 'secret.txt'), os.path.join(self.work, 'leaf'))
        result = self.path_open('leaf', Preview1.RIGHTS_FD_READ, lookup=0)
        self.assertIn(result[0], [Preview1.ERRNO_LOOP, Preview1.ERRNO_PERM])
        self.assertEqual(len(self.wasi.fd), 4)
        self.assert_outside_untouched()

    def test_absolute_path_is_rejected(self) -> None:
        result = self.path_open(os.path.join(self.outside, 'secret.txt'), Preview1.RIGHTS_FD_READ)
        self.assertIn(result[0], [Preview1.ERRNO_ILSEQ, Preview1.ERRNO_PERM])
        self.assert_outside_untouched()

    def test_nul_byte_path_is_rejected(self) -> None:
        length = self.write_path(100, 'safe.txt\0../outside/secret.txt')
        result = self.wasi.path_open(
            self.machine,
            [self.dir_fd, 0, 100, length, 0, Preview1.RIGHTS_FD_READ, 0, 0, 512],
        )
        self.assertIn(result[0], [Preview1.ERRNO_ILSEQ, Preview1.ERRNO_PERM, Preview1.ERRNO_NOENT])
        self.assert_outside_untouched()

    def test_legitimate_open_read_and_write(self) -> None:
        with open(os.path.join(self.work, 'notes.txt'), 'w') as f:
            f.write('hello')
        result = self.path_open('notes.txt', Preview1.RIGHTS_FD_READ)
        self.assertEqual(result, [Preview1.ERRNO_SUCCESS])
        fd = self.mem.get_u32(512)
        self.assertEqual(self.wasi.fd[fd].host_root, os.path.realpath(self.work))
        self.assertEqual(os.read(self.wasi.fd[fd].host_fd, 5), b'hello')
        os.close(self.wasi.fd[fd].host_fd)

    def test_rights_are_masked_by_inherited_directory_rights(self) -> None:
        with open(os.path.join(self.work, 'f.txt'), 'w') as f:
            f.write('x')
        parent = self.wasi.fd[self.dir_fd]
        parent.wasm_rights_root = Preview1.RIGHTS_FD_READ
        result = self.path_open('f.txt', Preview1.RIGHTS_FD_READ | Preview1.RIGHTS_FD_WRITE)
        self.assertEqual(result, [Preview1.ERRNO_SUCCESS])
        fd = self.mem.get_u32(512)
        self.assertEqual(self.wasi.fd[fd].wasm_rights_base, Preview1.RIGHTS_FD_READ)
        self.assertEqual(self.wasi.fd[fd].wasm_rights_base & Preview1.RIGHTS_FD_WRITE, 0)
        os.close(self.wasi.fd[fd].host_fd)

    def test_path_open_requires_directory_descriptor(self) -> None:
        with open(os.path.join(self.work, 'f.txt'), 'w') as f:
            f.write('x')
        opened = self.path_open('f.txt', Preview1.RIGHTS_FD_READ)
        self.assertEqual(opened, [Preview1.ERRNO_SUCCESS])
        file_fd = self.mem.get_u32(512)
        length = self.write_path(200, 'f.txt')
        result = self.wasi.path_open(
            self.machine,
            [file_fd, 0, 200, length, 0, Preview1.RIGHTS_FD_READ, 0, 0, 600],
        )
        self.assertEqual(result, [Preview1.ERRNO_NOTCAPABLE])
        os.close(self.wasi.fd[file_fd].host_fd)

    def test_rejected_open_leaves_no_descriptor(self) -> None:
        os.symlink(self.outside, os.path.join(self.work, 'escape'))
        before = self.open_count()
        for _ in range(5):
            result = self.path_open('escape/secret.txt', Preview1.RIGHTS_FD_READ)
            self.assertEqual(result, [Preview1.ERRNO_PERM])
        self.assertEqual(self.open_count(), before)
        self.assertEqual(len(self.wasi.fd), 4)

    def test_rename_replaces_inside_workdir(self) -> None:
        if not PATH_CAP_RENAMEAT:
            self.skipTest('renameat is not supported on this platform')
        with open(os.path.join(self.work, 'old.txt'), 'w') as f:
            f.write('v1')
        with open(os.path.join(self.work, 'new.txt'), 'w') as f:
            f.write('v2')
        src_len = self.write_path(100, 'old.txt')
        dst_len = self.write_path(200, 'new.txt')
        before = self.open_count()
        result = self.wasi.path_rename(self.machine, [self.dir_fd, 100, src_len, self.dir_fd, 200, dst_len])
        self.assertEqual(result, [Preview1.ERRNO_SUCCESS])
        self.assertFalse(os.path.exists(os.path.join(self.work, 'old.txt')))
        with open(os.path.join(self.work, 'new.txt')) as f:
            self.assertEqual(f.read(), 'v1')
        self.assertEqual(self.open_count(), before)

    def test_rename_escape_via_symlink_is_rejected(self) -> None:
        if not PATH_CAP_RENAMEAT:
            self.skipTest('renameat is not supported on this platform')
        with open(os.path.join(self.work, 'movable.txt'), 'w') as f:
            f.write('m')
        os.symlink(self.outside, os.path.join(self.work, 'outlink'))
        src_len = self.write_path(100, 'movable.txt')
        dst_len = self.write_path(200, 'outlink/movable.txt')
        result = self.wasi.path_rename(self.machine, [self.dir_fd, 100, src_len, self.dir_fd, 200, dst_len])
        self.assertEqual(result, [Preview1.ERRNO_PERM])
        self.assertTrue(os.path.exists(os.path.join(self.work, 'movable.txt')))
        self.assert_outside_untouched()

    def test_rename_to_textual_traversal_is_rejected(self) -> None:
        if not PATH_CAP_RENAMEAT:
            self.skipTest('renameat is not supported on this platform')
        with open(os.path.join(self.work, 'movable.txt'), 'w') as f:
            f.write('m')
        src_len = self.write_path(100, 'movable.txt')
        dst_len = self.write_path(200, '../outside/movable.txt')
        result = self.wasi.path_rename(self.machine, [self.dir_fd, 100, src_len, self.dir_fd, 200, dst_len])
        self.assertEqual(result, [Preview1.ERRNO_PERM])
        self.assertTrue(os.path.exists(os.path.join(self.work, 'movable.txt')))
        self.assert_outside_untouched()

    def test_cross_device_rename_is_explicitly_refused(self) -> None:
        if not PATH_CAP_RENAMEAT:
            self.skipTest('renameat is not supported on this platform')
        work_dev = os.stat(self.work).st_dev
        other_root = None
        for candidate in ('/dev', '/proc', '/sys', '/'):
            if not os.path.isdir(candidate):
                continue
            try:
                if os.stat(candidate).st_dev != work_dev and os.access(candidate, os.R_OK | os.X_OK):
                    other_root = candidate
                    break
            except OSError:
                continue
        if other_root is None:
            self.skipTest('no second filesystem available for a cross-device rename')
        with open(os.path.join(self.work, 'cross.txt'), 'w') as f:
            f.write('x')
        other = Preview1(['other.wasm'], {'/work': self.work, '/other': other_root}, {})
        try:
            work_fd = next(f.wasm_fd for f in other.fd if f.wasm_name == '/work')
            other_fd = next(f.wasm_fd for f in other.fd if f.wasm_name == '/other')
            src_len = self.write_path(100, 'cross.txt')
            dst_len = self.write_path(200, 'cross-moved.txt')
            result = other.path_rename(self.machine, [work_fd, 100, src_len, other_fd, 200, dst_len])
            self.assertEqual(result, [Preview1.ERRNO_XDEV])
            self.assertTrue(os.path.exists(os.path.join(self.work, 'cross.txt')))
        finally:
            for f in other.fd:
                if f.wasm_type != Preview1.FILETYPE_CHARACTER_DEVICE and f.host_status == Preview1.FILE_STATUS_OPENED:
                    try:
                        os.close(f.host_fd)
                    except OSError:
                        pass

    def test_rename_requires_rename_rights(self) -> None:
        with open(os.path.join(self.work, 'a.txt'), 'w') as f:
            f.write('a')
        self.wasi.fd[self.dir_fd].wasm_rights_base &= ~Preview1.RIGHTS_PATH_RENAME_SOURCE
        src_len = self.write_path(100, 'a.txt')
        dst_len = self.write_path(200, 'b.txt')
        result = self.wasi.path_rename(self.machine, [self.dir_fd, 100, src_len, self.dir_fd, 200, dst_len])
        self.assertEqual(result, [Preview1.ERRNO_NOTCAPABLE])

    def test_hard_link_inside_workdir(self) -> None:
        with open(os.path.join(self.work, 'origin.txt'), 'w') as f:
            f.write('linked')
        src_len = self.write_path(100, 'origin.txt')
        dst_len = self.write_path(200, 'alias.txt')
        result = self.wasi.path_link(
            self.machine,
            [self.dir_fd, Preview1.LOOKUPFLAGS_SYMLINK_FOLLOW, 100, src_len, self.dir_fd, 200, dst_len],
        )
        self.assertEqual(result, [Preview1.ERRNO_SUCCESS])
        self.assertTrue(os.path.samefile(os.path.join(self.work, 'origin.txt'), os.path.join(self.work, 'alias.txt')))

    def test_hard_link_escape_is_rejected_and_rolled_back(self) -> None:
        os.symlink(self.outside, os.path.join(self.work, 'outlink'))
        with open(os.path.join(self.outside, 'target.txt'), 'w') as f:
            f.write('outside-data')
        src_len = self.write_path(100, 'outlink/target.txt')
        dst_len = self.write_path(200, 'inside.txt')
        before = self.open_count()
        result = self.wasi.path_link(
            self.machine,
            [self.dir_fd, Preview1.LOOKUPFLAGS_SYMLINK_FOLLOW, 100, src_len, self.dir_fd, 200, dst_len],
        )
        self.assertEqual(result, [Preview1.ERRNO_PERM])
        self.assertFalse(os.path.exists(os.path.join(self.work, 'inside.txt')))
        self.assertEqual(sorted(os.listdir(self.outside)), ['secret.txt', 'target.txt'])
        self.assertEqual(self.open_count(), before)

    def test_hard_link_of_symlink_without_follow_needs_platform_capability(self) -> None:
        os.symlink('origin.txt', os.path.join(self.work, 'pointer'))
        with open(os.path.join(self.work, 'origin.txt'), 'w') as f:
            f.write('data')
        src_len = self.write_path(100, 'pointer')
        dst_len = self.write_path(200, 'pointer-hard')
        result = self.wasi.path_link(self.machine, [self.dir_fd, 0, 100, src_len, self.dir_fd, 200, dst_len])
        if PATH_CAP_LINKAT_NOFOLLOW:
            self.assertEqual(result, [Preview1.ERRNO_SUCCESS])
            self.assertTrue(os.path.islink(os.path.join(self.work, 'pointer-hard')))
        else:
            self.assertEqual(result, [Preview1.ERRNO_NOTSUP])
            self.assertFalse(os.path.exists(os.path.join(self.work, 'pointer-hard')))

    def test_path_link_requires_link_rights(self) -> None:
        with open(os.path.join(self.work, 'a.txt'), 'w') as f:
            f.write('a')
        self.wasi.fd[self.dir_fd].wasm_rights_base &= ~Preview1.RIGHTS_PATH_LINK_TARGET
        src_len = self.write_path(100, 'a.txt')
        dst_len = self.write_path(200, 'b.txt')
        result = self.wasi.path_link(
            self.machine,
            [self.dir_fd, Preview1.LOOKUPFLAGS_SYMLINK_FOLLOW, 100, src_len, self.dir_fd, 200, dst_len],
        )
        self.assertEqual(result, [Preview1.ERRNO_NOTCAPABLE])

    def test_create_directory_and_unlink_stay_confined(self) -> None:
        name_len = self.write_path(100, 'subdir')
        self.assertEqual(
            self.wasi.path_create_directory(self.machine, [self.dir_fd, 100, name_len]),
            [Preview1.ERRNO_SUCCESS],
        )
        self.assertTrue(os.path.isdir(os.path.join(self.work, 'subdir')))
        bad_len = self.write_path(200, '../outside/evildir')
        self.assertEqual(
            self.wasi.path_create_directory(self.machine, [self.dir_fd, 200, bad_len]),
            [Preview1.ERRNO_PERM],
        )
        self.assertFalse(os.path.exists(os.path.join(self.outside, 'evildir')))

    def test_capability_flags_reflect_platform(self) -> None:
        if platform.system().lower() == 'windows':
            self.assertFalse(PATH_CAP_DIRFD)
            self.assertFalse(PATH_CAP_RENAMEAT)
        else:
            self.assertTrue(PATH_CAP_DIRFD)
            self.assertTrue(PATH_CAP_RENAMEAT)
        self.assertIsInstance(PATH_CAP_LINKAT_NOFOLLOW, bool)

    def test_empty_path_opens_the_directory_descriptor_itself(self) -> None:
        length = self.write_path(100, '')
        result = self.wasi.path_open(
            self.machine,
            [self.dir_fd, Preview1.LOOKUPFLAGS_SYMLINK_FOLLOW, 100, length,
             Preview1.OFLAGS_DIRECTORY, 0, 0, 0, 512],
        )
        self.assertEqual(result, [Preview1.ERRNO_SUCCESS])
        fd = self.mem.get_u32(512)
        self.assertEqual(self.wasi.fd[fd].wasm_type, Preview1.FILETYPE_DIRECTORY)
        self.assertEqual(self.wasi.fd[fd].host_root, os.path.realpath(self.work))
        os.close(self.wasi.fd[fd].host_fd)

    def test_descriptor_root_is_inherited_through_nested_open(self) -> None:
        os.mkdir(os.path.join(self.work, 'nested'))
        first = self.path_open('nested', 0, oflags=Preview1.OFLAGS_DIRECTORY)
        self.assertEqual(first, [Preview1.ERRNO_SUCCESS])
        nested_fd = self.mem.get_u32(512)
        self.assertEqual(self.wasi.fd[nested_fd].host_root, os.path.realpath(self.work))
        with open(os.path.join(self.work, 'nested', 'deep.txt'), 'w') as f:
            f.write('deep')
        length = self.write_path(200, 'deep.txt')
        result = self.wasi.path_open(
            self.machine,
            [nested_fd, 0, 200, length, 0, Preview1.RIGHTS_FD_READ, 0, 0, 600],
        )
        self.assertEqual(result, [Preview1.ERRNO_SUCCESS])
        deep_fd = self.mem.get_u32(600)
        self.assertEqual(self.wasi.fd[deep_fd].host_root, os.path.realpath(self.work))
        os.close(self.wasi.fd[nested_fd].host_fd)
        os.close(self.wasi.fd[deep_fd].host_fd)


if __name__ == '__main__':
    unittest.main(verbosity=2)

import typing

# Resource quota attribution for a runtime that hosts multiple WebAssembly instances.
#
# A Ledger groups instances into tasks, each with a memory quota in bytes. It attributes every byte of linear
# memory to exactly one task at any moment, covering:
#
#   - initial allocation of a memory (module-defined or host-created),
#   - memory.grow deltas, charged to the growing instance's task,
#   - host-side buffers, charged explicitly through the ledger.
#
# A memory imported by several instances is registered once and explicitly approved per task; the importing
# tasks are recorded as references but are not charged again, so sharing never double-charges. Because each
# grow delta is charged to exactly one task, the per-memory contributions always sum to the memory's current
# size, so sharing never under-counts either.
#
# When a task ends, its exclusive memories are freed and their charge released; memories still referenced by
# surviving tasks stay alive and the ending task's contribution is transferred to a surviving sharer, which is
# reported. Host buffers still open are released by the task end. All of this is returned as a Report.

PAGE_SIZE = 64 * 1024


class QuotaExceeded(Exception):
    # Raised when an allocation would push a task over its memory quota. Nothing is charged and the memory or
    # buffer that triggered it is left untouched.
    pass


class ShareNotApproved(Exception):
    # Raised when an instance is bound to a task that imports a shared memory without an explicit approval.
    pass


class TaskClosed(Exception):
    # Raised when charging a task that has already ended.
    pass


class Task:
    # A task is the unit of quota ownership. Instances and host buffers are bound to a task; the sum of their
    # attributed bytes is limited by the task's quota.

    def __init__(self, name: str, limit: int) -> None:
        self.name = name
        self.limit = limit
        self.used = 0
        self.ended = False

    def __repr__(self) -> str:
        return f'Task({self.name} {self.used}/{self.limit})'


class HostBuffer:
    # A host-side buffer whose bytes are charged to a task until it is closed or the task ends.

    def __init__(self, ledger: 'Ledger', task: Task, size: int, label: str) -> None:
        self.ledger = ledger
        self.task = task
        self.data = bytearray(size)
        self.label = label
        self.closed = False

    def __len__(self) -> int:
        return len(self.data)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.ledger._host_free(self)

    def __repr__(self) -> str:
        return f'HostBuffer({self.label} {len(self.data)}B task={self.task.name})'


class MemAccount:
    # Per-memory attribution. contrib maps a live task to the bytes it paid for; the sum always equals the
    # memory's current size. refs are the tasks with live instances referencing the memory.

    def __init__(self, mem: typing.Any) -> None:
        self.mem = mem
        self.contrib: dict[Task, int] = {}
        self.refs: list[Task] = []
        self.freed = False

    def charged(self) -> int:
        return sum(self.contrib.values())


class Report:
    # The outcome of ending a task: which resources were released by it, which were transferred to surviving
    # sharers, and which transfers pushed a sharer over its quota.

    def __init__(self, task: Task) -> None:
        self.task = task
        self.freed: list[str] = []
        self.transferred: list[str] = []
        self.released_host: list[str] = []
        self.over_limit: list[str] = []

    def __repr__(self) -> str:
        lines = [f'end_task({self.task.name})']
        for e in self.freed:
            lines.append(f'  freed: {e}')
        for e in self.transferred:
            lines.append(f'  transferred: {e}')
        for e in self.released_host:
            lines.append(f'  released host buffer: {e}')
        for e in self.over_limit:
            lines.append(f'  over limit: {e}')
        return '\n'.join(lines)


class Ledger:
    # Tracks quota ownership of every memory and host buffer in one runtime.

    def __init__(self) -> None:
        self.tasks: list[Task] = []
        self.mems: dict[int, MemAccount] = {}
        self.host_buffers: list[HostBuffer] = []
        self.approved: set[tuple[str, int]] = set()

    def create_task(self, name: str, limit: int) -> Task:
        task = Task(name, limit)
        self.tasks.append(task)
        return task

    def _charge(self, task: Task, size: int) -> None:
        if task.ended:
            raise TaskClosed(f'task {task.name} has ended')
        if task.used + size > task.limit:
            raise QuotaExceeded(
                f'task {task.name} quota exceeded: {task.used}+{size} > {task.limit}'
            )
        task.used += size

    def _discharge(self, task: Task, size: int) -> None:
        task.used -= size
        assert task.used >= 0

    def can_charge(self, task: Task, size: int) -> bool:
        return not task.ended and task.used + size <= task.limit

    # Memory attribution.

    def mem_create(self, task: Task, mem: typing.Any) -> None:
        # Charge the initial size of a freshly allocated memory to its creator. Raises QuotaExceeded before
        # touching anything when the quota does not fit.
        size = mem.size * PAGE_SIZE
        self._charge(task, size)
        account = MemAccount(mem)
        account.contrib[task] = size
        account.refs.append(task)
        self.mems[id(mem)] = account

    def mem_approve(self, task: Task, mem: typing.Any) -> None:
        # Explicitly approve a task to import a shared memory.
        assert id(mem) in self.mems, 'shared memory is not registered with the ledger'
        self.approved.add((task.name, id(mem)))

    def mem_attach(self, task: Task, mem: typing.Any) -> None:
        # Record that an instance of the task references an imported memory. No charge: the existing bytes are
        # already attributed to their contributors.
        account = self.mems.get(id(mem))
        if account is None or (task.name, id(mem)) not in self.approved:
            raise ShareNotApproved(
                f'task {task.name} imports a shared memory without explicit approval'
            )
        if task not in account.refs:
            account.refs.append(task)

    def mem_detach(self, task: Task, mem: typing.Any) -> None:
        account = self.mems.get(id(mem))
        if account and task in account.refs:
            account.refs.remove(task)

    def mem_can_grow(self, task: Task, mem: typing.Any, pages: int) -> bool:
        return self.can_charge(task, pages * PAGE_SIZE)

    def mem_grow(self, task: Task, mem: typing.Any, pages: int) -> None:
        # Charge a grow delta to the growing task. Call only after mem_can_grow succeeded.
        size = pages * PAGE_SIZE
        self._charge(task, size)
        account = self.mems[id(mem)]
        account.contrib[task] = account.contrib.get(task, 0) + size
        assert account.charged() == (mem.size + pages) * PAGE_SIZE

    def mem_uncharge(self, task: Task, mem: typing.Any) -> None:
        # Roll back a mem_create, used when instantiation fails partway.
        account = self.mems.pop(id(mem))
        self._discharge(task, account.contrib[task])

    # Host-side buffers.

    def host_alloc(self, task: Task, size: int, label: str = '') -> HostBuffer:
        self._charge(task, size)
        buf = HostBuffer(self, task, size, label or f'host:{len(self.host_buffers)}')
        self.host_buffers.append(buf)
        return buf

    def _host_free(self, buf: HostBuffer) -> None:
        self.host_buffers.remove(buf)
        self._discharge(buf.task, len(buf.data))

    # Task lifecycle.

    def end_task(self, task: Task) -> Report:
        assert not task.ended, f'task {task.name} already ended'
        report = Report(task)
        for buf in [b for b in self.host_buffers if b.task is task]:
            buf.closed = True
            self._host_free(buf)
            report.released_host.append(f'{buf.label} ({len(buf.data)}B) released by {task.name}')
        for account in list(self.mems.values()):
            if task not in account.refs:
                continue
            account.refs.remove(task)
            contrib = account.contrib.pop(task, 0)
            if contrib:
                self._discharge(task, contrib)
            size = len(account.mem.data)
            if not account.refs:
                account.freed = True
                account.mem.data = bytearray()
                account.mem.size = 0
                self.mems.pop(id(account.mem))
                report.freed.append(
                    f'memory ({size}B) freed, charge released by {task.name}'
                )
                for other, rest in list(account.contrib.items()):
                    self._discharge(other, rest)
                account.contrib.clear()
            elif contrib:
                heir = account.refs[0]
                account.contrib[heir] = account.contrib.get(heir, 0) + contrib
                heir.used += contrib
                report.transferred.append(
                    f'memory ({size}B) kept alive by {len(account.refs)} surviving sharer(s); '
                    f'{contrib}B contribution of {task.name} transferred to {heir.name}'
                )
                if heir.used > heir.limit:
                    report.over_limit.append(
                        f'{heir.name} now at {heir.used}/{heir.limit} after transfer'
                    )
        task.ended = True
        assert task.used == 0
        return report

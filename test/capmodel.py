"""Capability state model for WASI preview1 descriptor operations.

The model is independent of pywasm's implementation. A state maps descriptor
numbers to capabilities. Each capability binds a backing object to a rights
mask (what the holder may do now), a root mask (the ceiling inheritable by
derived descriptors), and a *relinquished* mask (every bit this descriptor
number has ever given away through T_drop).

Transitions:

  T_open    parent + requested masks            -> brand-new descriptor
  T_drop    fd + strictly smaller masks         -> same fd, fewer rights;
                                                   removed bits enter relinquished
  T_renumber src, dst                            -> dst receives src's exact caps
                                                   and src closes; dst's own
                                                   relinquished bits stay dead
  T_close   fd                                   -> the descriptor number dies
  T_action  fd, right                            -> permitted iff the bit is held

Failed transitions return an errno and leave the state untouched. The security
invariant is NO-RECOVERY: a bit present in a descriptor's relinquished mask can
never appear in that descriptor's base again, regardless of renumbering,
handle derivation, or a retried/erroneous re-grant call. T_open mints a fresh
descriptor (fresh number, fresh relinquished mask) whose rights are bounded by
the parent's root; it never reinstates rights dropped on another descriptor.
"""

import dataclasses

OPENED = 0
CLOSED = 1

BADF = 8
NOTCAPABLE = 76
SUCCESS = 0


@dataclasses.dataclass(frozen=True)
class Cap:
    obj: str
    base: int
    root: int
    relinquished: int = 0
    status: int = OPENED


class CapModel:
    def __init__(self, rights: dict[int, int], roots: dict[int, int], objs: dict[int, str]):
        self.fds: dict[int, Cap] = {}
        for fd in rights:
            self.fds[fd] = Cap(objs[fd], rights[fd], roots[fd])
        self.history: list[tuple[str, int, frozenset[int]]] = []

    def snapshot(self) -> dict[int, Cap]:
        return {fd: dataclasses.replace(cap) for fd, cap in self.fds.items()}

    def _alive(self, fd: int) -> Cap | None:
        cap = self.fds.get(fd)
        return cap if cap is not None and cap.status == OPENED else None

    def can(self, fd: int, right: int) -> bool:
        cap = self._alive(fd)
        return cap is not None and bool(cap.base & right)

    def open(self, parent: int, req_base: int, req_root: int, obj: str,
             path_open_right: int, spec_strict: bool = True) -> tuple[int, int | None]:
        cap = self._alive(parent)
        if cap is None:
            return BADF, None
        if not (cap.base & path_open_right):
            return NOTCAPABLE, None
        if spec_strict and (req_base & ~cap.root or req_root & ~cap.root):
            return NOTCAPABLE, None
        fd = max(self.fds) + 1
        self.fds[fd] = Cap(obj, req_base, req_root)
        self._record('T_open', fd)
        return SUCCESS, fd

    def drop(self, fd: int, new_base: int, new_root: int) -> int:
        cap = self._alive(fd)
        if cap is None:
            return BADF
        if (cap.base & new_base) != new_base or (cap.root & new_root) != new_root:
            return NOTCAPABLE
        given_away = cap.base & ~new_base
        self.fds[fd] = Cap(cap.obj, new_base, new_root,
                           cap.relinquished | given_away)
        self._record('T_drop', fd)
        return SUCCESS

    def renumber(self, src: int, dst: int) -> int:
        stem, dest = self._alive(src), self._alive(dst)
        if stem is None or dest is None:
            return BADF
        # Correct semantics: the destination receives the source capability
        # verbatim and the source closes. The slot's relinquished memory is
        # retained only as a detector hook; under correct transfer the new base
        # equals the source base, so no dropped bit is independently recovered.
        self.fds[dst] = Cap(stem.obj, stem.base, stem.root, dest.relinquished)
        self.fds[src] = Cap(stem.obj, stem.base, stem.root,
                            stem.relinquished, CLOSED)
        self._record('T_renumber', dst)
        return SUCCESS

    def close(self, fd: int) -> int:
        cap = self._alive(fd)
        if cap is None:
            return BADF
        self.fds[fd] = Cap(cap.obj, cap.base, cap.root, cap.relinquished, CLOSED)
        self._record('T_close', fd)
        return SUCCESS

    def _record(self, transition: str, fd: int) -> None:
        cap = self.fds[fd]
        self.history.append((transition, fd, frozenset(self._bits(cap.base))))

    @staticmethod
    def _bits(mask: int) -> set[int]:
        return {bit for bit in range(30) if mask & (1 << bit)}

    def assert_no_recovery(self, transition: str, fd: int, before: dict[int, Cap],
                           closed_src: int | None = None) -> None:
        """No descriptor re-acquires a right it relinquished.

        T_open allocates a fresh number with an empty relinquished mask and is
        exempt. T_renumber is a *transfer*: the destination may take over the
        source's exact rights only because the source closes in the same step,
        so no two live descriptors end up holding more than before. A union
        variant (destination gaining a bit the source did not hold) or a
        surviving source is a genuine recovery and fails here. Every other
        transition must satisfy base & relinquished == 0 for each descriptor.
        """
        if transition == 'T_open':
            return
        if transition == 'T_renumber' and closed_src is not None:
            old_src, new_dst = before[closed_src], self.fds[fd]
            assert self.fds[closed_src].status == CLOSED, 'renumber source must close'
            extra = self._bits(new_dst.base) - self._bits(old_src.base)
            assert not extra, (
                f'{transition} fd={fd}: destination gained rights {extra!r} the '
                f'source never held (source={self._bits(old_src.base)}, '
                f'result={self._bits(new_dst.base)})'
            )
            return
        for number, old in before.items():
            new = self.fds[number]
            recovered = self._bits(new.base & old.relinquished)
            assert not recovered, (
                f'{transition} fd={fd}: recovered relinquished rights {recovered!r} '
                f'on fd={number} (base={self._bits(new.base)}, '
                f'relinquished={self._bits(old.relinquished)})'
            )

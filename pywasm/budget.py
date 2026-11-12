# Resource budgets that guard WebAssembly decoding and instantiation.
#
# A single Budget object threads through both phases:
#   * decoding (ModuleDesc.from_reader): every input byte is charged before it is
#     read, and every structural entry is charged before its object is built;
#   * admission (Machine.instance): the entries the module plans to allocate in the
#     store, together with the backing pages and elements, are charged up front.
#
# Limits of None mean "unlimited", so callers that never construct a Budget keep the
# historical behavior byte for byte. When a limit is crossed, BudgetExceeded is raised
# with one of the stable reason codes below; callers should branch on the reason rather
# than on the human readable message.

import io


class Reason:
    # Stable rejection reasons. The string values are part of the public contract and
    # must not be renamed; new reasons may only be added.
    INPUT_BYTES = 'input_bytes_exceeded'
    STRUCT_ENTRIES = 'struct_entries_exceeded'
    PLANNED_ALLOCATIONS = 'planned_allocations_exceeded'


class BudgetExceeded(Exception):
    # Raised as soon as a budget limit would be crossed, before the offending bytes are
    # read or the offending structure is built.

    def __init__(self, reason: str, limit: int | None, used: int, requested: int) -> None:
        self.reason = reason
        self.limit = limit
        self.used = used
        self.requested = requested
        super().__init__(f'{reason}: limit={limit} used={used} requested={requested}')


class Budget:
    # Three independent counters covering input size, structural complexity and the
    # runtime objects that admission would create.

    def __init__(
        self,
        input_bytes: int | None = None,
        struct_entries: int | None = None,
        planned_allocations: int | None = None
    ) -> None:
        self.limit_input_bytes = input_bytes
        self.limit_struct_entries = struct_entries
        self.limit_planned_allocations = planned_allocations
        self.used_input_bytes = 0
        self.used_struct_entries = 0
        self.used_planned_allocations = 0

    def charge_input(self, n: int) -> None:
        # Reserve n input bytes before they leave the underlying stream.
        if self.limit_input_bytes is not None and self.used_input_bytes + n > self.limit_input_bytes:
            raise BudgetExceeded(
                Reason.INPUT_BYTES, self.limit_input_bytes, self.used_input_bytes, n
            )
        self.used_input_bytes += n

    def refund_input(self, n: int) -> None:
        # Give back bytes that were reserved but never actually produced by the stream,
        # for example when a truncated module ends inside a section.
        self.used_input_bytes -= n
        assert self.used_input_bytes >= 0

    def charge_entry(self, n: int = 1) -> None:
        # Reserve n structural entries (types, functions, instructions, ...) before the
        # corresponding objects are constructed.
        if self.limit_struct_entries is not None and self.used_struct_entries + n > self.limit_struct_entries:
            raise BudgetExceeded(
                Reason.STRUCT_ENTRIES, self.limit_struct_entries, self.used_struct_entries, n
            )
        self.used_struct_entries += n

    def charge_allocation(self, n: int = 1) -> None:
        # Reserve n planned runtime allocations before the store is touched.
        if n <= 0:
            return
        if (
            self.limit_planned_allocations is not None
            and self.used_planned_allocations + n > self.limit_planned_allocations
        ):
            raise BudgetExceeded(
                Reason.PLANNED_ALLOCATIONS,
                self.limit_planned_allocations,
                self.used_planned_allocations,
                n
            )
        self.used_planned_allocations += n


class BudgetedReader(io.IOBase):
    # Wraps any binary stream and charges every delivered byte against the budget. The
    # charge happens before the underlying read, so a huge r.read(n) is rejected without
    # ever materializing the n-byte buffer. Reads to end of stream are served in bounded
    # chunks to avoid buffering an unbounded amount of data.

    CHUNK = 64 * 1024

    def __init__(self, raw: io.IOBase, budget: Budget) -> None:
        self.raw = raw
        self.budget = budget

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            parts = []
            while True:
                self.budget.charge_input(self.CHUNK)
                chunk = self.raw.read(self.CHUNK)
                if len(chunk) < self.CHUNK:
                    self.budget.refund_input(self.CHUNK - len(chunk))
                    parts.append(chunk)
                    return b''.join(parts)
                parts.append(chunk)
        self.budget.charge_input(size)
        data = self.raw.read(size)
        if len(data) != size:
            self.budget.refund_input(size - len(data))
        return data

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.raw.seek(offset, whence)

    def tell(self) -> int:
        return self.raw.tell()

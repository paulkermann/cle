from collections import OrderedDict
import bisect

from . import Backend
from .region import EmptySegment
from .. import Clemory, Regions

class NonEmptySegment(EmptySegment):
    @property
    def only_contains_uninitialized_data(self):
        return False

class LazyClemory(Clemory):
    def __init__(self, owner: 'LazyBackend', chunk_size=0x1000):
        """
        chunk_size must be a power of two
        """
        self.owner = owner
        self.chunk_size = chunk_size
        self.resident = 0

        super().__init__(self.owner.arch)

        self.min_addr = self.owner.min_addr
        self.max_addr = self.owner.max_addr
        self.consecutive = False
        self.loaded_pages = []

    def _update_min_max(self):
        pass

    def __getitem__(self, k):
        return self.load(k, 1)[0]

    def __setitem__(self, k, v):
        return self.store(k, bytes(([v])))

    def __contains__(self, k):
        return self.region_containing(k)[0] is not None

    def region_containing(self, k):
        seg = self.owner.find_segment_containing(k)
        if seg is None:
            return None, None
        return seg.vaddr, seg.memsize

    def __iter__(self):
        raise TypeError("Cannot enumerate data of LazyClemory")

    def _split_to_unmapped(self, addr, end):
        """
        returns list of [(start addr, end addr)]
        """
        missing = []
        seen_one = False
        for start, backer in super().backers(addr):
            seen_one = True
            if start > addr:
                missing.append((addr, start))

            addr = start + len(backer)
            if addr >= end:
                break

        if not seen_one:
            missing.append((addr, end))

        return missing

    def remove_backer(self, start):
        popped = super().remove_backer(start)
        self.resident -= len(popped)
        return popped

    def add_backer(self, start, data, overwrite=False):
        if overwrite:
            raise TypeError("Cannot add_backer(overwrite=True) with LazyClemory")

        try:
            existing, _ = next(super().backers(start))
        except StopIteration:
            pass
        else:
            if existing <= start:
                raise ValueError("Address %#x is already backed!" % start)

        if type(data) is bytes:
            data = bytearray(data)
        bisect.insort(self._backers, (start, data))
        self.resident += len(data)

    def next_region(self, addr):
        return self.owner.segments.find_region_next_to(addr).min_addr

    def backers(self, addr=0):
        if not self.owner.segments.find_region_containing(addr):
            return
            
        while addr < self.max_addr:
            chunk_addr = addr & ~(self.chunk_size - 1)
            self.make_resident(chunk_addr, self.chunk_size)
            end = chunk_addr + self.chunk_size
            for start, backer in super().backers(addr):
                if start > chunk_addr + self.chunk_size:
                    break
                yield start, backer
                end = max(end, start + len(backer))
            addr = end

    def make_resident(self, addr, size):
        addr_alligned_down = addr &~(self.chunk_size - 1)
        size_alligned_up = (size + (self.chunk_size - 1)) &~(self.chunk_size - 1)

        for i in range(addr_alligned_down, addr_alligned_down + size_alligned_up, self.chunk_size):
            if i in self.loaded_pages:
                continue

            self.loaded_pages.append(i)
            self.add_backer(i, self.owner._load_data(i, self.chunk_size))

    def load(self, addr, size):
        self.make_resident(addr, size)
        return super().load(addr, size)

    def store(self, addr, data):
        raise TypeError("Cannot store data to LazyClemory")

    def find(self, data, search_min=None, search_max=None):
        raise TypeError("Cannot perform find operation via LazyClemory")


class LazyBackend(Backend):
    """
    This is a set of tools which should help you write a backend which accesses some memory space lazily.
    """
    def __init__(self, binary, **kwargs):
        super().__init__(binary, None, **kwargs)

        self._memory_map = None
        self._segments = None
        self.pic = False
        self.linked_base = 0
        self.memory = LazyClemory(self)

    @property
    def segments(self) -> Regions:
        if self._segments is None:
            memory_map = self._load_memory_map()
            self._segments = Regions([NonEmptySegment(addr, size) for addr, size in memory_map])
        return self._segments

    def _load_memory_map(self):
        raise NotImplementedError

    def _load_data(self, addr: int, size: int):
        raise NotImplementedError

    CLEMORY_CLASS = LazyClemory

import cle
import cle.backends
from cle.backends import Backend, register_backend
from cle.memory import Clemory

import angr, archinfo
from io import BytesIO
import cle.backends.lazy
import binascii
import logging
import pdb

logging.getLogger().setLevel(-50)

class lazy_amd64_backend(cle.backends.lazy.LazyBackend):
    def __init__(self, binary, binary_stream, **kwargs):
        super().__init__(binary, **kwargs)

    def _load_data(self, addr, size):
        if addr == 0x111119000:
            cur_data = binascii.unhexlify("48C7C037130000C3")
            return cur_data + (size - len(cur_data)) * b"\x00"

        return b"\x01" * size

    def _load_memory_map(self):
        lower_half = (0, (1<<47) - 1)
        upper_half_start = ((1<<47) - 1) ^ 0xffffffffffffffff
        upper_half_size = ((1 << 64) - upper_half_start)
        
        got =  [lower_half, (upper_half_start, upper_half_size)]
        return got

register_backend("lazy", lazy_amd64_backend)

def main():
    stream = BytesIO(b"\x00" * 0)
    proj = angr.Project(stream, main_opts={"backend": "lazy", "entry_point": 0, "arch": archinfo.arch_amd64.ArchAMD64()})
    state = proj.factory.call_state(0x111119000, stack_base=0x111110000)
    sm = proj.factory.simulation_manager(state)
    sm.explore()

    state = sm.deadended[0]
    assert state.regs.rax.concrete
    assert state.solver.eval(state.regs.rax) == 0x1337

if __name__ == "__main__":
    main()

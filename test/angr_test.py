from angr import *
import claripy
from pwn import *


def main():
    p = Project("./angr_test", load_options={"auto_load_libs": False})
    symbolic_input = claripy.BVS("input", 300 * 8)
    argv = ["./angr_test"]
    state = p.factory.full_init_state(args=argv, stdin=symbolic_input)
    state.libc.buf_symbolic_bytes = 0x100

    state.solver.add()

    simgr = p.factory.simgr(state, save_unconstrained=True)

    simgr.explore(find=lambda s: b"Good" in s.posix.dumps(1))

    if len(simgr.found) > 0:
        found = simgr.found[0]
        print(found.posix.dumps(0))

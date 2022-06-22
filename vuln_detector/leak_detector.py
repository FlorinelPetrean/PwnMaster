import angr
from angr import sim_options as so
from binary.binary import *
import claripy
import timeout_decorator
import logging
from func_model.rand import *
from func_model.exit import *
from func_model.scanf import *
from func_model.gets import *
from func_model.printf_leak import *
from func_model.puts_leak import *

# from func_model.print_format import *

log = logging.getLogger(__name__)


# logging.getLogger("angr").setLevel("CRITICAL")
def get_stdin_input(state):
    vars = list(state.solver.get_variables('file', 'stdin'))
    fmt_input = []
    for _, var in vars:
        bytestr = b""
        for i, c in enumerate(var.chop(8)):
            if state.satisfiable(extra_constraints=[c == 0x42]):
                state.add_constraints(c == 0x42)
            bytestr += state.solver.eval(c).to_bytes(1, context.endian)
        print(bytestr)
        fmt_input.append(bytestr)
    return fmt_input

def detect_leak(binary: Binary):
    context.binary = binary.elf
    p = angr.Project(binary.bin_path, load_options={"auto_load_libs": False})
    # p.entry = 0x400000
    # Hook rands
    p.hook_symbol("rand", RandHook(), replace=True)
    p.hook_symbol("srand", RandHook(), replace=True)
    # Hook exit
    p.hook_symbol("exit", ExitHook(), replace=True)

    # Stdio based ones
    p.hook_symbol("printf", PrintfLeak(0))
    p.hook_symbol("fprintf", PrintfLeak(1))
    p.hook_symbol("dprintf", PrintfLeak(1))
    p.hook_symbol("sprintf", PrintfLeak(1))
    p.hook_symbol("snprintf", PrintfLeak(2))

    # Stdarg base ones
    p.hook_symbol("vprintf", PrintfLeak(0))
    p.hook_symbol("vfprintf", PrintfLeak(1))
    p.hook_symbol("vdprintf", PrintfLeak(1))
    p.hook_symbol("vsprintf", PrintfLeak(1))
    p.hook_symbol("vsnprintf", PrintfLeak(2))

    p.hook_symbol("puts", PutsLeak())

    state = p.factory.entry_state()

    state.libc.buf_symbolic_bytes = 0x100
    state.libc.max_gets_size = 0x100
    state.globals["exit"] = False
    simgr = p.factory.simgr(state, save_unconstrained=True)
    vuln_details = {}
    # Lame way to do a timeout
    try:

        # @timeout_decorator.timeout(120)
        def explore_binary(simgr: angr.sim_manager):
            simgr.explore(
                find=lambda s: "type" in s.globals,
                # avoid=lambda s: s.globals["exit"] is True
            )

        explore_binary(simgr)

        if "found" in simgr.stashes and len(simgr.found):
            exploit_state: angr.SimState = simgr.found[0]
            # simgr = p.factory.simgr(exploit_state, save_unconstrained=True)
            # simgr.explore()
            # print(simgr.stashes)
            # end_state = simgr.pruned[0]
            end_state = exploit_state
            vuln_details["type"] = end_state.globals["type"]
            vuln_details["input"] = get_stdin_input(end_state)
            vuln_details["leak"] = end_state.globals["leak"]
            vuln_details["length"] = end_state.globals["length"]
            vuln_details["output"] = end_state.posix.dumps(1)

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Keyboard Interrupt")

    return vuln_details

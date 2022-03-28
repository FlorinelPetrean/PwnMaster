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
from func_model.print_format import *

# from func_model.print_format import *

log = logging.getLogger(__name__)


logging.getLogger("angr").setLevel("CRITICAL")


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


def detect_format_string(binary: Binary):
    context.binary = binary.elf
    p = angr.Project(binary.bin_path, load_options={"auto_load_libs": False})
    # Hook rands
    p.hook_symbol("rand", RandHook(), replace=True)
    p.hook_symbol("srand", RandHook(), replace=True)
    # Hook exit
    p.hook_symbol("exit", ExitHook(), replace=True)

    # Stdio based ones
    p.hook_symbol("printf", PrintFormat(0), replace=True)
    p.hook_symbol("fprintf", PrintFormat(1))
    p.hook_symbol("dprintf", PrintFormat(1))
    p.hook_symbol("sprintf", PrintFormat(1))
    p.hook_symbol("snprintf", PrintFormat(2))

    # Stdarg base ones
    p.hook_symbol("vprintf", PrintFormat(0))
    p.hook_symbol("vfprintf", PrintFormat(1))
    p.hook_symbol("vdprintf", PrintFormat(1))
    p.hook_symbol("vsprintf", PrintFormat(1))
    p.hook_symbol("vsnprintf", PrintFormat(2))

    # symbolic_input = claripy.BVS("input", 300 * 8)
    input_type = binary.detect_input_type()

    state = p.factory.entry_state()

    state.libc.buf_symbolic_bytes = 0x100
    state.libc.max_gets_size = 0x100
    state.globals["input_type"] = input_type
    state.globals["exit"] = False
    simgr = p.factory.simgr(state, save_unconstrained=True)
    print(simgr.stashes)
    vuln_details = {}
    # Lame way to do a timeout
    try:

        # @timeout_decorator.timeout(120)
        def explore_binary(simgr: angr.sim_manager):
            simgr.explore(
                find=lambda s: "type" in s.globals,
                avoid=lambda s: s.globals["exit"] is True
            )

        explore_binary(simgr)

        if "found" in simgr.stashes and len(simgr.found):
            exploit_state : angr.SimState = simgr.found[0]
            simgr = p.factory.simgr(exploit_state, save_unconstrained=True)
            simgr.explore()
            print(simgr.stashes)
            end_state = simgr.pruned[0]
            vuln_details["type"] = end_state.globals["type"]
            vuln_details["input"] = get_stdin_input(end_state)
            vuln_details["position"] = end_state.globals["position"]
            vuln_details["length"] = end_state.globals["length"]
            vuln_details["output"] = end_state.posix.dumps(1)

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Keyboard Interrupt")

    return vuln_details

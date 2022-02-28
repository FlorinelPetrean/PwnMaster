import angr
from angr import sim_options as so
from binary.binary import *
import claripy
import timeout_decorator
import logging
from func_model.rand import *
from func_model.exit import *

log = logging.getLogger(__name__)


# logging.getLogger("angr").setLevel("CRITICAL")


def printable_char(state, c):
    '''returns constraints s.t. c is printable'''
    return state.solver.And(c <= '~', c >= ' ')


def bof_filter(simgr):
    for state in simgr.unconstrained:
        bits = state.arch.bits
        num_count = bits / 8
        pc_value = b"X" * int(num_count)
        # Check satisfiability
        if state.solver.satisfiable(extra_constraints=[state.regs.pc == pc_value]):
            log.info("Found vulnerable state.")
            state.add_constraints(state.regs.pc == pc_value)
            user_input = state.globals["user_input"]
            input_bytes = state.solver.eval(user_input, cast_to=bytes)
            offset = input_bytes.index(pc_value)

            log.info("Constraining input to be printable and everything after return address is constrained")
            index = 0
            for c in user_input.chop(8):
                if index > offset:
                    constraint = claripy.And(c == 0x41, c == 0x41)
                else:
                    constraint = claripy.And(c > 0x2F, c < 0x7F)
                if state.solver.satisfiable([constraint]):
                    state.add_constraints(constraint)
                index = index + 1

            # Get input values
            # input_data = state.posix.stdin.load(0, state.posix.stdin.size)
            input_bytes = state.solver.eval(user_input, cast_to=bytes)
            log.info("[+] Vulnerable path found {}".format(input_bytes))
            if b"XXXX" in input_bytes:
                log.info("[+] Offset to bytes : {}".format(input_bytes.index(pc_value)))
            state.globals["type"] = "Overflow"
            state.globals["input"] = input_bytes
            simgr.stashes["found"].append(state)
            simgr.stashes["unconstrained"].remove(state)
            break

    return simgr


def detect_overflow(binary: Binary):
    p = angr.Project(binary.bin_path, load_options={"auto_load_libs": False})
    # Hook rands
    p.hook_symbol("rand", RandHook())
    p.hook_symbol("srand", RandHook())
    # Hook exit
    p.hook_symbol("exit", ExitHook())

    # Setup state based on input type
    argv = [binary.elf.path]
    symbolic_input = claripy.BVS("input", 300 * 8)
    input_type = binary.detect_input_type()
    if input_type == "STDIN":
        state = p.factory.full_init_state(args=argv, stdin=symbolic_input)
        state.globals["user_input"] = symbolic_input
    else:
        argv.append(symbolic_input)
        state = p.factory.full_init_state(args=argv, stdin=symbolic_input)
        state.globals["user_input"] = symbolic_input

    state.libc.buf_symbolic_bytes = 0x100
    state.globals["input_type"] = input_type
    state.globals["exit"] = False
    simgr = p.factory.simgr(state, save_unconstrained=True)

    vuln_details = {"type": None, "input": None, "offset": None}
    # Lame way to do a timeout
    try:

        @timeout_decorator.timeout(120)
        def explore_binary(simgr: angr.sim_manager):
            simgr.explore(
                find=lambda s: "type" in s.globals, step_func=bof_filter,
                avoid=lambda s: s.globals["exit"] is True
            )

        explore_binary(simgr)

        if "found" in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            print("input", end_state.posix.dumps(0))
            print("output", end_state.posix.dumps(1))
            vuln_details["type"] = end_state.globals["type"]
            vuln_details["input"] = end_state.globals["input"]
            vuln_details["output"] = end_state.posix.dumps(1)

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Keyboard Interrupt")

    return vuln_details

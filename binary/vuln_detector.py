import angr
from angr import sim_options as so
from binary.binary import *
import claripy
import timeout_decorator
import logging

log = logging.getLogger(__name__)
# logging.getLogger("angr").setLevel("CRITICAL")


def overflow_detect_filter(simgr):
    for state in simgr.unconstrained:
        bits = state.arch.bits
        num_count = bits / 8
        pc_value = b"C" * int(num_count)

        # Check satisfiability
        if state.solver.satisfiable(extra_constraints=[state.regs.pc == pc_value]):

            state.add_constraints(state.regs.pc == pc_value)
            user_input = state.globals["user_input"]

            log.info("Found vulnerable state.")

            log.info("Constraining input to be printable")
            for c in user_input.chop(8):
                constraint = claripy.And(c > 0x2F, c < 0x7F)
                if state.solver.satisfiable([constraint]):
                    state.add_constraints(constraint)

            # Get input values
            input_bytes = state.solver.eval(user_input, cast_to=bytes)
            log.info("[+] Vulnerable path found {}".format(input_bytes))
            if b"CCCC" in input_bytes:
                log.info("[+] Offset to bytes : {}".format(input_bytes.index(b"CCCC")))
            state.globals["offset"] = input_bytes.index(b"CCCC")
            state.globals["type"] = "Overflow"
            state.globals["input"] = input_bytes
            simgr.stashes["found"].append(state)
            simgr.stashes["unconstrained"].remove(state)
            break

    return simgr


def detect_overflow(binary: Binary):
    # extras = {
    #     so.REVERSE_MEMORY_NAME_MAP,
    #     so.TRACK_ACTION_HISTORY,
    #     so.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    #     so.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    # }

    class HookRand(angr.SimProcedure):
        IS_FUNCTION = True

        def run(self):
            return 4  # Fair dice roll

    p = angr.Project(binary.bin_path, load_options={"auto_load_libs": False})
    # Hook rands
    p.hook_symbol("rand", HookRand)
    p.hook_symbol("srand", HookRand)
    # p.hook_symbol('fgets',angr.SIM_PROCEDURES['libc']['gets']())

    # Setup state based on input type
    argv = [binary.elf.path]
    symbolic_input = claripy.BVS("input", 300 * 8)
    input_type = binary.detect_input_type()
    if input_type == "STDIN":
        state = p.factory.full_init_state(args=argv, stdin=symbolic_input)
        state.globals["user_input"] = symbolic_input
    else:
        argv.append(symbolic_input)
        state = p.factory.full_init_state(args=argv)
        state.globals["user_input"] = symbolic_input

    # state.libc.buf_symbolic_bytes = 0x100
    state.globals["input_type"] = input_type
    simgr = p.factory.simgr(state, save_unconstrained=True)

    vuln_details = {"type": None, "input": None, "offset": None}
    # Lame way to do a timeout
    try:

        @timeout_decorator.timeout(120)
        def explore_binary(simgr):
            simgr.explore(
                find=lambda s: "type" in s.globals, step_func=overflow_detect_filter
            )

        explore_binary(simgr)
        if "found" in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            vuln_details["type"] = end_state.globals["type"]
            vuln_details["input"] = end_state.globals["input"]
            vuln_details["offset"] = end_state.globals["offset"]

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Keyboard Interrupt")

    return vuln_details

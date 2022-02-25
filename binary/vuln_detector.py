import angr
from angr import sim_options as so
from binary.binary import *
import claripy
import timeout_decorator
import logging

log = logging.getLogger(__name__)


# logging.getLogger("angr").setLevel("CRITICAL")


def char(state, c):
    '''returns constraints s.t. c is printable'''
    return state.solver.And(c <= '~', c >= ' ')


def overflow_detect_filter(simgr):
    for state in simgr.unconstrained:
        bits = state.arch.bits
        num_count = bits / 8
        pc_value = b"C" * int(num_count)
        # Check satisfiability
        if state.solver.satisfiable(extra_constraints=[state.regs.pc == pc_value]):

            state.add_constraints(state.regs.pc == pc_value)

            state.add_constraints(b"Go to return!\n" in state.posix.dumps(1))
            user_input = state.globals["user_input"]
            input_bytes = state.solver.eval(user_input, cast_to=bytes)
            offset = input_bytes.index(pc_value)

            log.info("Found vulnerable state.")

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
            if b"CCCC" in input_bytes:
                log.info("[+] Offset to bytes : {}".format(input_bytes.index(pc_value)))
            state.globals["offset"] = input_bytes.index(pc_value)
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
        state = p.factory.full_init_state(args=argv, stdin=symbolic_input)
        state.globals["user_input"] = symbolic_input

    # constrain_stdin_printable(state)
    state.libc.buf_symbolic_bytes = 0x100
    state.globals["input_type"] = input_type
    simgr = p.factory.simgr(state, save_unconstrained=True)

    vuln_details = {"type": None, "input": None, "offset": None}
    # Lame way to do a timeout
    try:

        @timeout_decorator.timeout(120)
        def explore_binary(simgr: angr.sim_manager):
            simgr.explore(
                find=lambda s: "type" in s.globals, step_func=overflow_detect_filter
                # find=lambda s: b"Found vuln!\n" in s.posix.dumps(1)
                # find=lambda s: b"Go to return!" in s.posix.dumps(1)
            )

        explore_binary(simgr)

        if "found" in simgr.stashes and len(simgr.found):
            end_state = simgr.found[0]
            print("input", end_state.posix.dumps(0))
            print("output", end_state.posix.dumps(1))
            vuln_details["type"] = end_state.globals["type"]
            vuln_details["input"] = end_state.globals["input"]
            vuln_details["offset"] = end_state.globals["offset"]

            # simgr1 = p.factory.simgr(end_state, save_unconstrained=True)
            #
            # simgr1.explore(
            #     # find=lambda s: "type" in s.globals, step_func=overflow_detect_filter
            #     # find=lambda s: b"Found vuln!\n" in s.posix.dumps(1)
            #     find=lambda s: b"Go to return!" in s.posix.dumps(1)
            # )
            # print(simgr1.found[0])


    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Keyboard Interrupt")

    return vuln_details

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

# from func_model.print_format import *

log = logging.getLogger(__name__)


# logging.getLogger("angr").setLevel("CRITICAL")


def bof_filter(simgr: angr.sim_manager):
    for state in simgr.unconstrained:
        bits = state.arch.bits
        addr_size = bits // 8
        pc_value = b"X" * addr_size
        # Check satisfiability
        if state.solver.satisfiable(extra_constraints=[state.regs.pc == pc_value]):
            log.info("Found vulnerable state.")
            state.add_constraints(state.regs.pc == pc_value)

            sp = state.callstack.current_stack_pointer
            buf_mem = state.memory.load(sp - addr_size, 300 * 8)
            control_after_ret = 0

            for index, c in enumerate(buf_mem.chop(8)):
                constraint = claripy.And(c == b"P", c == b"P")
                if state.solver.satisfiable([constraint]):
                    state.add_constraints(constraint)
                    control_after_ret += 1
                else:
                    break

            print(list(state.solver.get_variables('mem')))
            vars = list(state.solver.get_variables('file', 'stdin'))
            crash_input = []
            for _, var in vars:
                var_val = b""
                for i, c in enumerate(var.chop(8)):
                    constraint = claripy.And(c == 0x42, c == 0x42)
                    if state.solver.satisfiable([constraint]):
                        state.add_constraints(constraint)
                    var_val += state.solver.eval(c).to_bytes(1, context.endian)
                print(var_val)
                if pc_value in var_val:
                    offset = var_val.index(pc_value)
                    controlled_bytes = var_val[0:offset].count(b"B")
                    state.globals["control_before_ret"] = controlled_bytes
                crash_input.append(var_val)

            # for buf_addr in find_symbolic_buffer(state, 10):
            #     log.info("found symbolic buffer at %#x", buf_addr)

            state.globals["type"] = "bof"
            if "control_after_ret" not in state.globals:
                state.globals["control_after_ret"] = control_after_ret
            state.globals["input"] = crash_input
            simgr.stashes["found"].append(state)
            simgr.stashes["unconstrained"].remove(state)
            return simgr

    return simgr


def detect_overflow(binary: Binary):
    context.binary = binary.elf
    p = angr.Project(binary.bin_path, load_options={"auto_load_libs": False})
    # Hook rands
    p.hook_symbol("rand", RandHook())
    p.hook_symbol("srand", RandHook())
    # Hook exit
    p.hook_symbol("exit", ExitHook(), replace=True)

    # p.hook_symbol("scanf", ScanfHook())
    p.hook_symbol("gets", GetsHook(), replace=True)

    # p.hook_symbol("printf", PrintFormat(0))

    # Setup state based on input type
    argv = [binary.elf.path]
    # symbolic_input = claripy.BVS("input", 300 * 8)
    input_type = binary.detect_input_type()
    # if input_type == "STDIN":
    #     state = p.factory.full_init_state(args=argv, stdin=symbolic_input)
    #     state.globals["user_input"] = symbolic_input
    # else:
    #     argv.append(symbolic_input)
    #     state = p.factory.full_init_state(args=argv, stdin=symbolic_input)
    #     state.globals["user_input"] = symbolic_input

    state = p.factory.entry_state()

    state.libc.buf_symbolic_bytes = 0x100
    state.libc.max_gets_size = 0x100
    state.globals["input_type"] = input_type
    state.globals["exit"] = False
    simgr = p.factory.simgr(state, save_unconstrained=True)
    vuln_details = {}
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
            # print("input", end_state.posix.dumps(0))
            # print("output", end_state.posix.dumps(1))

            vuln_details["type"] = end_state.globals["type"]
            vuln_details["input"] = end_state.globals["input"]
            vuln_details["control_before_ret"] = end_state.globals["control_before_ret"]
            vuln_details["control_after_ret"] = end_state.globals["control_after_ret"]
            vuln_details["output"] = end_state.posix.dumps(1)

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Keyboard Interrupt")

    return vuln_details

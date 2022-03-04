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

def fully_symbolic(state, variable):
    '''
    check if a symbolic variable is completely symbolic
    '''

    for i in range(state.arch.bits):
        if not state.solver.symbolic(variable[i]):
            return False

    return True


def check_continuity(address, addresses, length):
    '''
    dumb way of checking if the region at 'address' contains 'length' amount of controlled
    memory.
    '''

    for i in range(length):
        if not address + i in addresses:
            return False

    return True


def find_symbolic_buffer(state, length):
    '''
    dumb implementation of find_symbolic_buffer, looks for a buffer in memory under the user's
    control
    '''

    # get all the symbolic bytes from stdin

    sym_addrs = []
    for _, symbol in state.solver.get_variables('file', 'stdin'):
        sym_addrs.extend(state.memory.addrs_for_name(next(iter(symbol.variables))))

    for addr in sym_addrs:
        if check_continuity(addr, sym_addrs, length):
            yield addr


def printable_char(state, c):
    '''returns constraints s.t. c is printable'''
    return state.solver.And(c <= '~', c >= ' ')


def bof_filter(simgr):
    for state in simgr.unconstrained:
        bits = state.arch.bits
        addr_size = bits // 8
        pc_value = b"X" * addr_size
        # Check satisfiability
        if state.solver.satisfiable(extra_constraints=[state.regs.pc == pc_value]):
            log.info("Found vulnerable state.")
            state.add_constraints(state.regs.pc == pc_value)

            sp = state.callstack.current_stack_pointer - addr_size
            buf_mem = state.memory.load(sp, 300 * 8)
            controlled_stack_space = 0

            for index, c in enumerate(buf_mem.chop(8)):
                constraint = claripy.And(c == b"P", c == b"P")
                if state.solver.satisfiable([constraint]):
                    state.add_constraints(constraint)
                    controlled_stack_space += 1
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
                    var_val += state.solver.eval(c).to_bytes(1, 'little')
                print(var_val)
                crash_input.append(var_val)

            for buf_addr in find_symbolic_buffer(state, 10):
                log.info("found symbolic buffer at %#x", buf_addr)


            state.globals["type"] = "bof"
            if "ctrl_stack_space" not in state.globals:
                state.globals["ctrl_stack_space"] = controlled_stack_space
            state.globals["input"] = crash_input
            simgr.stashes["found"].append(state)
            simgr.stashes["unconstrained"].remove(state)
            return simgr

    return simgr


def detect_overflow(binary: Binary):
    p = angr.Project(binary.bin_path, load_options={"auto_load_libs": False})
    # Hook rands
    p.hook_symbol("rand", RandHook())
    p.hook_symbol("srand", RandHook())
    # Hook exit
    p.hook_symbol("exit", ExitHook(), replace=True)

    p.hook_symbol("scanf", ScanfHook())
    p.hook_symbol("gets", GetsHook(), replace=True)

    # p.hook_symbol("printf", PrintFormat(0))

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

    state = p.factory.entry_state()

    state.libc.buf_symbolic_bytes = 0x100
    state.libc.max_gets_size = 128
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
            print("input", end_state.posix.dumps(0))
            print("output", end_state.posix.dumps(1))
            vuln_details["type"] = end_state.globals["type"]
            vuln_details["input"] = end_state.globals["input"]
            vuln_details["ctrl_stack_space"] = end_state.globals["ctrl_stack_space"]
            vuln_details["output"] = end_state.posix.dumps(1)

    except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
        log.info("[~] Keyboard Interrupt")

    return vuln_details

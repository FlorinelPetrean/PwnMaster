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
from func_model.printf_dummy import *

# from func_model.print_format import *

log = logging.getLogger(__name__)


# logging.getLogger("angr").setLevel("CRITICAL")

class BofDetector:
    def __init__(self, binary):
        self.binary = binary
        context.binary = binary.elf
        self.pc_value = b"X" * context.bytes

    def get_stdin_input(self, state):
        vars = list(state.solver.get_variables('file', 'stdin'))
        crash_input = []
        for _, var in vars:
            bytestr = b""
            for i, c in enumerate(var.chop(8)):
                constraint = claripy.And(c == 0x42, c == 0x42)
                if state.solver.satisfiable([constraint]):
                    state.add_constraints(constraint)
                bytestr += state.solver.eval(c).to_bytes(1, context.endian)
            print(bytestr)
            if self.pc_value in bytestr:
                offset = bytestr.index(self.pc_value)
                controlled_bytes = bytestr[0:offset].count(b"B")
                state.globals["control_before_ret"] = controlled_bytes
            crash_input.append(bytestr)

        return crash_input

    def bof_filter(self, simgr: angr.sim_manager):
        for state in simgr.unconstrained:
            # Check satisfiability
            if state.solver.satisfiable(extra_constraints=[state.regs.pc == self.pc_value]):
                log.info("Found vulnerable state.")
                state.add_constraints(state.regs.pc == self.pc_value)

                sp = state.callstack.current_stack_pointer
                buf_mem = state.memory.load(sp - context.bytes, 300 * 8)
                control_after_ret = 0

                for index, c in enumerate(buf_mem.chop(8)):
                    constraint = c == b"P"
                    if state.solver.satisfiable([constraint]):
                        state.add_constraints(constraint)
                        control_after_ret += 1
                    else:
                        break

                state.globals["type"] = "bof"
                if "control_after_ret" not in state.globals:
                    state.globals["control_after_ret"] = control_after_ret
                state.globals["input"] = self.get_stdin_input(state)
                simgr.stashes["found"].append(state)
                simgr.stashes["unconstrained"].remove(state)
                return simgr

        return simgr

    def explore_binary(self, p, state):
        simgr = p.factory.simgr(state, save_unconstrained=True)
        vuln_details = {}
        end_state = None
        # Lame way to do a timeout
        try:

            # @timeout_decorator.timeout(120)
            def explore_binary(simgr: angr.sim_manager):
                simgr.explore(
                    find=lambda s: "type" in s.globals and s.globals["type"] == "bof", step_func=self.bof_filter,
                    avoid=lambda s: s.globals["exit"] is True
                )

            explore_binary(simgr)
            print(simgr.stashes)

            if "found" in simgr.stashes and len(simgr.found):
                end_state = simgr.found[0]
                vuln_details["type"] = end_state.globals["type"]
                vuln_details["input"] = end_state.globals["input"]
                vuln_details["control_before_ret"] = end_state.globals["control_before_ret"]
                vuln_details["control_after_ret"] = end_state.globals["control_after_ret"]
                vuln_details["output"] = end_state.posix.dumps(1)
            if "deadended" in simgr.stashes and len(simgr.deadended):
                print(self.get_stdin_input(simgr.deadended[0]))

        except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
            log.info("[~] Keyboard Interrupt")

        return vuln_details, end_state

    def detect_overflow(self, p=None, state=None):
        p = angr.Project(self.binary.bin_path, load_options={"auto_load_libs": False}) if p is None else p
        # Hook rands
        p.hook_symbol("rand", RandHook())
        p.hook_symbol("srand", RandHook())
        # Hook exit
        p.hook_symbol("exit", ExitHook(), replace=True)

        p.hook_symbol("gets", GetsHook(), replace=True)
        p.hook_symbol("printf", PrintfDummy(), replace=True)

        state = p.factory.entry_state() if state is None else state

        state.libc.buf_symbolic_bytes = 0x100
        state.libc.max_gets_size = 0x200
        # state.globals["input_type"] = input_type
        state.globals["exit"] = False

        return self.explore_binary(p, state)

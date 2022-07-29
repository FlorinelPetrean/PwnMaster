from pwn import *
import angr
import claripy
import tqdm
import logging

log = logging.getLogger(__name__)


class PutsLeak(angr.procedures.libc.puts.puts):
    IS_FUNCTION = True

    def check_for_leak(self, string):

        state = self.state
        obj = state.project.loader.main_object
        print("Checking for leak...")
        print()
        format_arg = self.arguments[0]
        format_addr = self.state.solver.eval(format_arg)

        # string should be a ptr, we are going to check
        # to see if it's pointing to a got entry
        string_addr = state.solver.eval(string)
        mem = state.memory.load(string_addr, 8 + 3)
        val_content1 = state.solver.eval(mem)
        val_content = state.mem[string_addr]
        for addr, name in obj.plt.items():
            if addr == val_content1:
                log.info("[+] Puts leaked {}".format(name))
                state.globals["type"] = "leak"
                state.globals["output_before_leak"] = state.posix.dumps(1)
                state.globals["leaked_func"] = name
                return True

        # elf = ELF(state.project.filename)
        # for name, addr in elf.symbols.items():
        #     addr_x = hex(addr)
        #     addr_val = hex(val_content1)
        #     if val_content1 == addr:
        #         log.info("[+] Puts leaked {}".format(name))
        #         state.globals["type"] = "leak"
        #         state.globals["output_before_leak"] = state.posix.dumps(1)
        #         state.globals["leaked_func"] = name
        #         return True
        #
        # return False

    def run(self, string):
        self.check_for_leak(string)

        # Wait till angr #3026 gets merged, then change it back
        # to
        return super(type(self), self).run(string)



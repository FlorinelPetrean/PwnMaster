from pwn import *
import angr
import claripy
import tqdm
from .simgr_helper import get_trimmed_input
import logging
import copy

log = logging.getLogger(__name__)


# Better symbolic strlen
def get_max_strlen(state, value):
    i = 0
    for c in value.chop(8):  # Chop by byte
        i += 1
        if not state.solver.satisfiable([c != 0x00]):
            log.debug("Found the null at offset : {}".format(i))
            return i - 1
    return i


"""
Model either printf("User input") or printf("%s","Userinput")
"""


class PrintfLeak(angr.procedures.libc.printf.printf):
    IS_FUNCTION = True
    format_index = 0
    """
    Checks userinput arg
    """

    def __init__(self, format_index):
        # Set user input index for different
        # printf types
        self.format_index = format_index
        super(type(self), self).__init__()

    def check_for_leak(self, fmt):

        bits = self.state.arch.bits
        load_len = int(bits / 8)
        max_read_len = 1024
        """
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        """
        state = self.state
        p = self.state.project
        elf = ELF(state.project.filename)

        fmt_str = self._parse(fmt)

        for component in fmt_str.components:

            # We only want format specifiers
            if (
                    isinstance(component, bytes)
                    or isinstance(component, str)
                    or isinstance(component, claripy.ast.BV)
            ):
                continue

            printf_arg = component

            fmt_spec = component

            i_val = self.va_arg("void*")

            c_val = int(state.solver.eval(i_val))
            c_val &= (1 << (fmt_spec.size * 8)) - 1
            if fmt_spec.signed and (c_val & (1 << ((fmt_spec.size * 8) - 1))):
                c_val -= 1 << fmt_spec.size * 8

            if fmt_spec.spec_type in (b"d", b"i"):
                s_val = str(c_val)
            elif fmt_spec.spec_type == b"u":
                s_val = str(c_val)
            elif fmt_spec.spec_type == b"c":
                s_val = chr(c_val & 0xFF)
            elif fmt_spec.spec_type == b"x":
                s_val = hex(c_val)[2:]
            elif fmt_spec.spec_type == b"o":
                s_val = oct(c_val)[2:]
            elif fmt_spec.spec_type == b"p":
                s_val = hex(c_val)
            else:
                log.warning("Unimplemented format specifier '%s'" % fmt_spec.spec_type)
                continue

            if isinstance(fmt_spec.length_spec, int):
                s_val = s_val.rjust(fmt_spec.length_spec, fmt_spec.pad_chr)

            var_addr = c_val

            # Are any pointers GOT addresses?
            for name, addr in elf.got.items():
                if var_addr == addr:
                    log.info("[+] Printf leaked GOT {}".format(name))
                    state.globals["leaked_type"] = "function"
                    state.globals["leaked_func"] = name
                    state.globals["leaked_addr"] = var_addr

                    # Input to leak
                    user_input = state.globals["user_input"]
                    input_bytes = state.solver.eval(user_input, cast_to=bytes)

                    state.globals["leak_input"] = input_bytes
                    state.globals["leak_output"] = state.posix.dumps(1)
                    return True
            # Heap and stack addrs should be in a heap or stack
            # segment, but angr doesn't map those segments so the
            # below call will not work
            # found_obj = p.loader.find_segment_containing(var_addr)

            # Check for stack address leak
            # So we have a dumb check to see if it's a stack addr
            stack_ptr = state.solver.eval(state.regs.sp)

            var_addr_mask = var_addr >> 28
            stack_ptr_mask = stack_ptr >> 28

            if var_addr_mask == stack_ptr_mask:
                log.info("[+] Leaked a stack addr : {}".format(hex(var_addr)))
                state.globals["leaked_type"] = "stack_address"
                state.globals["leaked_addr"] = var_addr

                # Input to leak
                user_input = state.globals["user_input"]
                input_bytes = state.solver.eval(user_input, cast_to=bytes)

                input_bytes = get_trimmed_input(user_input, state)

                state.globals["leak_input"] = input_bytes
                state.globals["leak_output"] = state.posix.dumps(1)
            # Check tracked malloc addrs
            if "stored_malloc" in self.state.globals.keys():
                for addr in self.state.globals["stored_malloc"]:
                    if addr == var_addr:
                        log.info("[+] Leaked a heap addr : {}".format(hex(var_addr)))
                        state.globals["leaked_type"] = "heap_address"
                        state.globals["leaked_addr"] = var_addr

                        # Input to leak
                        user_input = state.globals["user_input"]
                        input_bytes = state.solver.eval(user_input, cast_to=bytes)

                        state.globals["leak_input"] = input_bytes
                        state.globals["leak_output"] = state.posix.dumps(1)

    def run(self, fmt):
        """
        Iterating over the va_args checking for a leak
        will consume them and prevent us from printing
        normally, so we need to make a copy.
        """
        va_args_copy = copy.deepcopy(self)

        va_args_copy.check_for_leak(fmt)

        return super(type(self), self).run(fmt)

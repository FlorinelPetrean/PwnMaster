from pwn import *
import angr
import claripy
import tqdm
# from .simgr_helper import get_trimmed_input
import logging
import copy

log = logging.getLogger(__name__)


# Better symbolic strlen
def get_max_strlen(state, bitstring):
    i = 0
    for c in bitstring.chop(8):  # Chop by byte
        i += 1
        if not state.solver.satisfiable([c != 0x00]):
            log.debug("Found the null at offset : {}".format(i))
            return i - 1
    return i


def is_char_symbolic(ch):
    for b in ch.chop(1):
        if not b.symbolic:
            return False
    return True


"""
Model either printf("User input") or printf("%s","Userinput")
"""


class PrintFormat(angr.procedures.libc.printf.printf):
    IS_FUNCTION = True
    format_index = 0
    """
    Checks userinput arg
    """

    def __init__(self, format_index):
        # Set user input index for different
        # printf types
        self.format_index = format_index
        angr.procedures.libc.printf.printf.__init__(self)

    def detect_vuln(self, fmt):

        bits = self.state.arch.bits
        max_read_len = 300 * 8
        """
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        """
        i = self.format_index
        state = self.state
        eval = state.solver.eval

        format_arg = self.arguments[i]

        format_addr = eval(format_arg)

        # Parts of this argument could be symbolic, so we need
        # to check every byte
        var_data = state.memory.load(format_addr, max_read_len)
        var_len = get_max_strlen(state, var_data)

        self._sim_strlen(fmt)

        # Reload with just our max len
        var_data = state.memory.load(format_addr, var_len * 8)

        buffer_length = 0
        largest_buffer_position = 0
        largest_buffer_length = buffer_length
        for index, c in enumerate(var_data.chop(8)):
            if not is_char_symbolic(c) or eval(c) == b"\x00":
                if largest_buffer_length < buffer_length:
                    largest_buffer_length = buffer_length
                    largest_buffer_position = index - buffer_length
                buffer_length = 0
            else:
                buffer_length += 1

        buffer_position = largest_buffer_position
        buffer_length = largest_buffer_length

        log.info(
            "[+] Found symbolic buffer at position {} of length {}".format(
                buffer_position, buffer_length
            )
        )
        buffer = state.memory.load(format_addr + buffer_position, buffer_length * 8)

        if buffer_length > 0:
            constrained = True
            # str_val = b"%lx|" if bits == 32 else b"%llx|"
            str_val = b"F"
            concrete_buffer_val = str_val * (buffer_length // len(str_val))
            if state.solver.satisfiable(extra_constraints=[buffer == concrete_buffer_val]):
                state.add_constraints(buffer == concrete_buffer_val)
                constrained = True
            else:
                for index, c in enumerate(buffer.chop(8)):
                    if state.solver.satisfiable(extra_constraints=[c == concrete_buffer_val[index]]):
                        state.add_constraints(c == concrete_buffer_val[index])
                    else:
                        constrained = False

            if constrained is True:
                self.state.globals["input"] = eval(buffer, cast_to=bytes)
                self.state.globals["type"] = "fmt"
                self.state.globals["position"] = buffer_position
                self.state.globals["length"] = buffer_length

                return True

        return False

    def run(self, _, fmt):
        if not self.detect_vuln(fmt):
            return super(type(self), self).run(fmt)

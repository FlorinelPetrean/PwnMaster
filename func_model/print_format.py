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

    def __init__(self, format_index, **kwargs):
        # Set user input index for different
        # printf types
        super().__init__(**kwargs)
        self.format_index = format_index
        angr.procedures.libc.printf.printf.__init__(self)

    def is_vulnerable(self, fmt):

        max_read_len = 1024
        """
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        """
        i = self.format_index

        format_arg = self.arguments[i]

        format_addr = self.state.solver.eval(format_arg)

        # Parts of this argument could be symbolic, so we need
        # to check every byte
        old_format_data = self.state.memory.load(format_addr, max_read_len)
        max_len = get_max_strlen(self.state, old_format_data)

        self._sim_strlen(fmt)

        # Reload with just our max len
        format_data = self.state.memory.load(format_addr, max_len)

        buffer_position = None
        buffer_length = 0
        largest_buffer_position = buffer_position
        largest_buffer_length = buffer_length
        for index, c in enumerate(format_data.chop(8)):
            if not c.symbolic or index == max_len - 1:
                if largest_buffer_length < buffer_length:
                    largest_buffer_length = buffer_length
                    largest_buffer_position = buffer_position
                    buffer_position = None
                buffer_length = 0
                if index == max_len - 1:
                    break
            else:
                if buffer_position is None:
                    buffer_position = index
                buffer_length += 1

        buffer_position = largest_buffer_position
        buffer_length = largest_buffer_length

        log.info(
            "[+] Found symbolic buffer at position {} of length {}".format(
                buffer_position, buffer_length
            )
        )

        buffer = self.state.memory.load(format_addr + buffer_position, buffer_length)

        if buffer_length > 0:
            str_val = b"F"
            buffer_val = str_val * buffer_length

            if self.state.solver.satisfiable(extra_constraints=[buffer == buffer_val[:buffer_length]]):
                log.info("Can constrain it all, let's go!")
                self.state.add_constraints(buffer == buffer_val[:buffer_length])
            else:
                for index, c in enumerate(buffer.chop(8)):
                    if self.state.solver.satisfiable(extra_constraints=[c == buffer_val[index]]):
                        self.state.add_constraints(c == buffer_val[index])

            vars = list(self.state.solver.get_variables('file', 'stdin'))
            crash_input = []
            for _, var in vars:
                bytestr = b""
                for i, c in enumerate(var.chop(8)):
                    constraint = c == 0x42
                    if self.state.solver.satisfiable([constraint]):
                        self.state.add_constraints(constraint)
                    bytestr += self.state.solver.eval(c).to_bytes(1, context.endian)
                print(bytestr)
                crash_input.append(bytestr)

            self.state.globals["input"] = crash_input
            self.state.globals["type"] = "fmt"
            self.state.globals["position"] = buffer_position
            self.state.globals["length"] = buffer_length

            return True

        return False

    def run(self, _, fmt):
        if not self.is_vulnerable(fmt):
            return super(type(self), self).run(fmt)

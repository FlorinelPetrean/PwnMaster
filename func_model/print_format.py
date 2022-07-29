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


"""
Model either printf("User input") or printf("%s","Userinput")
"""


class PrintFormat(angr.procedures.libc.printf.printf):
    IS_FUNCTION = True
    format_index = 0

    def __init__(self, format_index):
        # Set user input index for different
        # printf types
        self.format_index = format_index
        super(type(self), self).__init__()

    def is_vulnerable(self):
        max_read_len = 1024
        i = self.format_index
        format_arg = self.arguments[i]
        format_addr = self.state.solver.eval(format_arg)

        # Parts of this argument could be symbolic, so we need
        # to check every byte
        old_format_data = self.state.memory.load(format_addr, max_read_len)
        max_len = get_max_strlen(self.state, old_format_data)
        # Reload with just our max len
        format_data = self.state.memory.load(format_addr, max_len)

        buffer_position = None
        buffer_length = 0
        largest_buffer_position = buffer_position
        largest_buffer_length = buffer_length
        for index, c in enumerate(format_data.chop(8)):
            if c.symbolic:
                if buffer_position is None:
                    buffer_position = index
                buffer_length += 1
            if not c.symbolic or index == max_len - 1:
                if largest_buffer_length < buffer_length:
                    largest_buffer_length = buffer_length
                    largest_buffer_position = buffer_position
                    buffer_position = None
                buffer_length = 0

        if largest_buffer_length > 0:
            buffer_position = largest_buffer_position
            buffer_length = largest_buffer_length
            log.info("[+] Found symbolic buffer at position {} of length {}".format(buffer_position, buffer_length))
            buffer = self.state.memory.load(format_addr + buffer_position, buffer_length)
            str_val = b"F"
            buffer_val = str_val * buffer_length
            if self.state.solver.satisfiable(extra_constraints=[buffer == buffer_val[:buffer_length]]):
                log.info("Can constrain it all, let's go!")
                self.state.add_constraints(buffer == buffer_val[:buffer_length])
            else:
                for index, c in enumerate(buffer.chop(8)):
                    if self.state.solver.satisfiable(extra_constraints=[c == buffer_val[index]]):
                        self.state.add_constraints(c == buffer_val[index])

            self.state.globals["type"] = "fmt"
            self.state.globals["position"] = buffer_position
            self.state.globals["length"] = buffer_length
            return True

        return False

    def run(self, fmt):
        if not self.is_vulnerable():
            return super(type(self), self).run(fmt)


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

    def vulnerable(self, fmt):

        bits = self.state.arch.bits
        max_read_len = 100 * 8
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
        var_data = self.state.memory.load(format_addr, max_read_len)
        var_len = get_max_strlen(self.state, var_data)

        # self._sim_strlen(fmt)

        # Reload with just our max len
        var_data = self.state.memory.load(format_addr, var_len * 8)

        buffer_length = 0
        largest_buffer_position = 0
        largest_buffer_length = buffer_length
        for index, c in enumerate(var_data.chop(8)):
            if not is_char_symbolic(c) or self.state.solver.eval(c) == b'\x00':
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
        buffer = self.state.memory.load(format_addr + buffer_position, buffer_length * 8)

        if buffer_length > 0:
            constrained = True
            # str_val = b"%lx|" if bits == 32 else b"%llx|"
            str_val = b"F"
            concrete_buffer_val = str_val * (buffer_length // len(str_val))
            # if self.state.solver.satisfiable(extra_constraints=[buffer == concrete_buffer_val]):
            #     self.state.add_constraints(buffer == concrete_buffer_val)
            #     constrained = True
            # else:
            # for index, c in enumerate(buffer.chop(8)):
            #     if self.state.solver.satisfiable(extra_constraints=[c == b"F"]):
            #         self.state.add_constraints(c == b"F")
            #     else:
            #         constrained = False

            if self.can_constrain_bytes(
                self.state, format_addr, buffer_position, buffer_length, strVal=str_val
            ):
                log.info("[+] Can constrain bytes")
                log.info("[+] Constraining input to leak")

                self.constrainBytes(
                    self.state,
                    format_addr,
                    buffer_position,
                    buffer_length,
                    strVal=str_val,
                )

                # print(self.state.globals["user_input"].variables)
                # if constrained is True:
                # self.state.globals["input"] = self.state.solver.eval(self.state.globals["user_input"], cast_to=bytes)

                vars = list(self.state.solver.get_variables('file', 'stdin'))
                crash_input = []
                for _, var in vars:
                    bytestr = b""
                    for i, c in enumerate(var.chop(8)):
                        constraint = claripy.And(c == 0x42, c == 0x42)
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



    def can_constrain_bytes(self, state, loc, position, length, strVal=b"%x_"):
        total_region = self.state.memory.load(loc + position, length)
        total_format = strVal * length
        # If we can constrain it all in one go, then let's do it!
        if state.solver.satisfiable(
            extra_constraints=[total_region == total_format[:length]]
        ):
            log.info("Can constrain it all, let's go!")
            state.add_constraints(total_region == total_format[:length])
            return True

        for i in tqdm.tqdm(range(length), total=length, desc="Checking Constraints"):
            strValIndex = i % len(strVal)
            curr_byte = self.state.memory.load(loc + i, 1)
            if not state.solver.satisfiable(
                extra_constraints=[curr_byte == strVal[strValIndex]]
            ):
                return False
        return True

    def constrainBytes(self, state, loc, position, length, strVal=b"%x_"):

        total_region = self.state.memory.load(loc + position, length)
        total_format = strVal * length
        # If we can constrain it all in one go, then let's do it!
        if state.solver.satisfiable(
            extra_constraints=[total_region == total_format[:length]]
        ):
            log.info("Can constrain it all, let's go!")
            state.add_constraints(total_region == total_format[:length])
            return

        for i in tqdm.tqdm(range(length), total=length, desc="Constraining"):
            strValIndex = i % len(strVal)
            curr_byte = self.state.memory.load(loc + i, 1)
            if state.solver.satisfiable(
                extra_constraints=[curr_byte == strVal[strValIndex]]
            ):
                state.add_constraints(curr_byte == strVal[strValIndex])
            else:
                log.info(
                    "[~] Byte {} not constrained to {}".format(i, strVal[strValIndex])
                )

    def run(self, _, fmt):
        if not self.vulnerable(fmt):
            return super(type(self), self).run(fmt)

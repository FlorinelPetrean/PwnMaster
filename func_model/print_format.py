from pwn import *
import angr
import claripy
import tqdm
# from .simgr_helper import get_trimmed_input
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
        max_read_len = 1024
        """
        For each value passed to printf
        Check to see if there are any symbolic bytes
        Passed in that we control
        """
        i = self.format_index
        state = self.state
        solv = state.solver.eval

        format_arg = self.arguments[i]

        format_addr = solv(format_arg)

        # Parts of this argument could be symbolic, so we need
        # to check every byte
        var_data = state.memory.load(format_addr, max_read_len)
        var_len = get_max_strlen(state, var_data)

        self._sim_strlen(fmt)

        # Reload with just our max len
        var_data = state.memory.load(format_addr, var_len)

        log.info("Building list of symbolic bytes")
        symbolic_list = [
            state.memory.load(format_addr + x, 1).symbolic for x in range(var_len)
        ]
        log.info("Done Building list of symbolic bytes")

        """
        Iterate over the characters in the string
        Checking for where our symbolic values are
        This helps in weird cases like:

        char myVal[100] = "I\'m cool ";
        strcat(myVal,STDIN);
        printf(myVal);
        """
        position = 0
        count = 0
        greatest_count = 0
        for i in range(1, len(symbolic_list)):
            if symbolic_list[i] and symbolic_list[i] == symbolic_list[i - 1]:
                count = count + 1
                if count > greatest_count:
                    greatest_count = count
                    position = i - count
            else:
                if count > greatest_count:
                    greatest_count = count
                    position = i - 1 - count
                    # previous position minus greatest count
                count = 0

        log.info(
            "[+] Found symbolic buffer at position {} of length {}".format(
                position, greatest_count
            )
        )

        if greatest_count > 0:
            str_val = b"%lx_"
            if bits == 64:
                str_val = b"%llx_"
            if self.can_constrain_bytes(
                    state, format_addr, position, var_len, strVal=str_val
            ):
                log.info("[+] Can constrain bytes")
                log.info("[+] Constraining input to leak")

                self.constrainBytes(
                    state,
                    format_addr,
                    position,
                    var_len,
                    strVal=str_val,
                )
                # Verify solution
                user_input = state.globals["user_input"]

                self.state.globals["input"] = solv(user_input, cast_to=bytes)
                self.state.globals["type"] = "Format"
                self.state.globals["position"] = position
                self.state.globals["length"] = greatest_count

                return True

        return False

    def can_constrain_bytes(self, state, loc, position, length, strVal=b"%x_"):
        total_region = self.state.memory.load(loc, length)
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

        total_region = self.state.memory.load(loc, length)
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
        if not self.detect_vuln(fmt):
            return super(type(self), self).run(fmt)

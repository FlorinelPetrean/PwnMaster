from pwn import *
from subprocess import Popen, PIPE

context.arch = 'amd64'


class Binary:
    def __init__(self,
                 binary_path):
        self.bin_path = binary_path
        context.binary = self.bin_path
        self.elf = ELF(self.bin_path)
        self.protection = self.init_properties()
        self.input_type = self.detect_input_type()
        self.libc = self.init_libc()
        self.arch = self.elf.arch

    def init_libc(self):
        libc = None
        try:
            libc = self.elf.libc
        except ValueError:
            pass
        return libc

    def init_properties(self):
        properties = {
            "aslr": self.elf.aslr,
            "canary": self.elf.canary,
            "nx": self.elf.nx,
            "pie": self.elf.pie,
            "relro": self.elf.relro}

        return properties

    def detect_input_type(self):
        all_functions = self.elf.symbols
        read_functions = ["fgets", "gets", "scanf", "read", "__isoc99_scanf"]
        if any(func in read_functions for func in all_functions):
            return "STDIN"
        return "ARGS"

    def get_base_address(self):
        return self.elf.address

    def adjust_binary_base(self, leak_addr):
        self.elf.address = leak_addr - self.libc.sym['puts']
        log.success(f'binary base: {hex(self.elf.address)}')

    def adjust_libc_base(self, puts_addr):
        self.libc.address = puts_addr - self.libc.sym['puts']
        log.success(f'libc base: {hex(self.libc.address)}')

    def find_function(self, function, search_libc=False):
        elf = self.elf if search_libc is False else self.libc
        if function in elf.plt:
            return elf.plt[function]
        if function in elf.symbols:
            return elf.symbols[function]
        return None

    def find_exec_function(self, search_libc=False):
        exec_functions = ["excve", "system"]
        for f in exec_functions:
            find_func = self.find_function(f, search_libc)
            if find_func is not None:
                return find_func
        return None

    def find_bytes(self, string, search_libc=False):
        elf = self.elf if search_libc is False else self.libc
        occurrences = list(elf.search(string))
        if len(occurrences) > 0:
            return occurrences[0]
        return None

    def find_binsh(self, search_libc=False):
        binsh = [b"/bin/sh\x00", b"/bin/bash\x00"]
        for s in binsh:
            find_s = self.find_bytes(s, search_libc)
            if find_s is not None:
                return find_s
        return None

    def get_rwx_segment(self):
        if len(self.elf.rwx_segments) > 0:
            return self.elf.rwx_segments[0]
        return None





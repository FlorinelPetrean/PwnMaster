import json
from pwn import *
import r2pipe
from subprocess import Popen, PIPE, check_output
from pylibcdb.LibcDB import LibcDB

context.arch = 'amd64'


class Binary:
    def __init__(self,
                 binary_path, ip=None, port=None):
        self.bin_path = binary_path
        context.binary = self.bin_path
        self.elf = ELF(self.bin_path)
        self.protection = self.init_protection()
        self.props = self.init_properties()
        self.libc = self.init_libc()
        self.arch = self.elf.arch
        self.remote = None if ip is None or port is None else [ip, port]

    def create_process(self, type="local"):
        pty = process.PTY
        if type == "local":
            return self.elf.process(stdin=pty, stdout=pty)
        elif type == "remote" and self.remote is not None:
            return remote(self.remote[0], self.remote[1])
        elif type == "debug":
            return gdb.debug(self.bin_path, '''break _start''')
        return self.elf.process(stdin=pty, stdout=pty)

    def init_libc(self):
        libc = None
        try:
            libc = self.elf.libc
        except ValueError:
            pass
        return libc

    def init_protection(self):
        protections = {
            "aslr": self.elf.aslr,
            "canary": self.elf.canary,
            "nx": self.elf.nx,
            "pie": self.elf.pie,
            "relro": self.elf.relro}

        return protections

    def init_properties(self):
        properties = {
            "adjusted_binary_base": not self.elf.pie,
            "adjusted_libc_base": False,
            "use_leak_addr_chain": "puts" in self.elf.plt
        }
        return properties

    # def detect_input_type(self):
    #     all_functions = self.elf.symbols
    #     read_functions = ["fgets", "gets", "scanf", "read", "__isoc99_scanf"]
    #     if any(func in read_functions for func in all_functions):
    #         return "STDIN"
    #     return "ARGS"

    def get_base_address(self):
        return self.elf.address

    def set_binary_base(self, base_addr):
        self.elf.address = base_addr
        self.props["adjusted_binary_base"] = True
        log.success(f'binary base: {hex(self.elf.address)}')

    def adjust_libc_base(self, leak_addr, function):
        if self.libc is None:
            libcdb = LibcDB("/libc-database")
            libc_name = libcdb.find_by_address(leak_addr, symbol=function)
            libc_path = libcdb.download_by_name(libc_name)
            self.libc = ELF(libc_path)
        self.libc.address = leak_addr - self.libc.sym[function]
        self.props["adjusted_libc_base"] = True
        log.success(f'Adjusted libc base to: {hex(self.libc.address)}')

    def set_libc_base(self, libc_base):
        if self.libc is not None:
            self.libc.address = libc_base
            self.props["adjusted_libc_base"] = True
            log.success(f'Set libc base to: {hex(self.libc.address)}')

    def find_function(self, function, search_libc=False):
        elf = self.elf if search_libc is False else self.libc
        if function in elf.plt and search_libc is False:
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

    def find_one_gadget(self):
        one_gadgets = [self.libc.address + int(i) for i in check_output(['one_gadget', '--raw', self.libc.path]).decode().split(' ')]
        log.info("one_gadgets: {}".format([hex(gadget) for gadget in one_gadgets]))
        return one_gadgets

    def get_rwx_segment(self):
        if len(self.elf.rwx_segments) > 0:
            return self.elf.rwx_segments[0]
        return None





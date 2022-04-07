from leak_detector import detect_leak
from fmt_detector import detect_format_string
from bof_detector import detect_overflow
from pwn import *
from rop_exploiter import RopExploiter
from fmt_exploiter import FmtExploiter


class PwnMaster:
    def __init__(self, binary):
        self.binary = binary
        self.vulns = {}
        self.detect_vulns()

    def detect_vulns(self):
        fmt_vuln = detect_format_string(self.binary)
        if "type" in fmt_vuln:
            self.vulns["fmt"] = fmt_vuln
        bof_vuln = detect_overflow(self.binary)
        if "type" in bof_vuln:
            self.vulns["bof"] = bof_vuln

    def compatible_vulns(self, bof, fmt):
        if bof is True and fmt is True:
            index_bof = 0
            pass

        return False

    def choose_strategy(self):
        protection = self.binary.protection
        pie = protection["pie"]
        canary = protection["canary"]
        relro = protection["relro"]
        bof = "bof" in self.vulns
        fmt = "fmt" in self.vulns
        both = self.compatible_vulns(bof, fmt)

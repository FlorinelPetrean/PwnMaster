from pwn import *
from pwn_master.vuln_detector.fmt_detector import FmtDetector
from pwn_master.vuln_detector.bof_detector import BofDetector
import angr


class FmtBofDetector:
    def __init__(self, binary):
        self.binary = binary
        context.binary = binary.elf

    def detect_vuln(self):
        p = angr.Project(self.binary.bin_path, load_options={"auto_load_libs": False})
        fmt_detector = FmtDetector(self.binary)
        fmt_details, state = fmt_detector.detect_format_string(p, intermediate=True)

        bof_detector = BofDetector(self.binary)
        bof_details, _ = bof_detector.detect_overflow(p, state)
        bof_details["type"] = "fmt&bof"
        return bof_details

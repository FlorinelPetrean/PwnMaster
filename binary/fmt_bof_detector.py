from pwn import *
from binary.fmt_detector import FmtDetector
from binary.bof_detector import BofDetector
import angr

from func_model.print_format import PrintFormat


class FmtBofDetector:
    def __init__(self, binary):
        self.binary = binary
        context.binary = binary.elf

    def explore_binary(self):
        p = angr.Project(self.binary.bin_path, load_options={"auto_load_libs": False})
        fmt_detector = FmtDetector(self.binary)
        fmt_details, state = fmt_detector.detect_format_string(p, intermediate=True)

        bof_detector = BofDetector(self.binary)
        bof_details, _ = bof_detector.detect_overflow(p, state)
        print(bof_details)

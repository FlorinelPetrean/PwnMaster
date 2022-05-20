from pwn import *
from binary.fmt_detector import FmtDetector
from binary.bof_detector import BofDetector
import angr


class FmtFmtDetector:
    def __init__(self, binary):
        self.binary = binary
        context.binary = binary.elf

    def detect_vuln(self):
        p = angr.Project(self.binary.bin_path, load_options={"auto_load_libs": False})
        fmt_detector = FmtDetector(self.binary)
        fmt_details, state = fmt_detector.detect_format_string(p, intermediate=True)

        fmt_details, _ = fmt_detector.detect_format_string(p, state=state)
        fmt_details["type"] = "fmt&fmt"
        return fmt_details

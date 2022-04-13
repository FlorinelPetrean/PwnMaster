# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

# Press the green button in the gutter to run the script.


from binary.binary import Binary
from binary.fmt_bof_detector import FmtBofDetector
from binary.fmt_bof_exploiter import FmtBofExploiter
from binary.both_detector import BothDetector
from pwn import *
from binary.pwn_master import PwnMaster
import argparse
import sys

if __name__ == '__main__':
    binary_path = sys.argv[1]
    binary = Binary(binary_path)
    fmt_bof_detector = FmtBofDetector(binary)
    details = fmt_bof_detector.detect_vuln()
    fmt_bof_exploiter = FmtBofExploiter(binary, details)
    fmt_bof_exploiter.two_stage_exploit()
    # pwn_master = PwnMaster(binary)
    # pwn_master.choose_strategy()






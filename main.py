# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

# Press the green button in the gutter to run the script.


from binary.binary import Binary
from binary.fmt_bof_detector import FmtBofDetector
from binary.fmt_bof_exploiter import FmtBofExploiter
from binary.fmt_detector import FmtDetector
from binary.fmt_exploiter import FmtExploiter
from pwn import *
from binary.pwn_master import PwnMaster
import argparse
import sys

if __name__ == '__main__':
    option = sys.argv[2]
    binary_path = sys.argv[1]

    ip = None
    port = None
    if option == "LOCAL":
        pass
    elif option == "REMOTE":
        ip = sys.argv[3]
        port = int(sys.argv[4])

    binary = Binary(binary_path, ip, port)

    pwn_master = PwnMaster(binary)
    pwn_master.choose_strategy()

    # fmt_detector = FmtDetector(binary)
    # details, _ = fmt_detector.detect_format_string()
    # fmt_exploiter = FmtExploiter(binary, details)
    # fmt_exploiter.find_pie_offset()












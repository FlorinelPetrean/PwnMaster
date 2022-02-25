# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from binary import *

# Press the green button in the gutter to run the script.
from binary.binary import Binary
from binary.exploiter import Exploiter
from binary.vuln_detector import *
from pwn import *
import argparse
import sys


if __name__ == '__main__':
    binary_path = sys.argv[1]
    binary = Binary(binary_path)
    vuln_details = detect_overflow(binary)
    print(vuln_details)
    exploiter = Exploiter(binary, vuln_details)
    exploiter.exploit()



# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

# Press the green button in the gutter to run the script.
from binary.binary import Binary
from binary.rop_exploiter import RopExploiter
from binary.sc_exploiter import ShellcodeExploiter
from binary.vuln_detector import *
from pwn import *
import argparse
import sys

if __name__ == '__main__':
    binary_path = sys.argv[1]
    binary = Binary(binary_path)
    vuln_details = detect_overflow(binary)
    if not binary.protection['nx']:
        exploiter = ShellcodeExploiter(binary, vuln_details)
        exploiter.exploit()
    else:
        exploiter = RopExploiter(binary, vuln_details)
        exploiter.exploit()

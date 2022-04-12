# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

# Press the green button in the gutter to run the script.


from binary.binary import Binary
from binary.pwn_master import PwnMaster
from binary.fmt_bof_detector import FmtBofDetector
from pwn import *
import argparse
import sys

if __name__ == '__main__':
    binary_path = sys.argv[1]
    binary = Binary(binary_path)
    pwn_master = PwnMaster(binary)
    pwn_master.choose_strategy()





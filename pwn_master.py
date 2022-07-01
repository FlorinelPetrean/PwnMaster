# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

# Press the green button in the gutter to run the script.


from pwn_master.binary_analyzer.binary import Binary
from pwn_master.vuln_filter.vuln_filter import VulnFilter
import sys
from pwn import *

context.log_level = 'ERROR'

if __name__ == '__main__':
    option = sys.argv[2]
    binary_path = sys.argv[1]
    ip = None
    port = None
    if option == "local":
        pass
    elif option == "remote":
        ip = sys.argv[3]
        port = int(sys.argv[4])

    binary = Binary(binary_path, ip, port)

    pwn_master = VulnFilter(binary)
    pwn_master.choose_strategy()













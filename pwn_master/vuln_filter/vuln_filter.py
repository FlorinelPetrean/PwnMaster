from pwn_master.vuln_detector.fmt_bof_detector import FmtBofDetector
from pwn_master.exploit_generator.fmt_bof_exploiter import FmtBofExploiter
from pwn_master.vuln_detector.fmt_detector import FmtDetector
from pwn_master.exploit_generator.fmt_exploiter import FmtExploiter
from pwn_master.exploit_generator.rop_exploiter import RopExploiter
from pwn_master.vuln_detector.bof_detector import BofDetector


class VulnFilter:
    def __init__(self, binary):
        self.binary = binary
        self.vulns = {}
        self.detect_vulns()

    def detect_vulns(self):
        pie = self.binary.protection["pie"]
        canary = self.binary.protection["canary"]
        if not (pie or canary):
            fmt_detector = FmtDetector(self.binary)
            fmt_vuln, _ = fmt_detector.detect_format_string()
            if "type" in fmt_vuln:
                self.vulns["fmt"] = fmt_vuln

            bof_detector = BofDetector(self.binary)
            bof_vuln, _ = bof_detector.detect_overflow()
            if "type" in bof_vuln:
                self.vulns["bof"] = bof_vuln
        else:
            fmt_bof_detector = FmtBofDetector(self.binary)
            fmt_bof_vuln = fmt_bof_detector.detect_vuln()
            if "type" in fmt_bof_vuln:
                self.vulns["fmt&bof"] = fmt_bof_vuln

    def choose_strategy(self):
        protection = self.binary.protection
        pie = protection["pie"]
        canary = protection["canary"]
        relro = protection["relro"]
        bof = "bof" in self.vulns
        fmt = "fmt" in self.vulns
        fmt_and_bof = "fmt&bof" in self.vulns

        protection_string = ""
        protection_string += "1" if pie is True else "0"
        protection_string += "1" if canary is True else "0"
        protection_string += "1" if relro is True else "0"

        found_exploit = False

        if protection_string == "000":
            if bof and found_exploit is False:
                bof_exploiter = RopExploiter(self.binary, self.vulns["bof"])
                bof_exploiter.ret2libc_exploit()
                found_exploit = True
            if fmt and found_exploit is False:
                fmt_exploiter = FmtExploiter(self.binary, self.vulns["fmt"])
                fmt_exploiter.got_overwrite_loop()
                found_exploit = True

        elif protection_string == "001":
            if bof and found_exploit is False:
                bof_exploiter = RopExploiter(self.binary, self.vulns["bof"])
                bof_exploiter.ret2libc_exploit()
                found_exploit = True
        elif protection_string == "010":
            # TODO
            pass
        elif protection_string == "011":
            pass
        elif protection_string == "100":
            pass
        elif protection_string == "101":
            pass
        elif protection_string == "110":
            pass
        elif protection_string == "111":
            pass
        if not found_exploit and fmt_and_bof:
            fmt_bof_exploiter = FmtBofExploiter(self.binary, self.vulns["fmt&bof"])
            fmt_bof_exploiter.two_stage_exploit()

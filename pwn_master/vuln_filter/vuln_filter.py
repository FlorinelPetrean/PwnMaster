from pwn_master.vuln_detector.fmt_bof_detector import FmtBofDetector
from pwn_master.exploit_generator.fmt_bof_exploiter import FmtBofExploiter
from pwn_master.vuln_detector.fmt_fmt_detector import FmtFmtDetector
from pwn_master.exploit_generator.fmt_fmt_exploiter import FmtFmtExploiter
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
        relro = self.binary.protection["relro"]
        if pie is False:
            if relro is False:
                fmt_detector = FmtDetector(self.binary)
                fmt_vuln, _ = fmt_detector.detect_format_string()
                if "type" in fmt_vuln:
                    self.vulns["fmt"] = fmt_vuln
            if canary is False:
                bof_detector = BofDetector(self.binary)
                bof_vuln, _ = bof_detector.detect_overflow()
                if "type" in bof_vuln:
                    self.vulns["bof"] = bof_vuln
        else:
            fmt_bof_detector = FmtBofDetector(self.binary)
            fmt_bof_vuln = fmt_bof_detector.detect_vuln()
            if "type" in fmt_bof_vuln:
                self.vulns["fmt&bof"] = fmt_bof_vuln
            else:
                fmt_fmt_detector = FmtFmtDetector(self.binary)
                fmt_fmt_vuln = fmt_fmt_detector.detect_vuln()
                if "type" in fmt_fmt_vuln:
                    self.vulns["fmt&fmt"] = fmt_bof_vuln

    def choose_strategy(self):
        protection = self.binary.protection
        pie = protection["pie"]
        canary = protection["canary"]
        relro = protection["relro"]
        bof = "bof" in self.vulns
        fmt = "fmt" in self.vulns
        fmt_and_bof = "fmt&bof" in self.vulns
        fmt_and_fmt = "fmt&fmt" in self.vulns

        protection_string = ""
        protection_string += "1" if pie is True else "0"
        protection_string += "1" if canary is True else "0"
        protection_string += "1" if relro is True else "0"

        found_exploit = False

        if protection_string == "000":
            if fmt and found_exploit is False:
                fmt_exploiter = FmtExploiter(self.binary, self.vulns["fmt"])
                fmt_exploiter.got_overwrite_loop()
                found_exploit = True
            if bof and found_exploit is False:
                bof_exploiter = RopExploiter(self.binary, self.vulns["bof"])
                bof_exploiter.ret2libc_exploit()
                found_exploit = True

        elif protection_string == "001":
            if bof and found_exploit is False:
                bof_exploiter = RopExploiter(self.binary, self.vulns["bof"])
                bof_exploiter.ret2libc_exploit()
                found_exploit = True

        elif protection_string == "010":
            if fmt and found_exploit is False:
                fmt_exploiter = FmtExploiter(self.binary, self.vulns["fmt"])
                fmt_exploiter.got_overwrite_loop()
                found_exploit = True

        elif protection_string == "011":
            if fmt_and_bof and found_exploit is False:
                fmt_bof_exploiter = FmtBofExploiter(self.binary, self.vulns["fmt&bof"])
                fmt_bof_exploiter.two_stage_exploit()
                found_exploit = True

        elif protection_string == "100":
            if fmt_and_bof and found_exploit is False:
                fmt_bof_exploiter = FmtBofExploiter(self.binary, self.vulns["fmt&bof"])
                fmt_bof_exploiter.two_stage_exploit()
                found_exploit = True
            if fmt_and_fmt and found_exploit is False:
                fmt_fmt_exploiter = FmtFmtExploiter(self.binary, self.vulns["fmt&fmt"])
                fmt_fmt_exploiter.got_overwrite_attack()
                found_exploit = True

        elif protection_string == "101":
            if fmt_and_bof and found_exploit is False:
                fmt_bof_exploiter = FmtBofExploiter(self.binary, self.vulns["fmt&bof"])
                fmt_bof_exploiter.two_stage_exploit()
                found_exploit = True

        elif protection_string == "110":
            if fmt_and_bof and found_exploit is False:
                fmt_bof_exploiter = FmtBofExploiter(self.binary, self.vulns["fmt&bof"])
                fmt_bof_exploiter.two_stage_exploit()
                found_exploit = True
            if fmt_and_fmt and found_exploit is False:
                fmt_fmt_exploiter = FmtFmtExploiter(self.binary, self.vulns["fmt&fmt"])
                fmt_fmt_exploiter.got_overwrite_attack()
                found_exploit = True

        elif protection_string == "111":
            if fmt_and_bof and found_exploit is False:
                fmt_bof_exploiter = FmtBofExploiter(self.binary, self.vulns["fmt&bof"])
                fmt_bof_exploiter.two_stage_exploit()
                found_exploit = True

        if found_exploit is False:
            print("No exploits found!")

from pwn import *
from timeout_decorator import timeout_decorator

from pwn_master.vuln_detector.fmt_detector import FmtDetector
import angr


class FmtFmtDetector(FmtDetector):
    def __init__(self, binary):
        super().__init__(binary)
        self.binary = binary
        context.binary = binary.elf

    def fmt_filter(self, simgr):
        for s in simgr.unconstrained:
            if "type" in s.globals and s.globals["type"] == "fmt":
                simgr.stashes["pruned"].append(s)
                simgr.stashes["unconstrained"].remove(s)
                return True
        return False

    def explore_binary(self, p, state, intermediate=False):
        simgr = p.factory.simgr(state, save_unconstrained=True)
        # simgr.use_technique(angr.exploration_techniques.DFS())

        vuln_details = {}
        end_state = None
        # Lame way to do a timeout
        try:

            @timeout_decorator.timeout(120)
            def explore_binary(simgr: angr.sim_manager):
                simgr.run(
                    until=self.fmt_filter
                )

            explore_binary(simgr)
            print(simgr.stashes)
            # print("0: ", self.get_stdin_input(simgr.pruned[0]))
            # print("1: ", self.get_stdin_input(simgr.pruned[2]))
            if "pruned" in simgr.stashes and len(simgr.pruned):
                exploit_state: angr.SimState = simgr.pruned[len(simgr.pruned) - 1]
                # simgr = p.factory.simgr(exploit_state, save_unconstrained=True)
                # simgr.run(drop=simgr.stashes["unconstrained"])
                # print(simgr.stashes)
                # if "deadended" in simgr.stashes and len(simgr.deadended):
                #     end_state = simgr.deadended[0]
                # if "pruned" in simgr.stashes and len(simgr.pruned):
                #     end_state = simgr.pruned[0]
                end_state = exploit_state

                self.get_vuln_details(vuln_details, end_state)

        except (KeyboardInterrupt, timeout_decorator.TimeoutError) as e:
            log.info("[~] Keyboard Interrupt")
        if end_state is not None:
            vuln_details["input"] = self.get_stdin_input(end_state)
        return vuln_details, end_state

    def detect_vuln(self):
        return self.detect_format_string()

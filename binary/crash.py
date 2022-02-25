from utils.input_type import *
from angr import *

class Crash:
    def __init__(self, binary, crash_input, input_type=InputType.STDIN):
        self.binary = binary
        self.crash_input = crash_input
        self.input_type = input_type

    def apply_input(self, p):
        argv = [self.binary.bin_path]
        if self.input_type == "STDIN":
            state = p.factory.full_init_state(args=argv, stdin=self.crash_input)
            state.globals["user_input"] = self.crash_input
            return state
        elif self.input_type == "ARGS":
            argv.append(self.crash_input)
            state = p.factory.full_init_state(args=argv)
            state.globals["user_input"] = self.crash_input
            return state

    def trace(self):
        p = Project(self.binary.bin_path, load_options={"auto_load_libs": False})
        state = self.apply_input(p)
        simgr = p.factory.simgr(state, save_unconstrained=True)

        tracer = exploration_techniques.Tracer(trace=self.crash_input)
        simgr.use_technique(tracer)
        simgr.explore()






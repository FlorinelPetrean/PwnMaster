import angr


class GetsHook(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self, dst):
        self.state.globals["ctrl_stack_space"] = 1024
        gets_func = angr.SIM_PROCEDURES["libc"]["gets"]
        return self.inline_call(gets_func, dst).ret_expr

import angr


class ExitHook(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self, exit_code):
        self.state.globals["exit"] = True
        # exit_func = angr.SIM_PROCEDURES["libc"]["exit"]
        # return self.inline_call(exit_func, exit_code).ret_expr
        return exit_code

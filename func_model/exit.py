import angr


class ExitHook(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self, return_value):
        self.state.globals["exit"] = True
        return return_value

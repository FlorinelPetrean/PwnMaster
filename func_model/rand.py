import angr


class RandHook(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self):
        return 6  # Fair dice roll

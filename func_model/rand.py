import angr


class HookRandom(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self):
        return 6  # Fair dice roll

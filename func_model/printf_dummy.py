import angr


class PrintfDummy(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self, fmt):
        print("Dummy printf")
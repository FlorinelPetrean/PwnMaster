import angr


class ScanfHook(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self, fmt):
        scanf = angr.SIM_PROCEDURES["libc"]["scanf"]
        ret = self.inline_call(scanf, fmt).ret_expr
        print(b"\x00")
        return ret



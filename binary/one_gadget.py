from subprocess import Popen, PIPE


class OneGadget:
    def __init__(self, offset, constraints):
        self.offset = offset
        self.constraints = constraints

    def get_one_gadgets(self, binary):
        one_gadget = Popen("one_gadget", binary.libc.path, stdout=PIPE)
        lines = one_gadget.stdout.readlines()

    def _parse_lines(self, lines):
        one_gadgets = []
        offset = 0
        constraints = []
        for line in lines:
            if line.strip() == "":
                one_gadget = OneGadget(offset, constraints)
                one_gadgets.append(one_gadget)

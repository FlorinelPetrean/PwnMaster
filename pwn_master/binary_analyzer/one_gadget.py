from subprocess import Popen, PIPE, check_output


class OneGadget:
    def __init__(self, filename):
        self.filename = filename
        self.offset = 0
        self.constraints = []

    def find_one_gadget(self):
        return [int(i) for i in check_output(['one_gadget', '--raw', self.filename]).decode().split(' ')]

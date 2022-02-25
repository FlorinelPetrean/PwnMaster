

class Fuzzer:
    def __init__(self,
                 binary,
                 working_dir="./test-binary"):
        self.binary_path = binary
        self.working_dir = working_dir
        self.in_dir = working_dir + "/in"
        self.out_dir = working_dir + "/out"
        self.afl_fuzzer_cmd = "afl-fuzz"

    pass

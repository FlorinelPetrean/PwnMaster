from abc import ABC

import angr


class IntegerHook(angr.sim_type.SimTypeInt, ABC):


    def run(self):
        pass
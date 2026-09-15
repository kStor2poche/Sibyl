# This file is part of Sibyl.
# Copyright 2014 Camille MOUGEY <camille.mougey@cea.fr>
#
# Sibyl is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sibyl is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sibyl. If not, see <http://www.gnu.org/licenses/>.


class ABI:
    "Parent class, stand for an ABI"

    # Associated architectures
    arch = []

    def __init__(self, jitter, lifter_model_call):
        self.jitter = jitter
        self.lifter_model_call = lifter_model_call

    def reset(self):
        "Reset the current ABI"

    def add_arg(self, number, element):
        """Add a function argument
        @number: argument number (start 0)
        @element: argument
        """
        raise NotImplementedError("Abstract method")

    def prepare_call(self, ret_addr):
        """Prepare the call to a function
        @ret_addr: return address
        """
        raise NotImplementedError("Abstract method")

    def get_result(self) -> int:
        """Return the function result value, as int"""
        raise NotImplementedError("Abstract method")


class ABIRegsStack(ABI):

    regs_mapping = None # Register mapping (list of str)
    args = None         # order => element

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = {}

    def add_arg(self, number: int, element: int):
        if isinstance(element, int):
            self.args[number] = element
        else:
            raise NotImplementedError()

    def vm_push(self, element):
        raise NotImplementedError("Abstract method")

    def set_ret(self, element):
        raise NotImplementedError("Abstract method")

    def prepare_call(self, ret_addr):
        # Get args
        numbers = sorted(self.args.keys())

        for i, key in reversed(list(enumerate(numbers))):
            element = self.args[key]

            if i < len(self.regs_mapping):
                # Regs argument
                setattr(self.jitter.cpu, self.regs_mapping[i], element)
            else:
                # Stack argument
                self.vm_push(element)

        self.set_ret(ret_addr)

    def reset(self):
        self.args = {}

    def get_result(self) -> int:
        return getattr(self.jitter.cpu, self.lifter_model_call.ret_reg.name)

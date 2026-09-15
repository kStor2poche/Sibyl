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


import struct

from miasm.jitter.csts import PAGE_READ, PAGE_WRITE

from sibyl.test.ctype_data import (
    _nl_C_LC_CTYPE_class,
    _nl_C_LC_CTYPE_tolower,
    _nl_C_LC_CTYPE_toupper,
    _nl_C_name,
)
from sibyl.test.test import Test, TestSetTest


class TestAbs(Test):

    value = 42

    # Test1
    def init1(self):
        self._add_arg(0, self.value + 1)

    def check1(self):
        result = self._get_result()
        return result == (self.value + 1)

    # Test2
    def init2(self):
        self._add_arg(0, self._as_int(-1 * self.value))

    def check2(self):
        result = self._get_result()
        return result == self.value

    # Properties
    func = "abs"
    tests = TestSetTest(init1, check1) & TestSetTest(init2, check2)


class TestA64l(Test):

    my_string = "v/"
    value = 123

    # Test
    def init(self):
        self.my_addr = self._alloc_string(self.my_string)
        self._add_arg(0, self.my_addr)

    def check(self):
        result = self._get_result()
        return all([result == self.value,
                    self._ensure_mem_str(self.my_addr, self.my_string)])

    # Properties
    func = "a64l"
    tests = TestSetTest(init, check)


class TestAtoi(Test):

    my_string = "44"
    my_string2 = "127.0.0.1"

    gs = 67
    gs_map_addr = 0x98765432 # hardcoded addresses are the besError: attempt to add page (0x98764432 0x98765432) overlapping page (0x98764432 0x98765432)
    gs_map_size = 0x1000 # idk maybe it's good enough

    def init_libc_locale_struct(self):
        # pack data into memory according to our machine
        ptr_sz = self.abi.lifter_model_call.sizeof_pointer() // 8
        _nl_C_LC_CTYPE_tolower_packed = struct.pack(('<' if self.jitter.vm.is_little_endian() else '>') + "I" * len(_nl_C_LC_CTYPE_tolower), *_nl_C_LC_CTYPE_tolower) # TODO: take ptr_sz into account
        _nl_C_LC_CTYPE_toupper_packed = struct.pack(('<' if self.jitter.vm.is_little_endian() else '>') + "I" * len(_nl_C_LC_CTYPE_toupper), *_nl_C_LC_CTYPE_toupper) # TODO: idem
        _nl_C_LC_CTYPE_class_packed = b''.join([bytes(reversed(_nl_C_LC_CTYPE_class[i:i+ptr_sz])) for i in range(0, len(_nl_C_LC_CTYPE_class), ptr_sz)]) if self.jitter.vm.is_little_endian() else _nl_C_LC_CTYPE_class

        # initialize TLS around gs segment
        self.jitter.vm.add_memory_page(self.gs_map_addr - self.gs_map_size, PAGE_READ | PAGE_WRITE, b'\x00'*self.gs_map_size) # cf. how TLS works on linux: user variables are placed before the segment base, while the TCB is right on this base
        self.jitter.cpu.GS = self.gs
        self.jitter.cpu.set_segm_base(self.gs, self.gs_map_addr)

        tolower_struct_ptr = self._alloc_bytes(_nl_C_LC_CTYPE_tolower_packed, True, comment="tolower")
        toupper_struct_ptr = self._alloc_bytes(_nl_C_LC_CTYPE_toupper_packed, True, comment="toupper")
        class_struct_ptr = self._alloc_bytes(_nl_C_LC_CTYPE_class_packed, True, comment="ctypes_class")
        _nl_C_name_ptr = self._alloc_bytes(_nl_C_name, True, comment="C locale name")
        to_bytes_args = { "length": ptr_sz, "byteorder": "big" } # because we pack later

        # ptr to this struct is at gs:0xffffffdc
        _nl_globale_locale = b"".join([
            b"\x00" * ptr_sz * 13, #.__locales
            (class_struct_ptr + 128).to_bytes(**to_bytes_args),
            (tolower_struct_ptr + 128).to_bytes(**to_bytes_args),
            (toupper_struct_ptr + 128).to_bytes(**to_bytes_args),
            (_nl_C_name_ptr.to_bytes(**to_bytes_args)) * 13, #.__names (we put some data but it's useless)
        ])
        _nl_globale_locale_packed = b''.join([bytes(reversed(_nl_globale_locale[i:i+ptr_sz])) for i in range(0, len(_nl_globale_locale), ptr_sz)]) if self.jitter.vm.is_little_endian() else _nl_globale_locale
        to_bytes_args = { "length": ptr_sz, "byteorder": "little" if self.jitter.vm.is_little_endian() else "big" }
        _nl_globale_locale_ptr = self._alloc_bytes(_nl_globale_locale_packed, True)
        self.jitter.vm.set_mem(self.gs_map_addr - 0x24, _nl_globale_locale_ptr.to_bytes(**to_bytes_args))


    # Test
    def my_init(self, string):
        self.init_libc_locale_struct()
        self.my_addr = self._alloc_string(string)
        self._add_arg(0, self.my_addr)

    def my_check(self, string: str):
        result = self._get_result()
        return all([result == int(string.split(".")[0]),
                    self._ensure_mem_str(self.my_addr, string)])

    # Test1
    def init1(self):
        return self.my_init(self.my_string)

    def check1(self):
        return self.my_check(self.my_string)

    # Test1
    def init2(self):
        return self.my_init(self.my_string2)

    def check2(self):
        return self.my_check(self.my_string2)


    # Properties
    func = "atoi"
    tests = TestSetTest(init1, check1) & TestSetTest(init2, check2)


TESTS = [TestAbs, TestA64l, TestAtoi]

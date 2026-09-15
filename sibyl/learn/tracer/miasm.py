'''
This module gives a tracer that uses miasm to run the program
'''

from miasm.analysis.machine import Machine
from miasm.arch.mips32.jit import LocationDB
from miasm.jitter.csts import PAGE_READ
from miasm.jitter.emulatedsymbexec import EmulatedSymbExec
from miasm.jitter.jitcore_python import JitCore_Python
from miasm.jitter.loader.elf import vm_load_elf

from sibyl.learn.trace import Snapshot, Trace
from sibyl.learn.tracer.tracer import Tracer


class CustomEmulatedSymbExec(EmulatedSymbExec):
    '''New emulator that trap all memory read and write which is needed by the miasm tracer'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._read_callback = set()
        self._write_callback = set()

    def add_read_call(self, callback):
        '''Add a new callback used each time a read appended'''
        self._read_callback.add(callback)

    def remove_read_callback(self, callback):
        '''Remove a read callback'''
        self._read_callback.remove(callback)

    def add_write_call(self, callback):
        '''Add a new callback used each time a write appended'''
        self._write_callback.add(callback)

    def remove_write_callback(self, callback):
        '''Remove a write callback'''
        self._write_callback.remove(callback)

    def mem_read(self, expr_mem):
        '''Function call for each read. We overwrite it to intercept the read'''
        for callback in self._read_callback:
            callback(self, expr_mem)

        return super().mem_read(expr_mem)

    def mem_write(self, dest, data):
        '''Function call for each write. We overwrite it to intercept the write'''
        for callback in self._write_callback:
            callback(self, dest, data)

        super().mem_write(dest, data)


class TracerMiasm(Tracer):

    '''Tracer that uses miasm'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.isTracing = False
        self.trace = None

    def read_callback(self, symb_exec, expr_mem):
        '''Read callback that add the read event to the snapshot'''
        addr = int(expr_mem.ptr)
        size = expr_mem.size // 8
        value = int.from_bytes(symb_exec.vm.get_mem(addr, size), byteorder="little")

        self.current_snapshot.add_memory_read(addr, size, value)

    def write_callback(self, symb_exec, dest, data):
        '''Write callback that add the read event to the snapshot'''
        addr = int(dest.ptr)
        size = data.size // 8
        value = int(data.arg)

        self.current_snapshot.add_memory_write(addr, size, value)

    def exec_callback(self, jitter):
        '''Callback called before each bloc execution'''
        self.current_snapshot.add_executed_instruction(jitter.pc)
        return True

    def begin_func(self, jitter):
        '''
        Function called by miasm at the begin of every execution of the traced function
        '''
        self.old_ret_addr = jitter.pop_uint64_t()
        jitter.push_uint64_t(0x1337beef)

        self.isTracing = True

        self.current_snapshot = Snapshot(self.abicls, self.machine)

        # Add the breakpoint to watch every memory read and write
        jitter.jit.symbexec.add_read_call(self.read_callback)
        jitter.jit.symbexec.add_write_call(self.write_callback)

        # Called before the execution of each basic bloc
        jitter.exec_cb = self.exec_callback

        for reg_name in self.reg_list:
            self.current_snapshot.add_input_register(
                reg_name, getattr(jitter.cpu, reg_name))

        return True

    def end_func(self, jitter):
        '''
        Function called by miasm at the end of every execution of the traced function
        '''
        jitter.pc = self.old_ret_addr

        for reg_name in self.reg_list:
            self.current_snapshot.add_output_register(
                reg_name, getattr(jitter.cpu, reg_name))

        jitter.exec_cb = None

        # Remove memory breakpoints
        jitter.jit.symbexec.remove_read_callback(self.read_callback)
        jitter.jit.symbexec.remove_write_callback(self.write_callback)

        self.trace.append(self.current_snapshot)

        self.isTracing = False

        return True

    def end_do_trace(self, jitter):
        '''
        Function called by miasm at the end of the program's execution
        '''
        jitter.run = False
        return False

    def do_trace(self):
        '''Run miasm and construct the trace'''

        self.trace = Trace()

        # Retrieve miasm tools
        machine = Machine(self.machine)
        loc_db = LocationDB()
        assert(machine.jitter is not None)
        jitter = machine.jitter(loc_db, "python")

        assert(isinstance(jitter.jit, JitCore_Python))
        # Set the jitter to use our custom emulator
        jitter.jit.symbexec = CustomEmulatedSymbExec(
            jitter.cpu, jitter.vm, jitter.jit.lifter, {})
        jitter.jit.symbexec.enable_emulated_simplifications()
        jitter.jit.symbexec.reset_regs()

        elf = vm_load_elf(jitter.vm, open(self.program, "rb").read())

        # Init segment
        jitter.lifter.do_stk_segm = True
        jitter.lifter.do_ds_segm = True
        jitter.lifter.do_str_segm = True
        jitter.lifter.do_all_segm = True

        FS_0_ADDR = 0x7ff70000
        jitter.cpu.FS = 0x4
        jitter.cpu.set_segm_base(jitter.cpu.FS, FS_0_ADDR)
        jitter.vm.add_memory_page(
            FS_0_ADDR + 0x28, PAGE_READ, b"\x42\x42\x42\x42\x42\x42\x42\x42")

        # Init stack and push main args
        jitter.init_stack()
        jitter.push_uint64_t(1)
        jitter.vm.add_memory_page(0x800000, PAGE_READ, self.program)
        jitter.push_uint64_t(0x800000)
        jitter.push_uint64_t(0xDEADDEAD)

        jitter.add_breakpoint(0xDEADDEAD, self.end_do_trace)
        jitter.add_breakpoint(0x1337beef, self.end_func)
        jitter.add_breakpoint(self.address, self.begin_func)

        # Run the execution
        if self.main_address is None:
            jitter.init_run(elf.Ehdr.entry)
        else:
            jitter.init_run(self.main_address)

        jitter.continue_run()
        assert jitter.run == False
        return self.trace

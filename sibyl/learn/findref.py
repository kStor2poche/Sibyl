import logging
import struct

import miasm.expression.expression as miasm_expr
from miasm.analysis.dse import ESETrackModif
from miasm.analysis.machine import Machine
from miasm.core.bin_stream import bin_stream_vm
from miasm.core.objc import CHandler
from miasm.ir.ir import AssignBlock
from miasm.jitter.csts import (
    EXCEPT_ACCESS_VIOL,
    EXCEPT_DIV_BY_ZERO,
    EXCEPT_PRIV_INSN,
    PAGE_READ,
)
from miasm.jitter.loader.elf import vm_load_elf

from sibyl.commons import objc_is_dereferenceable
from sibyl.config import config


class ExtractRef:
    '''
    Class used to concolic run a snapshot and extract references to input
    '''

    def __init__(self, testcreator, replayed_snapshot):
        '''
        @testcreator: TestCreator instance with associated information
        @replayed_snapshot: snapshot to be used
        '''
        self.loc_db = testcreator.loc_db
        self.isFuncFound = False
        self.filename = testcreator.program
        self.learned_addr = testcreator.address
        self.snapshot = replayed_snapshot
        self.replayexception = []
        self.abicls = testcreator.abicls
        self.machine = Machine(testcreator.machine)
        assert(self.machine.lifter_model_call is not None)
        self.lifter = self.machine.lifter_model_call(self.loc_db)
        self.ptr_size = self.lifter.sp.size // 8
        self.types = testcreator.types
        self.prototype = testcreator.prototype
        self.logger = testcreator.logger

    def use_snapshot(self, jitter):
        '''Initilize the VM with the snapshot informations'''
        for reg, value in self.snapshot.input_reg.items():
            setattr(jitter.cpu, reg, value)

        # Set values for input memory
        for addr, mem in self.snapshot.in_memory.items():
            assert mem.access != 0
            if not jitter.vm.is_mapped(addr, mem.size):
                jitter.vm.add_memory_page(addr, mem.access, mem.data)
            else:
                if jitter.vm.get_mem_access(addr) & 0b11 == mem.access & 0b11:
                    jitter.vm.set_mem(addr, mem.data)
                else:
                    # TODO memory page is already set but have not the
                    # same access right. However delete page does not
                    # exist
                    jitter.vm.set_mem(addr, mem.data)

    def compare_snapshot(self, jitter):
        '''Compare the expected result with the real one to determine if the function is recognize or not'''
        func_found = True

        for reg, value in self.snapshot.output_reg.items():
            if value != getattr(jitter.cpu, reg):
                self.replayexception += ["output register %s wrong : %i expected, %i found" % (reg, value, getattr(jitter.cpu, reg))]
                func_found = False

        for addr, mem in self.snapshot.out_memory.items():
            self.logger.debug("Check @%s, %s bytes: %r", hex(addr), hex(mem.size), mem.data[:0x10])
            jitter_mem = jitter.vm.get_mem(addr, mem.size)
            if mem.data != jitter_mem:
                self.replayexception += [f"output memory wrong at 0x{addr:x}: {mem.data!r} expected, {jitter_mem!r} found"]
                func_found = False

        return func_found

    def end_func(self, jitter):
        if jitter.vm.is_mapped(getattr(jitter.cpu, self.lifter.ret_reg.name), 1):
            self.replayexception += ["return value might be a pointer"]

        self.isFuncFound = self.compare_snapshot(jitter)

        jitter.run = False
        return False

    def is_pointer(self, expr):
        """Return True if expr may be a pointer"""
        target_types = self.c_handler.expr_to_types(expr)

        return any(objc_is_dereferenceable(target_type)
                   for target_type in target_types)

    def is_symbolic(self, expr):
        return expr.is_mem() and not expr.ptr.is_int()

    def get_arg_n(self, arg_number):
        """Return the Expression corresponding to the argument number
        @arg_number"""
        # TODO use abicls
        # TODO RSP doesn't seem to be set correctly in this context
        abi_order = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]
        size = 64
        sp = miasm_expr.ExprId("RSP", 64)
        if arg_number < len(abi_order):
            return miasm_expr.ExprId(abi_order[arg_number], size)
        else:
            destack = (arg_number - len(abi_order) + 1)
            return miasm_expr.ExprMem(sp + miasm_expr.ExprInt(destack * size // 8,
                                                        size),
                                   size)

    def callback(self, jitter):

        # Check previous state

        # When it is possible, consider only elements modified in the last run
        # -> speed up to avoid browsing the whole memory
        to_consider = self.symb.modified_expr

        for symbol in to_consider:
            # Do not consider PC
            if symbol == self.lifter.pc:
                continue

            # Read from ... @NN[... argX ...] ...
            symb_value = self.symb.eval_expr(symbol)
            to_replace = {}
            for expr in miasm_expr.ExprAssign(
                    symbol,
                    symb_value
            ).get_r(mem_read=True):
                if self.is_symbolic(expr):
                    if expr.is_mem():
                        # Consider each byte individually
                        # Case: @32[X] with only @8[X+1] to replace
                        addr_expr = expr.ptr
                        new_expr = []
                        consider = False
                        for offset in range(expr.size//8):
                            sub_expr = miasm_expr.ExprMem(self.symb.expr_simp(addr_expr + miasm_expr.ExprInt(offset, size=addr_expr.size)),
                                                       8)
                            if not self.is_pointer(sub_expr):
                                # Not a PTR, we have to replace with the real value
                                original_sub_expr = sub_expr.replace_expr(self.init_values)
                                new_expr.append(self.symb.eval_expr(original_sub_expr))
                                consider = True
                            else:
                                new_expr.append(sub_expr)

                        # Rebuild the corresponding expression
                        if consider:
                            assert len(new_expr) == expr.size // 8
                            to_replace[expr] = miasm_expr.ExprCompose(*new_expr)

                    if expr not in self.memories_write:
                        # Do not consider memory already written during the run
                        self.memories_read.add(expr)

            # Write to @NN[... argX ...]
            # Must be after Read, case: @[X] = f(@[X])
            if self.is_symbolic(symbol):
                self.memories_write.add(symbol)


            # Replace with real value for non-pointer symbols
            if to_replace:
                symb_value = self.symb.expr_simp(symb_value.replace_expr(to_replace))
                if isinstance(symbol, miasm_expr.ExprMem):
                    # Replace only in ptr (case to_replace: @[arg] = 8, expr:
                    # @[arg] = @[arg])
                    symbol = miasm_expr.ExprMem(self.symb.expr_simp(symbol.ptr.replace_expr(to_replace)),
                                      symbol.size)
                self.symb.apply_change(symbol, symb_value)

            # Check computed values against real ones
            # TODO idem memory
            if (isinstance(symbol, miasm_expr.ExprId) and
                isinstance(symb_value, miasm_expr.ExprInt)):
                if hasattr(jitter.cpu, symbol.name):
                    value = miasm_expr.ExprInt(getattr(jitter.cpu, symbol.name),
                                            symbol.size)
                    assert value == self.symb.symbols[symbol]

        cur_addr = jitter.pc
        self.logger.debug("Current address: %s", hex(cur_addr))
        if cur_addr == 0x1337BEEF or cur_addr == self.return_addr:
            # End reached
            if self.logger.isEnabledFor(logging.DEBUG):
                print("In:")
                for x in self.memories_read:
                    print(f"\t{x} ({self.c_handler.expr_to_c(x)})")
                print("Out:")
                for x in self.memories_write:
                    print(f"\t{x} ({self.c_handler.expr_to_c(x)})")
            return True

        # Update state
        self.symb.reset_modified()
        asm_block = self.mdis.dis_block(cur_addr)
        ircfg = self.symb_ir.new_ircfg()
        self.symb_ir.add_asmblock_to_ircfg(asm_block, ircfg)

        self.symb.run_at(ircfg, cur_addr)

        return True

    @staticmethod
    def memory_to_expr(addr):
        """Translate an address to its corresponding symbolic ID (8bits)
        @addr: int"""
        return miasm_expr.ExprId(f"MEM_0x{int(addr):x}", 8)

    def symbolize_memory(self, memory_range):
        """Register a range of memory addresses to symbolize
        @memory_range: object with support of __in__ operation (intervals, list,
        ...)
        """
        self.symb.dse_memory_range = memory_range
        self.symb.dse_memory_to_expr = self.memory_to_expr

    def prepare_symbexec(self, jitter, return_addr):
        # TODO: consider switching to miasm DSEEngine
        # Activate callback on each instr
        jitter.jit.set_options(max_exec_per_call=1, jit_maxline=1)
        #jitter.jit.log_mn = True
        #jitter.jit.log_regs = True
        jitter.exec_cb = self.callback

        # Disassembler
        assert(self.machine.dis_engine is not None)
        self.mdis = self.machine.dis_engine(bin_stream_vm(jitter.vm),
                                            lines_wd=1,
                                            loc_db=self.loc_db
                                            )

        # Symbexec engine
        ## Prepare the symbexec engine
        self.symb_ir = self.machine.lifter(self.mdis.loc_db)
        self.symb = ESETrackModif(jitter.cpu, jitter.vm, self.symb_ir, {})
        self.symb.enable_emulated_simplifications()

        ## Update registers value
        self.symb.reset_regs()
        self.symb.update_engine_from_cpu()

        ## Load the memory as ExprMem
        # self.symb.mem_read = None
        # self.symb.mem_write = None
        for base_addr, mem_segment in jitter.vm.get_all_memory().items():
            # Split into 8 bytes chunk for get_mem_overlapping
            for start in range(0, mem_segment["size"], 8):
                expr_mem = miasm_expr.ExprMem(miasm_expr.ExprInt(base_addr + start,
                                                           size=64),
                                           size=8*min(8, mem_segment["size"] - start))
                # Its initialisation, self.symb.apply_change is not necessary
                self.symb.symbols[expr_mem] = self.symb.mem_read(expr_mem)

        ## Save the initial state
        self.symbols_init = self.symb.symbols.copy()

        ## Save the returning address
        self.return_addr = return_addr

        # Inject argument
        self.init_values = {}
        # Expr -> set(ObjC types), for Expr -> C
        typed_exprs = {}
        # Expr name -> ObjC type, for C -> Expr
        typed_C_ids = {}
        self.args_symbols = []
        for i, param_name in enumerate(self.prototype.args_order):
            cur_arg_abi = self.get_arg_n(i)
            cur_arg = miasm_expr.ExprId("arg%d_%s" % (i, param_name),
                                     size=cur_arg_abi.size)
            if isinstance(cur_arg_abi, miasm_expr.ExprMem):
                to_symbolize = set()
                for byte_off in range(cur_arg_abi.size // 8):
                    byte_addr = int(self.symb.eval_expr(cur_arg_abi.ptr)) + byte_off
                    if not jitter.vm.is_mapped(byte_addr, 1):
                        to_symbolize.add(byte_addr)
                self.symbolize_memory(to_symbolize)
            self.init_values[cur_arg] = self.symb.eval_expr(cur_arg_abi)
            arg_type = self.prototype.args[param_name]
            if objc_is_dereferenceable(arg_type):
                # Convert the argument to symbol to track access based on it
                self.symb.apply_change(cur_arg_abi, cur_arg)
            typed_exprs[cur_arg] = {arg_type}
            typed_C_ids[cur_arg.name] = arg_type
            self.args_symbols.append(cur_arg)

        # Init Expr <-> C conversion
        # Strict access is deliberately not enforced (example: memcpy(struct))
        self.c_handler = CHandler(self.types, typed_exprs,
                                  enforce_strict_access=False)
        self.typed_C_ids = typed_C_ids

        # Init output structures
        self.memories_read = set()
        self.memories_write = set()

    def build_references(self):
        """At the end of the execution,
        - Fill memories accesses
        - Prepare output structures

        Enrich the snapshot with outputs
        """

        memory_in = {}
        memory_out = {}

        # Get the resulting symbolic value
        # TODO use abi
        output_value = self.symb.symbols[self.symb.lifter.arch.regs.RAX]

        # Fill memory *out* (written)
        for expr in self.memories_write:
            # Eval the expression with the *output* state
            value = self.symb.eval_expr(expr)
            memory_out[expr] = value

        # Fill memory *in* (read)
        saved_symbols = self.symb.symbols
        self.symb.symbols = self.symbols_init
        for expr in self.memories_read:
            # Eval the expression with the *input* state
            original_expr = expr.replace_expr(self.init_values)
            value = self.symb.eval_expr(original_expr)
            assert isinstance(value, miasm_expr.ExprInt)
            memory_in[expr] = value
        self.symb.symbols = saved_symbols

        if self.logger.isEnabledFor(logging.DEBUG):
            print("In:")
            print(memory_in)
            print("Out:")
            print(memory_out)
            print("Final value:")
            print(output_value)

        self.snapshot.memory_in = AssignBlock(memory_in)
        self.snapshot.memory_out = AssignBlock(memory_out)
        self.snapshot.output_value = output_value
        self.snapshot.c_handler = self.c_handler
        self.snapshot.typed_C_ids = self.typed_C_ids
        self.snapshot.arguments_symbols = self.args_symbols
        self.snapshot.init_values = self.init_values

    def run(self):
        '''Main function that is in charge of running the test and return the result:
        true if the snapshot has recognized the function, false else.'''

        # TODO inherit from Replay
        assert(self.machine.jitter is not None)
        jitter = self.machine.jitter(self.loc_db, config.miasm_engine)

        vm_load_elf(jitter.vm, open(self.filename, "rb").read())

        # Init segment
        jitter.lifter.do_stk_segm = True
        jitter.lifter.do_ds_segm = True
        jitter.lifter.do_str_segm = True
        jitter.lifter.do_all_segm = True

        FS_0_ADDR = 0x7ff70000
        jitter.cpu.FS = 0x4
        jitter.cpu.set_segm_base(jitter.cpu.FS, FS_0_ADDR)
        jitter.vm.add_memory_page(
            FS_0_ADDR + 0x28, PAGE_READ, b"\x42\x42\x42\x42\x42\x42\x42\x42", "Stack canary FS[0x28]")

        # Init the jitter with the snapshot
        self.use_snapshot(jitter)

        # Get the return address for our breakpoint
        return_addr = struct.unpack("P", jitter.vm.get_mem(jitter.cpu.RSP,
                                                           0x8))[0]
        jitter.add_breakpoint(return_addr, self.end_func)

        # Prepare the execution
        jitter.init_run(self.learned_addr)
        self.prepare_symbexec(jitter, return_addr)

        # Run the execution
        try:
            jitter.continue_run()
            assert jitter.run == False
        except AssertionError:
            if jitter.vm.get_exception() & EXCEPT_ACCESS_VIOL:
                self.replayexception += ["access violation"]
            elif jitter.vm.get_exception() & EXCEPT_DIV_BY_ZERO:
                self.replayexception += ["division by zero"]
            elif jitter.vm.get_exception() & EXCEPT_PRIV_INSN:
                self.replayexception += ["execution of private instruction"]
            elif jitter.vm.get_exception():
                self.replayexception += ["exception no %i" % (jitter.vm.get_exception())]
            else:
                raise
            self.isFuncFound = False

        # Rebuild references
        self.build_references()

        return self.isFuncFound

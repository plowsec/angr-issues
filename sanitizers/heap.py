import angr
import claripy

from helpers.log import logger
from sanitizers.base import Sanitizer, HookDispatcher
from helpers import angr_introspection

def is_stack_operation(state):
    """
    Determine if the current instruction is a stack operation such as return, push, or call.
    """
    ip = state.solver.eval(state.regs.rip)
    #insn = state.block().capstone.insns[state.inspect.instruction_index]
    for insn in state.block().capstone.insns:
        if insn.address == ip:
            logger.debug(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
            break
    else:
        logger.warning(f"Instruction not found at address 0x{ip:x}")
        return False

    mnemonic = insn.mnemonic
    logger.debug(f"Instruction mnemonic: {mnemonic}")
    return mnemonic in ['ret', 'push', 'call']



class MallocHook(angr.SimProcedure):
    def run(self, size):
        addr = self.state.heap._malloc(self.state.solver.eval(size))
        self.project.heap_sanitizer.allocations[addr] = size
        logger.debug(f"malloc({size}) = {addr}")
        return addr

class FreeHook(angr.SimProcedure):
    def run(self, ptr):
        addr = self.state.solver.eval(ptr)
        if addr in self.project.heap_sanitizer.allocations:
            size = self.project.heap_sanitizer.allocations.pop(addr)
            self.project.heap_sanitizer.freed_regions.append((addr, size))
            logger.debug(f"free({addr})")
        else:
            logger.debug(f"Double free detected at {addr}")
        return claripy.BVV(0, self.state.arch.bits)

class HeapSanitizer(Sanitizer):
    def __init__(self, project, dispatcher: HookDispatcher, shared):
        super().__init__(project)
        self.allocations = {}
        self.freed_regions = []
        self.shared = shared
        self.dispatcher: HookDispatcher = dispatcher
        self.project.heap_sanitizer = self

    def install_hooks(self):
        self.project.hook_symbol('malloc', MallocHook())
        self.project.hook_symbol('free', FreeHook())
        self.dispatcher.register_mem_read_hook(self.mem_read_hook)
        self.dispatcher.register_mem_write_hook(self.mem_write_hook)

    def mem_read_hook(self, state):

        if self.shared.proj.is_hooked(state.addr):
            return

        mem_addr = state.inspect.mem_read_address
        mem_length = state.inspect.mem_read_length

        if mem_addr is None or mem_length is None:
            return

        mem_addr = state.solver.eval(mem_addr)
        mem_length = state.solver.eval(mem_length)


        if not state.regs.sp.concrete:
            logger.critical(f"SP is symbolic: {state.regs.sp}")
            return

        if is_stack_operation(state):
            return

        sp_val = state.solver.eval(state.regs.sp)
        rip = state.solver.eval(state.regs.rip)
        logger.debug(f"[{hex(rip)}] Memory read at {hex(mem_addr)} of size {mem_length} (sp: {hex(sp_val)})")


        self.check_memory_access(state, mem_addr, mem_length)

    def mem_write_hook(self, state):

        if self.shared.proj.is_hooked(state.addr):
            return

        mem_addr = state.inspect.mem_write_address
        mem_length = state.inspect.mem_write_length

        if mem_addr is None or mem_length is None:
            return

        mem_addr = state.solver.eval(mem_addr)
        mem_length = state.solver.eval(mem_length)


        if not state.regs.sp.concrete:
            logger.critical(f"SP is symbolic: {state.regs.sp}")
            return

        if is_stack_operation(state):
            return

        sp_val = state.solver.eval(state.regs.sp)
        rip = state.solver.eval(state.regs.rip)
        logger.debug(f"[{hex(rip)}] Memory write at {hex(mem_addr)} of size {mem_length} (sp: {hex(sp_val)})")

        self.check_memory_access(state, mem_addr, mem_length)


    def check_memory_access(self, state, addr, size):
        # Check for UAF
        for (freed_addr, freed_size) in self.freed_regions:

            if state.solver.satisfiable(extra_constraints=[addr + size > freed_addr, addr < freed_addr + freed_size]):
                logger.debug(f"Use-After-Free detected at {hex(addr)}")
                angr_introspection.pretty_print_callstack(state)

                break

        # Check for out-of-bounds
        for (alloc_addr, alloc_size) in self.allocations.items():

            if state.solver.satisfiable(extra_constraints=[addr + size > alloc_addr, addr < alloc_addr + alloc_size]):
                logger.debug(f"Out-of-bounds access detected at {hex(addr)}")
                angr_introspection.pretty_print_callstack(state)
                break

        else:
            logger.debug(f"Invalid memory access at {addr}")
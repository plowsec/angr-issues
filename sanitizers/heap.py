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
            #logger.debug(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
            break
    else:
        logger.warning(f"Instruction not found at address 0x{ip:x}")
        return False

    mnemonic = insn.mnemonic
    #logger.debug(f"Instruction mnemonic: {mnemonic}")
    return mnemonic in ['ret', 'push', 'call']



class MallocHook(angr.SimProcedure):
    def run(self, size):
        sim_size = self.state.solver.eval(size)
        """
        The actual allocation primitive for this heap implementation. Increases the position of the break to allocate
        space. Has no guards against the heap growing too large.

        :param sim_size: a size specifying how much to increase the break pointer by
        :returns: a pointer to the previous break position, above which there is now allocated space
        """
        size = self.state.heap._conc_alloc_size(sim_size)
        while size % 16 != 0:
            size += 1
        addr = self.state.heap.heap_location
        self.state.heap.heap_location += size
        while addr in self.state.globals["allocations"].keys() or any([addr in x for x in self.state.globals["freed_regions"]]):
            if addr in self.state.globals["allocations"]:
                addr += self.state.globals["allocations"][addr]
            addr += 16

        while size % 16 != 0:
            size += 1
        logger.debug("Allocating %d bytes at address %#08x", size, addr)

        #addr = self.state.heap._malloc(self.state.solver.eval(size))

        self.state.globals["allocations"][addr] = size
        logger.debug(f"malloc({size}) = {hex(addr)}")
        return addr

class FreeHook(angr.SimProcedure):
    def run(self, ptr):
        addr = self.state.solver.eval(ptr)
        if addr in self.state.globals["allocations"]:
            size = self.state.globals["allocations"].pop(addr)
            self.state.globals["freed_regions"].append((addr, size))
            logger.debug(f"[{hex(self.state.addr)}] free({hex(addr)})")
            return claripy.BVV(0, self.state.arch.bits)

        for (freed_addr, freed_size) in self.state.globals["freed_regions"]:
            if addr == freed_addr:
                logger.warning(f"[{hex(self.state.addr)}] Double free detected at {hex(addr)}")
                return claripy.BVV(0, self.state.arch.bits)
        else:
            logger.debug(f"[{hex(self.state.addr)}] Freeing unknown address: {addr}")
            if ptr.symbolic:
                logger.warning(f"[{hex(self.state.addr)}] Symbolic free detected at {hex(addr)}")
                if self.state.solver.satisfiable(extra_constraints=[ptr == 31337]):
                    logger.warning(f"[{hex(self.state.addr)}] Arbitrary free detected, example ptr= {hex(addr)}")

        return claripy.BVV(0, self.state.arch.bits)


class HeapSanitizer(Sanitizer):
    def __init__(self, project, dispatcher: HookDispatcher, shared):
        super().__init__(project)
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
        #logger.debug(f"[{hex(rip)}] Memory read at {hex(mem_addr)} of size {mem_length} (sp: {hex(sp_val)})")


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
        #logger.debug(f"[{hex(rip)}] Memory write at {hex(mem_addr)} of size {mem_length} (sp: {hex(sp_val)})")

        self.check_memory_access(state, mem_addr, mem_length)

    def format_addr(self, addr):
        if isinstance(addr, int):
            return hex(addr)
        elif isinstance(addr, claripy.ast.bv.BV):
            return f"BV({addr})"
        else:
            return str(addr)

    def check_memory_access(self, state, addr, size):


        logger.debug(f"[{hex(state.addr)}] Checking memory access at {hex(addr)} of size {size}, freed regions: {len(state.globals["freed_regions"])}, allocations: {len(state.globals["allocations"])}")
        addr_str = self.format_addr(addr)
        freed_regions_str = ", ".join([f"{self.format_addr(freed_addr)}-{self.format_addr(freed_addr + freed_size)}" for (freed_addr, freed_size) in state.globals["freed_regions"]])
        # Check for UAF
        logger.debug(f"Checking for UAF at {addr_str} in {freed_regions_str}")
        for (freed_addr, freed_size) in state.globals["freed_regions"]:
            uaf_constraints = [addr + size > freed_addr, addr < freed_addr + freed_size]

            if state.solver.satisfiable(extra_constraints=uaf_constraints):

                state_copy = state.copy()
                state_copy.add_constraints(uaf_constraints[0])
                state_copy.add_constraints(uaf_constraints[1])

                # Get concrete values if possible
                concrete_addr = state_copy.solver.eval(addr) if state_copy.solver.unique(addr) else "symbolic"
                concrete_size = state_copy.solver.eval(size) if state_copy.solver.unique(size) else "symbolic"

                # Calculate offset from the start of the freed region
                if isinstance(concrete_addr, int):
                    offset = concrete_addr - freed_addr
                    offset_info = f", offset +{offset}"
                else:
                    offset_info = ", offset symbolic"

                logger.warning(
                    f"UaF at {hex(state.addr)}: access to {self.format_addr(concrete_addr) if isinstance(concrete_addr, int) else concrete_addr} (size: {concrete_size}), freed region: {self.format_addr(freed_addr)}-{self.format_addr(freed_addr + freed_size)}{offset_info}")

                angr_introspection.pretty_print_callstack(state, max_depth=50)
                break

        # Check for out-of-bounds
        # Check for out-of-bounds
        for (alloc_addr, alloc_size) in state.globals["allocations"].items():
            oob_constraints = [
                state.solver.Or(
                    state.solver.And(addr >= alloc_addr, addr < alloc_addr + alloc_size, addr + size > alloc_addr + alloc_size),
                    state.solver.And(addr < alloc_addr, addr + size > alloc_addr + alloc_size)
                )
            ]

            if state.solver.satisfiable(extra_constraints=oob_constraints):
                state_copy = state.copy()
                state_copy.add_constraints(*oob_constraints)

                concrete_addr = state_copy.solver.eval_one(addr) if state_copy.solver.unique(addr) else addr
                concrete_size = state_copy.solver.eval_one(size) if state_copy.solver.unique(size) else size

                # Calculate distance to relevant boundary
                if state_copy.solver.unique(addr) and state_copy.solver.unique(size):
                    concrete_addr = state_copy.solver.eval_one(addr)
                    concrete_size = state_copy.solver.eval_one(size)
                    if concrete_addr < alloc_addr:
                        distance = alloc_addr - concrete_addr
                        boundary = "lower"
                    else:
                        distance = (concrete_addr + concrete_size) - (alloc_addr + alloc_size)
                        boundary = "upper"
                    distance_info = f", {self.format_addr(distance)} bytes beyond {boundary} bound"
                else:
                    distance_info = ", distance symbolic"

                log_message = (
                    f"OOB at {self.format_addr(state.addr)}: "
                    f"access to {self.format_addr(concrete_addr)} "
                    f"(size: {concrete_size}), "
                    f"allocation: {self.format_addr(alloc_addr)}-{self.format_addr(alloc_addr + alloc_size)}"
                    f"{distance_info}"
                )

                logger.warning(log_message)
                angr_introspection.pretty_print_callstack(state, max_depth=20)
                break

        else:
            #logger.debug(f"Invalid memory access at {addr}")
            pass
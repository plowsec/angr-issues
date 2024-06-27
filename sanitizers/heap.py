import angr
import claripy
import monkeyhex

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

        shadow_size = 16  # Size of shadow bytes (adjust as needed)
        user_size = sim_size
        total_size = shadow_size + user_size + shadow_size

        # Align the total size to 16 bytes
        total_size = (total_size + 15) & ~15

        addr = self.state.heap.heap_location
        self.state.heap.heap_location += total_size

        # Find a free address
        while addr in self.state.globals["allocations"].keys() or any(
                [addr in x for x in self.state.globals["freed_regions"]]):
            if addr in self.state.globals["allocations"]:
                addr += self.state.globals["allocations"][addr]["total_size"]
            addr += 16

        logger.debug(f"Allocating {total_size} bytes (including shadow bytes) at address {hex(addr)}")

        # Initialize shadow bytes
        shadow_value = 0xAA  # Use a distinct value for shadow bytes
        self.state.memory.store(addr, bytes([shadow_value] * shadow_size))
        self.state.memory.store(addr + shadow_size + user_size, bytes([shadow_value] * shadow_size))

        # Store allocation information
        self.state.globals["allocations"][addr] = {
            "total_size": total_size,
            "user_size": user_size
        }
        self.state.globals["shadow_info"][addr] = {
            "start": addr,
            "end": addr + total_size,
            "user_start": addr + shadow_size,
            "user_end": addr + shadow_size + user_size,
        }

        logger.debug(f"malloc({sim_size}) = {hex(addr + shadow_size)}")

        # Return the address of the user buffer (after the shadow bytes)
        return addr + shadow_size

class FreeHook(angr.SimProcedure):
    def run(self, ptr):
        addr = self.state.solver.eval(ptr)
        user_start = addr - 16

        if user_start in self.state.globals["allocations"]:
            size = self.state.globals["allocations"].pop(user_start)
            self.state.globals["freed_regions"].append((user_start, size))
            logger.debug(f"[{hex(self.state.addr)}] free({hex(addr)})")
            return claripy.BVV(0, self.state.arch.bits)

        for (freed_addr, freed_size) in self.state.globals["freed_regions"]:
            if user_start == freed_addr:
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
        self.shadow_size = 16

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
        logger.debug(
            f"[{hex(state.addr)}] Checking memory access at {hex(addr)} of size {size}, freed regions: {len(state.globals['freed_regions'])}, allocations: {len(state.globals['allocations'])}")

        if self.check_use_after_free(state, addr, size):
            return True

        if self.check_out_of_bounds(state, addr, size):
            return True

        return False

    def check_use_after_free(self, state, addr, size):
        addr_str = self.format_addr(addr)
        freed_regions_str = ", ".join(
            [f"{self.format_addr(freed_addr)}-{self.format_addr(freed_addr + freed_size['user_size'])}" for
             (freed_addr, freed_size) in state.globals["freed_regions"]])
        logger.debug(f"Checking for UAF at {addr_str} in {freed_regions_str}")

        for (freed_addr, freed_size) in state.globals["freed_regions"]:
            if self.is_uaf_access(state, addr, size, freed_addr, freed_size):
                self.log_uaf_access(state, addr, size, freed_addr, freed_size)
                return True
        return False

    def is_uaf_access(self, state, addr, size, freed_addr, freed_size):
        user_start = freed_addr + self.shadow_size
        user_end = freed_addr + freed_size["user_size"]
        uaf_constraints = [addr + size > user_start, addr < user_end]
        return state.solver.satisfiable(extra_constraints=uaf_constraints)

    def log_uaf_access(self, state, addr, size, freed_addr, freed_size):
        state_copy = state.copy()
        uaf_constraints = [addr + size > freed_addr + self.shadow_size, addr < freed_addr + freed_size["user_size"]]
        state_copy.add_constraints(*uaf_constraints)

        concrete_addr = state_copy.solver.eval(addr) if state_copy.solver.unique(addr) else "symbolic"
        concrete_size = state_copy.solver.eval(size) if state_copy.solver.unique(size) else "symbolic"

        offset_info = self.get_offset_info(concrete_addr, freed_addr)

        logger.warning(
            f"UaF at {hex(state.addr)}: access to {self.format_addr(concrete_addr) if isinstance(concrete_addr, int) else concrete_addr} "
            f"(size: {concrete_size}), freed region: {self.format_addr(freed_addr)}-{self.format_addr(freed_addr + freed_size['user_size'])}{offset_info}")

        angr_introspection.pretty_print_callstack(state, max_depth=50)

    def get_offset_info(self, concrete_addr, freed_addr):
        if isinstance(concrete_addr, int):
            offset = concrete_addr - freed_addr
            return f", offset +{offset}"
        return ", offset symbolic"

    def check_out_of_bounds(self, state, addr, size):
        for alloc_addr, alloc_info in state.globals["allocations"].items():
            if self.is_oob_access(state, addr, size, alloc_addr, alloc_info):
                self.log_oob_access(state, addr, size, alloc_addr, alloc_info)
                return True
            elif self.is_in_bounds_access(state, addr, size, alloc_addr, alloc_info):
                self.log_in_bounds_access(state, addr, size, alloc_addr, alloc_info)
                return True
        return False

    def is_oob_access(self, state, addr, size, alloc_addr, alloc_info):
        user_start = alloc_addr + self.shadow_size
        user_end = user_start + alloc_info["user_size"]
        oob_constraints = self.get_oob_constraints(state, addr, size, alloc_addr, alloc_info, user_start, user_end)
        return state.solver.satisfiable(extra_constraints=oob_constraints)

    def get_oob_constraints(self, state, addr, size, alloc_addr, alloc_info, user_start, user_end):
        return [
            state.solver.Or(
                state.solver.And(addr >= user_start, addr < user_end, addr + size > user_end),
                state.solver.And(addr < user_start, addr + size > user_start),
                state.solver.And(addr < alloc_addr, addr + size > alloc_addr),
                state.solver.And(addr >= alloc_addr + alloc_info["total_size"],
                                 addr < alloc_addr + alloc_info["total_size"] + self.shadow_size))
        ]

    def log_oob_access(self, state, addr, size, alloc_addr, alloc_info):
        state_copy = state.copy()
        user_start = alloc_addr + self.shadow_size
        user_end = user_start + alloc_info["user_size"]
        oob_constraints = self.get_oob_constraints(state, addr, size, alloc_addr, alloc_info, user_start, user_end)
        state_copy.add_constraints(*oob_constraints)

        concrete_addr = state_copy.solver.eval_one(addr) if state_copy.solver.unique(addr) else addr
        concrete_size = state_copy.solver.eval_one(size) if state_copy.solver.unique(size) else size

        distance_info = self.get_distance_info(state_copy, addr, size, user_start, user_end)

        log_message = (
            f"OOB at {self.format_addr(state.addr)}: "
            f"access to {self.format_addr(concrete_addr)} "
            f"(size: {concrete_size}), "
            f"user allocation: {self.format_addr(user_start)}-{self.format_addr(user_end)}"
            f"{distance_info}"
        )

        logger.warning(log_message)
        angr_introspection.pretty_print_callstack(state, max_depth=20)

    def get_distance_info(self, state, addr, size, user_start, user_end):
        if state.solver.unique(addr) and state.solver.unique(size):
            concrete_addr = state.solver.eval_one(addr)
            concrete_size = state.solver.eval_one(size)
            if concrete_addr < user_start:
                distance = user_start - concrete_addr
                boundary = "lower"
            elif concrete_addr >= user_end:
                distance = concrete_addr - user_end
                boundary = "upper"
            else:
                distance = (concrete_addr + concrete_size) - user_end
                boundary = "upper"
            return f", {self.format_addr(distance)} bytes beyond {boundary} bound"
        return ", distance symbolic"

    def is_in_bounds_access(self, state, addr, size, alloc_addr, alloc_info):
        user_start = alloc_addr + self.shadow_size
        user_end = user_start + alloc_info["user_size"]
        return state.solver.satisfiable(extra_constraints=[
            state.solver.And(
                addr >= user_start,
                addr < user_end
            )])

    def log_in_bounds_access(self, state, addr, size, alloc_addr, alloc_info):
        user_start = alloc_addr + self.shadow_size
        user_end = user_start + alloc_info["user_size"]
        logger.info(
            f"Access starts in bounds at {self.format_addr(addr)} of size {size} in {self.format_addr(user_start)}-{self.format_addr(user_end)}")
        if state.solver.satisfiable(extra_constraints=[addr + size > user_end]):
            logger.warning(
                f"OOB access at {self.format_addr(state.addr)}: access to {self.format_addr(addr)} (size: {size}), user allocation: {self.format_addr(user_start)}-{self.format_addr(user_end)}")
            angr_introspection.pretty_print_callstack(state, max_depth=20)
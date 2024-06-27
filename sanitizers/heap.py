import angr
import claripy
import monkeyhex
from typing import Dict, List, Tuple, Union, Optional

from helpers.log import logger
from sanitizers.base import Sanitizer, HookDispatcher
from helpers import angr_introspection


def is_stack_operation(state: angr.SimState) -> bool:
    """
    Determine if the current instruction is a stack operation such as return, push, or call.
    """
    ip: int = state.solver.eval(state.regs.rip)
    for insn in state.block().capstone.insns:
        if insn.address == ip:
            break
    else:
        logger.warning(f"Instruction not found at address 0x{ip:x}")
        return False

    mnemonic: str = insn.mnemonic
    return mnemonic in ['ret', 'push', 'call']


class MallocHook(angr.SimProcedure):
    def run(self, size: claripy.ast.BV) -> claripy.ast.BV:
        sim_size: int = self.state.solver.eval(size)

        shadow_size: int = 16  # Size of shadow bytes (adjust as needed)
        user_size: int = sim_size
        total_size: int = shadow_size + user_size + shadow_size

        # Align the total size to 16 bytes
        total_size = (total_size + 15) & ~15

        addr: int = self.state.heap.heap_location
        self.state.heap.heap_location += total_size

        # Find a free address
        while addr in self.state.globals["allocations"].keys() or any(
                [addr in x for x in self.state.globals["freed_regions"]]):
            if addr in self.state.globals["allocations"]:
                addr += self.state.globals["allocations"][addr]["total_size"]
            addr += 16

        user_addr: int = addr + shadow_size
        end_addr: int = addr + total_size

        logger.info(
            f"MALLOC: req=0x{sim_size:x}, total=0x{total_size:x}, shadow=0x{shadow_size:x}, addr=0x{addr:x}-0x{end_addr:x}, user=0x{user_addr:x}-0x{user_addr + user_size:x}")

        # Initialize shadow bytes
        shadow_value: int = 0xAA  # Use a distinct value for shadow bytes
        self.state.memory.store(addr, bytes([shadow_value] * shadow_size))
        self.state.memory.store(end_addr - shadow_size, bytes([shadow_value] * shadow_size))

        logger.debug(f"SHADOW: before=0x{addr:x}-0x{user_addr:x}, after=0x{user_addr + user_size:x}-0x{end_addr:x}")

        # Store allocation information
        self.state.globals["allocations"][addr] = {
            "total_size": total_size,
            "user_size": user_size
        }
        self.state.globals["shadow_info"][addr] = {
            "start": addr,
            "end": end_addr,
            "user_start": user_addr,
            "user_end": user_addr + user_size,
        }

        logger.info(f"malloc({sim_size}) = 0x{user_addr:x}")

        # Return the address of the user buffer (after the shadow bytes)
        return claripy.BVV(user_addr, self.state.arch.bits)


class FreeHook(angr.SimProcedure):
    def run(self, ptr: claripy.ast.BV) -> claripy.ast.BV:
        addr: int = self.state.solver.eval(ptr)
        user_start: int = addr - 16

        if user_start in self.state.globals["allocations"]:
            size: Dict[str, int] = self.state.globals["allocations"].pop(user_start)
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
    def __init__(self, project: angr.Project, dispatcher: HookDispatcher, shared):
        super().__init__(project)
        self.shared = shared
        self.dispatcher: HookDispatcher = dispatcher
        self.project.heap_sanitizer = self
        self.shadow_size: int = 16

    def install_hooks(self) -> None:
        self.project.hook_symbol('malloc', MallocHook())
        self.project.hook_symbol('free', FreeHook())
        self.dispatcher.register_mem_read_hook(self.mem_read_hook)
        self.dispatcher.register_mem_write_hook(self.mem_write_hook)

    def mem_read_hook(self, state: angr.SimState) -> None:
        if self.shared.proj.is_hooked(state.addr):
            return

        mem_addr: Optional[claripy.ast.BV] = state.inspect.mem_read_address
        mem_length: Optional[claripy.ast.BV] = state.inspect.mem_read_length

        if mem_addr is None or mem_length is None:
            return

        mem_addr: int = state.solver.eval(mem_addr)
        mem_length: int = state.solver.eval(mem_length)

        if not state.regs.sp.concrete:
            logger.critical(f"SP is symbolic: {state.regs.sp}")
            return

        if is_stack_operation(state):
            return

        sp_val: int = state.solver.eval(state.regs.sp)
        rip: int = state.solver.eval(state.regs.rip)

        self.check_memory_access(state, mem_addr, mem_length)

    def mem_write_hook(self, state: angr.SimState) -> None:
        if self.shared.proj.is_hooked(state.addr):
            return

        mem_addr: Optional[claripy.ast.BV] = state.inspect.mem_write_address
        mem_length: Optional[claripy.ast.BV] = state.inspect.mem_write_length

        if mem_addr is None or mem_length is None:
            return

        mem_addr: int = state.solver.eval(mem_addr)
        mem_length: int = state.solver.eval(mem_length)

        if not state.regs.sp.concrete:
            logger.critical(f"SP is symbolic: {state.regs.sp}")
            return

        if is_stack_operation(state):
            return

        sp_val: int = state.solver.eval(state.regs.sp)
        rip: int = state.solver.eval(state.regs.rip)

        self.check_memory_access(state, mem_addr, mem_length)

    def format_addr(self, addr: Union[int, claripy.ast.BV]) -> str:
        if isinstance(addr, int):
            return hex(addr)
        elif isinstance(addr, claripy.ast.bv.BV):
            return f"BV({addr})"
        else:
            return str(addr)

    def check_memory_access(self, state: angr.SimState, addr: int, size: int) -> bool:
        logger.debug(
            f"[{hex(state.addr)}] Checking memory access at {hex(addr)} of size {size}, freed regions: {len(state.globals['freed_regions'])}, allocations: {len(state.globals['allocations'])}")

        if self.check_use_after_free(state, addr, size):
            return True

        if self.check_out_of_bounds(state, addr, size):
            return True

        return False

    def check_use_after_free(self, state: angr.SimState, addr: int, size: int) -> bool:
        addr_str: str = self.format_addr(addr)
        freed_regions_str: str = ", ".join(
            [f"{self.format_addr(freed_addr)}-{self.format_addr(freed_addr + freed_size['user_size'])}" for
             (freed_addr, freed_size) in state.globals["freed_regions"]])
        # logger.debug(f"[0x{state.addr:x}] Checking for UAF: {addr_str} in {freed_regions_str}")

        for (freed_addr, freed_size) in state.globals["freed_regions"]:
            if self.is_uaf_access(state, addr, size, freed_addr, freed_size):
                self.log_uaf_access(state, addr, size, freed_addr, freed_size)
                return True
        return False

    def is_uaf_access(self, state: angr.SimState, addr: int|claripy.ast.BV, size: int|claripy.ast.BV, freed_addr: int,
                      freed_size: Dict[str, int]) -> bool:
        user_start: int = freed_addr + self.shadow_size
        user_end: int = freed_addr + freed_size["user_size"]
        uaf_constraints: List[claripy.ast.Bool] = [addr + size > user_start, addr < user_end]
        return state.solver.satisfiable(extra_constraints=uaf_constraints)

    def log_uaf_access(self, state: angr.SimState, addr: int|claripy.ast.BV, size: int|claripy.ast.BV, freed_addr: int,
                       freed_size: Dict[str, int]) -> None:
        state_copy: angr.SimState = state.copy()
        uaf_constraints: List[claripy.ast.Bool] = [addr + size > freed_addr + self.shadow_size,
                                                   addr < freed_addr + freed_size["user_size"]]
        state_copy.add_constraints(*uaf_constraints)

        concrete_addr: Union[int, str] = state_copy.solver.eval(addr) if state_copy.solver.unique(addr) else "symbolic"
        concrete_size: Union[int, str] = state_copy.solver.eval(size) if state_copy.solver.unique(size) else "symbolic"

        offset_info: str = self.get_offset_info(concrete_addr, freed_addr)

        logger.warning(
            f"UaF at {hex(state.addr)}: access to {self.format_addr(concrete_addr) if isinstance(concrete_addr, int) else concrete_addr} "
            f"(size: {concrete_size}), freed region: {self.format_addr(freed_addr)}-{self.format_addr(freed_addr + freed_size['user_size'])}{offset_info}")

        angr_introspection.pretty_print_callstack(state, max_depth=50)


    def get_offset_info(self, concrete_addr: Union[int, str], freed_addr: int) -> str:
        if isinstance(concrete_addr, int):
            offset: int = concrete_addr - freed_addr
            return f", offset +{offset}"
        return ", offset symbolic"

    def check_out_of_bounds(self, state: angr.SimState, addr: int, size: int) -> bool:
        for alloc_addr, alloc_info in state.globals["allocations"].items():
            if self.is_oob_access(state, addr, size, alloc_addr, alloc_info):
                self.log_oob_access(state, addr, size, alloc_addr, alloc_info)
                return True
            elif self.is_in_bounds_access(state, addr, size, alloc_addr, alloc_info):
                self.log_in_bounds_access(state, addr, size, alloc_addr, alloc_info)
                return True
        return False

    def is_oob_access(self, state: angr.SimState, addr: int, size: int, alloc_addr: int,
                      alloc_info: Dict[str, int]) -> bool:
        user_start: int = alloc_addr + self.shadow_size
        user_end: int = user_start + alloc_info["user_size"]
        oob_constraints: List[claripy.ast.Bool] = self.get_oob_constraints(state, addr, size, alloc_addr, alloc_info,
                                                                           user_start, user_end)
        return state.solver.satisfiable(extra_constraints=oob_constraints)

    def get_oob_constraints(self, state: angr.SimState, addr: int, size: int, alloc_addr: int,
                            alloc_info: Dict[str, int], user_start: int, user_end: int) -> List[claripy.ast.Bool]:
        return [
            state.solver.And(
                alloc_addr < addr, addr < alloc_addr+alloc_info["total_size"]),
                state.solver.Or(
                    state.solver.And(addr >= user_start, addr + size > user_end),
                    addr + size > user_end,
                    addr < user_start,
                    state.solver.And(addr < user_start),
                    state.solver.And(addr < alloc_addr, addr + size > alloc_addr
                )
            )
        ]

    def log_oob_access(self, state: angr.SimState, addr: int|claripy.ast.BV, size: int|claripy.ast.BV, alloc_addr: int,
                       alloc_info: Dict[str, int]) -> None:
        state_copy: angr.SimState = state.copy()
        user_start: int = alloc_addr + self.shadow_size
        user_end: int = user_start + alloc_info["user_size"]
        oob_constraints: List[claripy.ast.Bool] = self.get_oob_constraints(state, addr, size, alloc_addr, alloc_info,
                                                                           user_start, user_end)
        state_copy.add_constraints(*oob_constraints)

        concrete_addr: Union[int, claripy.ast.BV] = state_copy.solver.eval_one(addr) if state_copy.solver.unique(
            addr) else addr
        concrete_size: Union[int, claripy.ast.BV] = state_copy.solver.eval_one(size) if state_copy.solver.unique(
            size) else size

        distance_info: str = self.get_distance_info(state_copy, addr, size, user_start, user_end)

        log_message: str = (
            f"OOB at {self.format_addr(state.addr)}: "
            f"access to {self.format_addr(concrete_addr)} "
            f"(size: {concrete_size}), "
            f"user allocation: {self.format_addr(user_start)}-{self.format_addr(user_end)}"
            f"{distance_info}"
        )

        logger.warning(log_message)
        angr_introspection.pretty_print_callstack(state, max_depth=20)

    def get_distance_info(self, state: angr.SimState, addr: int | claripy.ast.BV, size: int | claripy.ast.BV,
                          user_start: int, user_end: int) -> str:
        if state.solver.unique(addr) and state.solver.unique(size):
            concrete_addr: int = state.solver.eval_one(addr)
            concrete_size: int = state.solver.eval_one(size)
            if concrete_addr < user_start:
                distance: int = user_start - concrete_addr
                boundary: str = "lower"
            elif concrete_addr >= user_end:
                distance: int = concrete_addr - user_end
                boundary: str = "upper"
            else:
                distance: int = (concrete_addr + concrete_size) - user_end
                boundary: str = "upper"
            return f", {self.format_addr(distance)} bytes beyond {boundary} bound"
        return ", distance symbolic"

    def is_in_bounds_access(self, state: angr.SimState, addr: int, size: int, alloc_addr: int,
                            alloc_info: Dict[str, int]) -> bool:
        user_start: int = alloc_addr + self.shadow_size
        user_end: int = user_start + alloc_info["user_size"]
        return state.solver.satisfiable(extra_constraints=[
            state.solver.And(
                addr >= user_start,
                addr < user_end
            )])

    def log_in_bounds_access(self, state: angr.SimState, addr: int|claripy.ast.BV, size: int|claripy.ast.BV, alloc_addr: int,
                             alloc_info: Dict[str, int]) -> None:
        user_start: int = alloc_addr + self.shadow_size
        user_end: int = user_start + alloc_info["user_size"]
        logger.info(
            f"Access in bounds from {self.format_addr(addr)} to {self.format_addr(addr + size)} (size {size}) in region {self.format_addr(user_start)}-{self.format_addr(user_end)}")


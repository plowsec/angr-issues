import functools

import angr
import shared
from helpers.log import logger


# List to store tracked stack buffers
tracked_buffers = {} # dict: function address -> list of stack variables

# Set to track analyzed functions
analyzed_functions = set()

oob_addresses = set()

def analyze_stack_vars(state):
    func_addr = state.addr
    if func_addr in analyzed_functions:
        return

    analyzed_functions.add(func_addr)
    func = state.project.kb.functions.function(addr=func_addr)
    logger.debug(f'Analyzing function: {func}')

    a = state.project.analyses.VariableRecoveryFast(store_live_variables=True, func=func, track_sp=True, )
    fn_manager = a.variable_manager.function_managers.get(func.addr)
    stack_vars = [x for x in fn_manager.get_variables() if
                  isinstance(x, angr.analyses.variable_recovery.variable_recovery_fast.SimStackVariable)]

    # get min and max stack offset
    min_offset = 0
    max_offset = 0
    for var in stack_vars:
        if var.offset < min_offset:
            min_offset = var.offset
        if var.offset + var.size > max_offset:
            max_offset = var.offset + var.size


    tracked_buffers[func.addr] = []

    for var in stack_vars:
        var_addr = state.solver.eval(state.regs.bp + var.offset)
        tracked_buffers[func.addr].append((var.offset, var.size, (min_offset, max_offset)))
        logger.debug(f'Detected stack variable: {var} at {hex(var_addr)} of size {var.size}. Base {hex(var.base_addr) if var.base_addr is not None else 0}. Offset {hex(var.offset) if var.offset is not None else 0}')

    dec = shared.proj.analyses.Decompiler(func, cfg=shared.cfg.model)
    logger.debug(dec.codegen.text)


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



@functools.lru_cache(maxsize=128)
def get_function_stack_offset(func):

    first_block = shared.proj.factory.block(func.addr)

    # find the IRSB statement that sets the stack pointer
    for stmt in first_block.vex.statements:

        if stmt.tag != 'Ist_Put':
            continue

        if stmt.offset == shared.proj.arch.registers['sp'][0]:
            logger.debug(f"Stack pointer set to {stmt.data}")
            if stmt.data.tag == 'Iex_RdTmp':
                t = stmt.data.tmp
                logger.debug(f"Stack pointer set to {t}")
                break
            else:
                raise(f"Unhandled stack pointer set: {stmt.data}")

    else:
        raise("Stack pointer not found")

    # find the IRSB statement that does the stack pointer arithmetic
    for stmt in first_block.vex.statements:

        if stmt.tag != 'Ist_WrTmp':
            continue

        if stmt.tmp != t:
            continue

        if stmt.data.op.startswith('Iop_Sub'):
            logger.debug(f"Stack pointer arithmetic: {stmt.data}")
            operands = stmt.data.args
            break
    else:
        raise("Stack pointer arithmetic not found")


    # find the const value that is subtracted from the stack pointer
    for operand in operands:
        if operand.tag == 'Iex_Const':
            logger.debug(f"Stack pointer subtracted by {operand}")
            stack_offset = operand.con.value
            break
    else:

        raise Exception("Stack pointer offset not found")

    return stack_offset


def check_oob_write(state):

    if shared.proj.is_hooked(state.addr):
        return

    mem_addr = state.inspect.mem_write_address
    mem_length = state.inspect.mem_write_length

    if mem_addr is None or mem_length is None:
        return

    mem_addr = state.solver.eval(mem_addr)
    mem_length = state.solver.eval(mem_length)

    if mem_addr in oob_addresses:
        return

    if not state.regs.sp.concrete:
        logger.critical(f"SP is symbolic: {state.regs.sp}")
        return

    if is_stack_operation(state):
        return

    sp_val = state.solver.eval(state.regs.sp)
    rip = state.solver.eval(state.regs.rip)
    logger.debug(f"[{hex(rip)}] Memory write at {hex(mem_addr)} of size {mem_length} (sp: {hex(sp_val)})")

    # get the function address
    fn = shared.proj.kb.functions.floor_func(rip)
    if fn is None:
        logger.warning(f"Function not found for address {state.addr}")
        return


    # manual
    tracked_buffers_fn = tracked_buffers.get(fn.addr)

    if tracked_buffers_fn is None:
        logger.warning(f"No tracked buffers for function {fn.name}")
        analyze_stack_vars(state)
        tracked_buffers_fn = tracked_buffers.get(fn.addr)
        if tracked_buffers_fn is None:
            logger.warning(f"Still no tracked buffers for function {fn.name}")
            return

    # angr's solution
    fn_kb_var = shared.proj.kb.variables.function_managers.get(fn.addr)
    stack_min_offset = min(fn_kb_var._stack_region._storage.keys())
    stack_max_offset = max(fn_kb_var._stack_region._storage.keys())
    accessed_var = fn_kb_var.find_variables_by_insn(state.addr, "memory")
    if accessed_var is not None:
        logger.debug(f"Accessed variable: {accessed_var}")
        logger.debug(f"Stack min offset: {stack_min_offset}")
        logger.debug(f"Stack max offset: {stack_max_offset}")
    else:
        logger.error(f"(angr) OOB write detected at {hex(mem_addr)} (sp+{hex(mem_addr-sp_val)}) of size {mem_length}")


    get_function_stack_offset(fn)

    min_offset, max_offset = tracked_buffers_fn[0][2]

    first_block = shared.proj.factory.block(fn.addr)

    offset_diff = 0
    if rip > first_block.addr + first_block.size:
        try:
            offset_diff = get_function_stack_offset(fn) # get the stack offset by matching Sub RSP, const operations
            sp_val += offset_diff
        except:
            logger.critical(f"Failed to get stack offset for function {fn.name}")
            return

    # Check if the memory write is within the stack range
    if sp_val + min_offset <= mem_addr < sp_val + max_offset:
        for buffer in tracked_buffers_fn:
            buf_offset, buf_size, _ = buffer
            buf_addr = sp_val + buf_offset
            if buf_addr <= mem_addr < buf_addr + buf_size:
                # This is a known buffer, check for out-of-bounds
                if mem_addr + mem_length > buf_addr + buf_size:
                    logger.warning(f"Out-of-bounds write detected at {hex(mem_addr)} (sp+{hex(mem_addr-sp_val)}) of size {mem_length}")
                    is_stack_operation(state)
                else:
                    logger.debug(f"Write at {hex(mem_addr)} (sp+{hex(mem_addr-sp_val)}) of size {mem_length} is within bounds of buffer at {hex(buf_addr)} (sp+{hex(buf_offset)}) (size {buf_size})")
                return

        # If the write is not within any known buffer, it might be OOB

        logger.warning(f"[{hex(state.addr)}] Potential out-of-bounds write detected at sp+{hex(mem_addr-sp_val)} of size {mem_length}")
        oob_addresses.add(mem_addr)
    else:
        logger.debug(f"Write at {hex(mem_addr)} ({hex(mem_addr-sp_val)}) of size {mem_length} is not within stack bounds? ({hex(sp_val+min_offset)}-{hex(sp_val+max_offset)})")
        if mem_addr > sp_val + max_offset:
            logger.debug(f"Write is above stack bounds: {hex(mem_addr-(sp_val+max_offset))}")
        else:
            logger.debug(f"Write is below stack bounds: -{hex(sp_val+min_offset-mem_addr)}")
        logger.debug(f"Stack pointer: {hex(sp_val)}")


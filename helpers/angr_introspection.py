import uuid

from helpers.log import logger
from helpers import shared


def get_small_coverage(*args, **kwargs):
    """

    if not shared.proj.is_hooked(state.addr):
        block = shared.proj.factory.block(state.addr)

        if len(block.capstone.insns) == 1 and (
                block.capstone.insns[0].mnemonic.startswith("rep m")
                or block.capstone.insns[0].mnemonic.startswith("rep s")
        ):
            logger.debug(f"Hooking instruction {block.capstone.insns[0].mnemonic} @ {hex(state.addr)}")
            insn = block.capstone.insns[0]
            shared.proj.hook(state.addr, hooks.RepHook(insn.mnemonic.split(" ")[1]).run, length=insn.size)
    """
    sm = args[0]
    stashes = sm.stashes
    i = 0
    for simstate in stashes["active"]:
        state_history = ""

        for addr in simstate.history.bbl_addrs.hardcopy:
            write_address = hex(addr)
            state_history += "{0}\n".format(write_address)

        ip = hex(simstate.solver.eval(simstate.ip))
        uid = str(uuid.uuid4())
        sid = str(i).zfill(5)
        filename = "{0}_active_{1}_{2}".format(sid, ip, uid)

        with open(filename, "w") as f:
            f.write(state_history)
        i += 1

def debug_step_func(simgr):

    for state in simgr.stashes["active"]:
        logger.debug(f"Active state: {state}")
        pretty_print_callstack(state, 50)


def pretty_print_callstack(state, max_depth=10):
    state_history = "Call Stack:\n"
    kb_functions = shared.proj.kb.functions

    last_addr = None
    repeat_count = 0
    formatted_lines = []
    current_indent = 0

    for i, addr in enumerate(state.history.bbl_addrs.hardcopy):
        func = kb_functions.floor_func(addr)

        if addr == last_addr:
            repeat_count += 1
        else:
            if repeat_count > 0:
                formatted_lines[-1] += f" (repeated {repeat_count + 1} times)"
                repeat_count = 0

            indent = ' ' * (current_indent * 2)
            if func:
                fname = func.human_str if hasattr(func, 'human_str') else func.name
                func_prototype = func.prototype if hasattr(func, 'prototype') else ""
                formatted_lines.append(
                    f"{indent}-> 0x{addr:x} : {fname} {func_prototype} ({len(list(func.xrefs))} xrefs)")
            else:
                formatted_lines.append(f"{indent}-> 0x{addr:x} : Unknown function")

            current_indent += 1

        last_addr = addr

    # Handle the case where the last address was repeating
    if repeat_count > 0:
        formatted_lines[-1] += f" (repeated {repeat_count + 1} times)"

    state_history += "\n".join(formatted_lines)

    # Print the formatted call stack
    if len(formatted_lines) > max_depth:
        logger.debug("\n".join([state_history.split("\n")[0]] + formatted_lines[:max_depth // 2]))
        logger.debug("...")
        logger.debug("\n".join(formatted_lines[-max_depth // 2:]))
    else:
        logger.debug(state_history)


def inspect_call(state):

    # pretty_print_callstack(state)

    human_str = state.project.loader.describe_addr(state.addr)
    logger.debug(
        f'[{hex(state.addr)}] call {hex(state.addr)} ({human_str}) from {hex(state.history.addr)} ({state.project.loader.describe_addr(state.addr)})')
    if "extern-address" in human_str and not state.project.is_hooked(state.addr):
        logger.warning(f"Implement hook for {hex(state.addr)} ({human_str})")
        pass

    #if not shared.proj.is_hooked(state.addr):
    #    analyze_stack_vars(state)


def angr_enum_functions(proj):
    for addr in proj.kb.functions:
        logger.debug(f'function: {hex(addr)}')
        logger.debug(f'function name: {proj.kb.functions[addr].name}')
        logger.debug(f'strings: {list(proj.kb.functions[addr].string_references())}')


def inspect_concretization(state):
    # Log the event type
    logger.debug("Address concretization event triggered")

    # Log the SimAction object being used to record the memory action
    action = state.inspect.address_concretization_action
    logger.debug(f"SimAction: {action}")

    # Log the SimMemory object on which the action was taken
    memory = state.inspect.address_concretization_memory
    logger.debug(f"SimMemory: {memory}")

    # Log the AST representing the memory index being resolved
    expr = state.inspect.address_concretization_expr
    logger.debug(f"AST expression: {expr}")

    # Log whether or not constraints should/will be added for this read
    add_constraints = state.inspect.address_concretization_add_constraints
    logger.debug(f"Add constraints: {add_constraints}")

    # Log the list of resolved memory addresses (only available after concretization)
    if state.inspect.address_concretization_result is not None:
        result = state.inspect.address_concretization_result
        logger.debug(f"Resolved addresses: {result}")


def show_errors(state):
    logger.debug(f'errored state: {state}')

    # print the error message
    logger.debug(f'error message: {state.error}')

    # print the traceback for the error
    tb = state.traceback

    while tb.tb_next:
        logger.error(f'{tb.tb_frame}')
        tb = tb.tb_next

    logger.error(f'{tb.tb_frame}')
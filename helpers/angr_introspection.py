import uuid

from helpers.log import logger
import shared

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


def pretty_print_callstack(state):
    # Initialize an empty string to store the formatted call stack
    state_history = "Call Stack:\n"

    # Access the knowledge base of functions
    kb_functions = shared.proj.kb.functions

    # Iterate over the basic block addresses in the state's history
    for i, addr in enumerate(state.history.bbl_addrs.hardcopy):
        # Retrieve the function information from the knowledge base
        func = kb_functions.floor_func(addr)

        # Format the address and function prototype if available
        if func:
            fname = func.human_str if hasattr(func, 'human_str') else func.name
            func_prototype = func.prototype if hasattr(func, 'prototype') else ""
            state_history += f"{' ' * (i * 2)}-> 0x{addr:x} : {fname} {func_prototype} ({len(list(func.xrefs))} xrefs)\n"
        else:
            state_history += f"{' ' * (i * 2)}-> 0x{addr:x} : Unknown function\n"

    # Print the formatted call stack
    logger.debug(state_history)


def inspect_call(state):

    pretty_print_callstack(state)

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
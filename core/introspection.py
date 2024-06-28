import os
import uuid
from typing import Any, Dict, List, Set, Tuple

import networkx as nx

import angr
from helpers import shared
from helpers.log import logger


def get_small_coverage(*args, **kwargs) -> None:
    """
    Generate coverage files for active states in the simulation manager.

    """
    sm: angr.SimulationManager = args[0]
    stashes: Dict[str, List[angr.SimState]] = sm.stashes
    i: int = 0

    if not os.path.exists("cov"):
        os.makedirs("cov")

    for simstate in stashes["active"]:
        state_history: str = ""

        for addr in simstate.history.bbl_addrs.hardcopy:
            write_address: str = hex(addr)
            state_history += "{0}\n".format(write_address)

        ip: str = hex(simstate.solver.eval(simstate.ip))
        uid: str = str(uuid.uuid4())
        sid: str = str(i).zfill(5)
        filename: str = "cov/{0}_active_{1}_{2}".format(sid, ip, uid)

        with open(filename, "w") as f:
            f.write(state_history)
        i += 1


def debug_step_func(simgr: angr.SimulationManager) -> None:
    """
    Debug function to print active states and their call stacks.

    Args:
        simgr: The simulation manager.
    """
    for state in simgr.stashes["active"]:
        logger.debug(f"Active state: {state}")
        pretty_print_callstack(state, 50)

    get_small_coverage(simgr)


def pretty_print_callstack(state: angr.SimState, max_depth: int = 10) -> None:
    """
    Print a formatted call stack for a given state.

    Args:
        state: The simulation state.
        max_depth: Maximum depth of the call stack to print.
    """
    state_history: str = "Call Stack:\n"
    kb_functions = shared.proj.kb.functions

    last_addr: int = 0
    repeat_count: int = 0
    formatted_lines: List[str] = []
    call_stack: List[angr.knowledge_plugins.functions.function.Function] = []
    current_func: angr.knowledge_plugins.functions.function.Function | None = None

    for i, addr in enumerate(state.history.bbl_addrs.hardcopy):
        func: angr.knowledge_plugins.functions.function.Function = kb_functions.floor_func(addr)

        if addr == last_addr:
            repeat_count += 1
        else:
            if repeat_count > 0:
                formatted_lines[-1] += f" (repeated {repeat_count + 1} times)"
                repeat_count = 0

            if func != current_func:
                if func in call_stack:
                    while call_stack and call_stack[-1] != func:
                        call_stack.pop()
                    if call_stack:
                        call_stack.pop()
                else:
                    call_stack.append(func)
                current_func = func

            indent: str = ' ' * (len(call_stack) * 2)
            if func:
                fname: str = func.human_str if hasattr(func, 'human_str') else func.name
                func_prototype: str = func.prototype if hasattr(func, 'prototype') else ""
                formatted_lines.append(
                    f"{indent}-> 0x{addr:x} : {fname} {func_prototype} ({len(list(func.xrefs))} xrefs)")
            else:
                formatted_lines.append(f"{indent}-> 0x{addr:x} : Unknown function")

        last_addr = addr

    if repeat_count > 0:
        formatted_lines[-1] += f" (repeated {repeat_count + 1} times)"

    state_history += "\n".join(formatted_lines)

    if len(formatted_lines) > max_depth + 3:
        logger.debug("\n".join([state_history.split("\n")[0]] + formatted_lines[:max_depth]))
        logger.debug(f"...(truncated {len(formatted_lines) - (max_depth + 3)} lines)")
        logger.debug("\n".join(formatted_lines[-3:]))
    else:
        logger.debug(state_history)


def inspect_call(state: angr.SimState) -> None:
    """
    Inspect a function call in the given state.

    Args:
        state: The simulation state.
    """
    human_str: str = state.project.loader.describe_addr(state.addr)
    logger.debug(
        f'[{hex(state.addr)}] call {hex(state.addr)} ({human_str}) from {hex(state.history.addr)} ({state.project.loader.describe_addr(state.addr)})')
    if "extern-address" in human_str and not state.project.is_hooked(state.addr):
        logger.warning(f"Implement hook for {hex(state.addr)} ({human_str})")


def angr_enum_functions(proj: angr.Project) -> None:
    """
    Enumerate and log functions in the given project.

    Args:
        proj: The angr project.
    """
    for addr in proj.kb.functions:
        logger.debug(f'function: {hex(addr)}')
        logger.debug(f'function name: {proj.kb.functions[addr].name}')
        logger.debug(f'strings: {list(proj.kb.functions[addr].string_references())}')


def inspect_concretization(state: angr.SimState) -> None:
    """
    Inspect and log address concretization events.

    Args:
        state: The simulation state.
    """
    logger.debug("Address concretization event triggered")

    action: angr.state_plugins.inspect.SimAction = state.inspect.address_concretization_action
    logger.debug(f"SimAction: {action}")

    memory: angr.state_plugins.sim_memory.SimMemory = state.inspect.address_concretization_memory
    logger.debug(f"SimMemory: {memory}")

    expr: angr.sim_type.SimType = state.inspect.address_concretization_expr
    logger.debug(f"AST expression: {expr}")

    add_constraints: bool = state.inspect.address_concretization_add_constraints
    logger.debug(f"Add constraints: {add_constraints}")

    if state.inspect.address_concretization_result is not None:
        result: List[int] = state.inspect.address_concretization_result
        logger.debug(f"Resolved addresses: {result}")


def show_errors(state: angr.SimState) -> None:
    """
    Log error information for a given state.

    Args:
        state: The simulation state.
    """
    logger.debug(f'errored state: {state}')
    logger.debug(f'error message: {state.error}')

    tb: Any = state.traceback

    while tb.tb_next:
        logger.error(f'{tb.tb_frame}')
        tb = tb.tb_next

    logger.error(f'{tb.tb_frame}')


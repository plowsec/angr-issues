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


def get_reachable_info(cfg: angr.analyses.cfg.cfg_fast.CFGFast, entry_point: int) -> Tuple[
    Set[int], Dict[int, Set[angr.knowledge_plugins.cfg.cfg_node.CFGNode]]]:
    """
    Get reachable blocks and functions from the entry point in the CFG.

    Args:
        cfg: The control flow graph.
        entry_point: The entry point address.

    Returns:
        A tuple containing reachable blocks and reachable functions.
    """
    entry_node: angr.knowledge_plugins.cfg.cfg_node.CFGNode = cfg.get_any_node(entry_point)
    if not entry_node:
        raise ValueError(f"Entry point {hex(entry_point)} not found in CFG")

    reachable_nodes: Set[angr.knowledge_plugins.cfg.cfg_node.CFGNode] = nx.descendants(cfg.graph, entry_node)
    reachable_nodes.add(entry_node)

    reachable_blocks: Set[int] = set(node.addr for node in reachable_nodes if node.block)

    reachable_functions: Dict[int, Set[angr.knowledge_plugins.cfg.cfg_node.CFGNode]] = {}
    for node in reachable_nodes:
        if node.function_address not in reachable_functions:
            reachable_functions[node.function_address] = set()
        reachable_functions[node.function_address].add(node)

    return reachable_blocks, reachable_functions


def read_coverage_files(coverage_dir: str) -> Set[int]:
    """
    Read coverage files and return a set of covered block addresses.

    Args:
        coverage_dir: The directory containing coverage files.

    Returns:
        A set of covered block addresses.
    """
    covered_blocks: Set[int] = set()
    for filename in os.listdir(coverage_dir):
        if filename.startswith("00"):
            with open(os.path.join(coverage_dir, filename), 'r') as f:
                covered_blocks.update(int(line.strip(), 16) for line in f if line.strip())
    return covered_blocks


def compare_coverage(proj: angr.Project, reachable_blocks: Set[int],
                     reachable_functions: Dict[int, Set[angr.knowledge_plugins.cfg.cfg_node.CFGNode]],
                     covered_blocks: Set[int]) -> Tuple[float, Dict[str, Dict[str, Any]]]:
    """
    Compare coverage between reachable blocks and covered blocks.

    Args:
        proj: The angr project.
        reachable_blocks: Set of reachable block addresses.
        reachable_functions: Dictionary of reachable functions and their nodes.
        covered_blocks: Set of covered block addresses.

    Returns:
        A tuple containing overall coverage and function coverage information.
    """
    total_reachable: int = len(reachable_blocks)
    total_covered: int = len(covered_blocks.intersection(reachable_blocks))
    overall_coverage: float = total_covered / total_reachable if total_reachable > 0 else 0

    function_coverage: Dict[str, Dict[str, Any]] = {}
    for func_addr, nodes in reachable_functions.items():
        func: angr.knowledge_plugins.functions.function.Function = proj.kb.functions.get(func_addr)
        if func:
            func_blocks: Set[int] = set(node.addr for node in nodes if node.block)
            covered_func_blocks: Set[int] = func_blocks.intersection(covered_blocks)
            coverage: float = len(covered_func_blocks) / len(func_blocks) if func_blocks else 0
            function_coverage[func.name] = {
                'address': func_addr,
                'total_blocks': len(func_blocks),
                'covered_blocks': len(covered_func_blocks),
                'coverage': coverage
            }

    return overall_coverage, function_coverage


def analyze_coverage(proj: angr.Project, cfg: angr.analyses.cfg.cfg_fast.CFGFast, entry_point: int,
                     coverage_dir: str, coverage_file: str = 'reachable_blocks.txt') -> Tuple[float, Dict[str, Dict[str, Any]]]:
    """
    Analyze coverage for the given project and CFG.

    Args:
        proj: The angr project.
        cfg: angr control flow graph.
        entry_point: The entry point address.
        coverage_dir: The directory containing coverage files.
        coverage_file: The coverage file to write to

    Returns:
        A tuple containing overall coverage and function coverage information.
    """
    reachable_blocks, reachable_functions = get_reachable_info(cfg, entry_point)
    covered_blocks = read_coverage_files(coverage_dir)
    overall_coverage, function_coverage = compare_coverage(proj, reachable_blocks, reachable_functions, covered_blocks)

    logger.info(f"Total reachable blocks: {len(reachable_blocks)}")
    logger.info(f"Total covered blocks: {len(covered_blocks)}")
    logger.info(f"Overall coverage: {overall_coverage * 100:.2f}%")

    logger.info("\nFunction Coverage:")
    for func_name, data in function_coverage.items():
        logger.info(f"{func_name} (0x{data['address']:x}):")
        logger.info(f"  Total blocks: {data['total_blocks']}")
        logger.info(f"  Covered blocks: {data['covered_blocks']}")
        logger.info(f"  Coverage: {data['coverage'] * 100:.2f}%")


    with open(coverage_file, 'w') as f:
        f.write("\n".join([hex(block) for block in reachable_blocks]))

    return overall_coverage, function_coverage

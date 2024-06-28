import os
import uuid
import angr
import networkx as nx

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

    if not os.path.exists("cov"):
        os.makedirs("cov")

    for simstate in stashes["active"]:
        state_history = ""

        for addr in simstate.history.bbl_addrs.hardcopy:
            write_address = hex(addr)
            state_history += "{0}\n".format(write_address)

        ip = hex(simstate.solver.eval(simstate.ip))
        uid = str(uuid.uuid4())
        sid = str(i).zfill(5)
        filename = "cov/{0}_active_{1}_{2}".format(sid, ip, uid)

        with open(filename, "w") as f:
            f.write(state_history)
        i += 1


def debug_step_func(simgr):
    for state in simgr.stashes["active"]:
        logger.debug(f"Active state: {state}")
        pretty_print_callstack(state, 50)

    get_small_coverage(simgr)


def pretty_print_callstack(state, max_depth=10):
    state_history = "Call Stack:\n"
    kb_functions = shared.proj.kb.functions

    last_addr = None
    repeat_count = 0
    formatted_lines = []
    call_stack = []
    current_func = None

    for i, addr in enumerate(state.history.bbl_addrs.hardcopy):
        func = kb_functions.floor_func(addr)

        if addr == last_addr:
            repeat_count += 1
        else:
            if repeat_count > 0:
                formatted_lines[-1] += f" (repeated {repeat_count + 1} times)"
                repeat_count = 0

            # Adjust indentation based on function calls and returns
            if func != current_func:
                if func in call_stack:
                    # Function return
                    while call_stack and call_stack[-1] != func:
                        call_stack.pop()
                    if call_stack:
                        call_stack.pop()
                else:
                    # New function call
                    call_stack.append(func)
                current_func = func

            indent = ' ' * (len(call_stack) * 2)
            if func:
                fname = func.human_str if hasattr(func, 'human_str') else func.name
                func_prototype = func.prototype if hasattr(func, 'prototype') else ""
                formatted_lines.append(
                    f"{indent}-> 0x{addr:x} : {fname} {func_prototype} ({len(list(func.xrefs))} xrefs)")
            else:
                formatted_lines.append(f"{indent}-> 0x{addr:x} : Unknown function")

        last_addr = addr

    # Handle the case where the last address was repeating
    if repeat_count > 0:
        formatted_lines[-1] += f" (repeated {repeat_count + 1} times)"

    state_history += "\n".join(formatted_lines)

    # Print the formatted call stack
    if len(formatted_lines) > max_depth + 3:
        logger.debug("\n".join([state_history.split("\n")[0]] + formatted_lines[:max_depth]))
        logger.debug(f"...(truncated {len(formatted_lines) - (max_depth + 3)} lines)")
        logger.debug("\n".join(formatted_lines[-3:]))
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


def get_reachable_info(cfg, entry_point):
    # Get the node corresponding to the entry point
    entry_node = cfg.get_any_node(entry_point)
    if not entry_node:
        raise ValueError(f"Entry point {hex(entry_point)} not found in CFG")

    # Use networkx to get all reachable nodes from the entry point
    reachable_nodes = nx.descendants(cfg.graph, entry_node)
    reachable_nodes.add(entry_node)  # Include the entry node itself

    # Extract basic block addresses
    reachable_blocks = set(node.addr for node in reachable_nodes if node.block)

    # Get reachable functions and their nodes
    reachable_functions = {}
    for node in reachable_nodes:
        if node.function_address not in reachable_functions:
            reachable_functions[node.function_address] = set()
        reachable_functions[node.function_address].add(node)

    return reachable_blocks, reachable_functions


def read_coverage_files(coverage_dir):
    covered_blocks = set()
    for filename in os.listdir(coverage_dir):
        if filename.startswith("00"):  # Assuming all relevant files start with "00"
            with open(os.path.join(coverage_dir, filename), 'r') as f:
                covered_blocks.update(int(line.strip(), 16) for line in f if line.strip())
    return covered_blocks


def compare_coverage(proj, reachable_blocks, reachable_functions, covered_blocks):
    total_reachable = len(reachable_blocks)
    total_covered = len(covered_blocks.intersection(reachable_blocks))
    overall_coverage = total_covered / total_reachable if total_reachable > 0 else 0

    function_coverage = {}
    for func_addr, nodes in reachable_functions.items():
        func = proj.kb.functions.get(func_addr)
        if func:
            func_blocks = set(node.addr for node in nodes if node.block)
            covered_func_blocks = func_blocks.intersection(covered_blocks)
            coverage = len(covered_func_blocks) / len(func_blocks) if func_blocks else 0
            function_coverage[func.name] = {
                'address': func_addr,
                'total_blocks': len(func_blocks),
                'covered_blocks': len(covered_func_blocks),
                'coverage': coverage
            }

    return overall_coverage, function_coverage


def analyze_coverage(proj, cfg, entry_point, coverage_dir):
    reachable_blocks, reachable_functions = get_reachable_info(cfg, entry_point)
    covered_blocks = read_coverage_files(coverage_dir)
    overall_coverage, function_coverage = compare_coverage(proj, reachable_blocks, reachable_functions, covered_blocks)

    # Log results
    logger.info(f"Total reachable blocks: {len(reachable_blocks)}")
    logger.info(f"Total covered blocks: {len(covered_blocks)}")
    logger.info(f"Overall coverage: {overall_coverage * 100:.2f}%")

    logger.info("\nFunction Coverage:")
    for func_name, data in function_coverage.items():
        logger.info(f"{func_name} (0x{data['address']:x}):")
        logger.info(f"  Total blocks: {data['total_blocks']}")
        logger.info(f"  Covered blocks: {data['covered_blocks']}")
        logger.info(f"  Coverage: {data['coverage'] * 100:.2f}%")

    # Write reachable blocks to file
    with open('reachable_blocks.txt', 'w') as f:
        f.write("\n".join([hex(block) for block in reachable_blocks]))

    return overall_coverage, function_coverage

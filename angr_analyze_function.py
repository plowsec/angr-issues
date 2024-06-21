import functools
import pickle

import angr
import sys
import IPython
import logging
import uuid

import claripy
import pyvex

from exploration_techniques.CFGFollower import CFGFollower
from helpers.log import logger
from helpers import angr_introspection, state_plugin

import int_overflow
import shared
import hooks
import opcodes
import utils

import angr.calling_conventions
import angr.sim_type


logging.basicConfig(level=logging.DEBUG)
logging.getLogger("angr.exploration_techniques").setLevel(logging.DEBUG)


def inspect_new_constraint(state):
    logger.debug(f'new constraint {state.inspect.added_constraints}')


def set_hooks(proj):
    proj.hook_symbol('__stdio_common_vfprintf', hooks.stdio_common_vfprintf())
    proj.hook_symbol('__acrt_iob_func', hooks.acrt_iob_func())
    proj.hook_symbol('printf', angr.procedures.libc.printf.printf())
    proj.hook_symbol('sprintf', angr.procedures.libc.sprintf.sprintf())
    proj.hook_symbol('fprintf', angr.procedures.libc.fprintf.fprintf())


def check_for_vulns(*args, **kwargs):


    sm = args[0]

    for state in sm.active:
        if state.loop_data.current_loop is not None and len(state.loop_data.current_loop) > 0:
            logger.debug(f'loop: {state.loop_data.current_loop}')

    int_overflow.check_for_vulns(sm, shared.proj)
    """for state in sm.active:
        logger.debug(f'{state.addr} {state.regs.rip}')
        detect_overflow(state)
    """


def create_simgr(proj, addr_target):

    # Get control flow graph.
    #shared.cfg = angr_proj.analyses.CFGFast(normalize=True )
    shared.cfg = proj.analyses.CFGEmulated(fail_fast=True, normalize=True, keep_state=True)

    # Enumerate functions
    angr_introspection.angr_enum_functions(proj)
    shared.proj.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True, cfg=shared.cfg)


    # Set hooks
    set_hooks(proj)

    # Create a new state with the function arguments set up
    state = proj.factory.blank_state()

    # Manually create a symbolic buffer
    input_buf_len = state.solver.BVV(0x10, 64)  # Example length for InputBufLen
    input_buffer = state.solver.BVS('input_buffer', 0x10 * 8)  # Create a symbolic bitvector for the buffer

    # Allocate memory for the buffer and store the symbolic buffer in memory
    input_buffer_addr = state.solver.BVV(0x100000, 64)  # Example address to store the buffer
    state.memory.store(input_buffer_addr, input_buffer)

    shared.mycc = angr.calling_conventions.SimCCMicrosoftAMD64(shared.proj.arch)

    # init_analysis(angr_proj)

    state = proj.factory.call_state(
        addr_target,
        input_buffer_addr,
        input_buf_len,
        cc=shared.mycc,
        prototype="void call_me(char *InputBuffer, int64_t InputBufLen);"
    )

    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    """
    state.options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
    state.options.add(angr.options.LAZY_SOLVES)
    state.options.add(angr.options.SYMBOLIC_MEMORY_NO_SINGLEVALUE_OPTIMIZATIONS)
    state.options.add(angr.options.CONSTRAINT_TRACKING_IN_SOLVER)
    state.options.add(angr.options.TRACK_CONSTRAINTS)
    state.options.add(angr.options.TRACK_TMP_ACTIONS)
    state.options.add(angr.options.SYMBOLIC_TEMPS)

    """


    state.inspect.b('call', when=angr.BP_BEFORE, action=angr_introspection.inspect_call)
    #state.inspect.b('constraints', when=angr.BP_AFTER, action=inspect_new_constraint)
    #state.inspect.b('address_concretization', when=angr.BP_AFTER, action=inspect_concretization)
    #state.inspect.b('mem_write', when=angr.BP_BEFORE, action=check_oob_write)

    state.register_plugin("deep", state_plugin.SimStateDeepGlobals())

    shared.state = state
    shared.simgr = proj.factory.simgr(state)
    shared.phase = 2

    logger.debug(shared.simgr.active[0].regs.rip)
    return shared.simgr


def exploration_done():

    s = shared.simgr
    logger.debug(f'active: {len(s.active)}')
    logger.debug(f'found: {len(s.found)}')
    logger.debug(f'avoid: {len(s.avoid)}')

    if len(s.avoid) > 0:
        # pretty print the avoid states
        for state in s.avoid:
            logger.debug(f'avoid state: {state}')
            angr_introspection.pretty_print_callstack(state)

    logger.debug(f'deadended: {len(s.deadended)}')
    logger.debug(f'errored: {len(s.errored)}')

    if len(s.errored) > 0:
        for state in s.errored:
            angr_introspection.show_errors(state)

    logger.debug(f'unsat: {len(s.unsat)}')
    logger.debug(f'uncons: {len(s.unconstrained)}')

    logger.debug("Done")
    if len(s.found) > 0:

        found = s.one_found
        logger.debug("Found state")
        logger.debug(f'found: {found}')
    else:
        logger.debug("No found state")


def check_find_addresses(find_addresses):

    for f in find_addresses:
        nodes = shared.cfg.model.get_all_nodes(f)
        if len(nodes) == 0:
            logger.critical(f"Node not found for address {hex(f)}. Specify the start of a basic block.")
            func = shared.proj.kb.functions.floor_func(f)

            if func is None:
                logger.critical(f"This address is not even within a function.")
                return False

            # enumerate all basic blocks and check if the address is within the range of any block
            for block in func.blocks:
                if block.addr <= f < block.addr + block.size:
                    logger.debug(f"Try this one? {block}. Your address is in it.")
                    break

            return False

    return True


def analyze(angr_proj):

    addr_target = 0x0000000140001000
    create_simgr(angr_proj, addr_target)

    # shared.simgr.use_technique(angr.exploration_techniques.LocalLoopSeer(bound=shared.args.bound))
    # shared.simgr.use_technique(angr.exploration_techniques.LengthLimiter(shared.args.length))
    # shared.simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=shared.cfg, bound=50))

    # analyze_stack_vars()

    # 00000001400010D0 loop overflow
    # 0x000000014000109D simple overflow
    find_addresses = [0x1400014E5]

    check_find_addresses(find_addresses)

    #shared.simgr.use_technique(CFGFollower(cfg=shared.cfg, find=find_addresses))

    shared.simgr.explore(
        find=find_addresses,
        # avoid=[0x00000001400010E0],
        # step_func=check_for_vulns,
        cfg=shared.cfg
    )

    #shared.simgr.run()

    exploration_done()


def main():
    shared.driver_path = sys.argv[1]

    try:
        shared.proj = angr.Project(shared.driver_path, auto_load_libs=False)
        logger.debug(f'analyze driver {shared.driver_path}')
    except:
        logger.error(f'cannot analyze {shared.driver_path}')
        sys.exit(-1)
    analyze(shared.proj)


if __name__ == "__main__":
    main()
